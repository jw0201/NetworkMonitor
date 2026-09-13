//
//  ByteReaderTests.swift
//
//  ByteReader is the only thing standing between a hostile packet and a root
//  process, so the interesting cases here are all the ones where a malicious
//  length field tries to walk the cursor out of bounds.
//

import NMCore
import NMTestKit

@inline(never)
private func withBytes(_ bytes: [UInt8], _ body: (inout ByteReader) throws -> Void) rethrows {
    try bytes.withUnsafeBytes { buf in
        guard var r = ByteReader(buf) else {
            // Only possible for an empty buffer with a nil base address.
            var empty = ByteReader(UnsafeRawPointer(bitPattern: 0x1000)!, count: 0)
            return try body(&empty)
        }
        return try body(&r)
    }
}

func runByteReaderTests() {
    NMTest.suite("ByteReader / basic reads") {

        NMTest.test("big-endian reads advance correctly") {
            try withBytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]) { r in
                NMTest.equal(try r.u8(), 0x01)
                NMTest.equal(try r.u16be(), 0x0203)
                NMTest.equal(try r.u24be(), 0x040506)
                NMTest.equal(r.remaining, 2)
            }
        }

        NMTest.test("endianness is explicit and the two orders disagree") {
            try withBytes([0xAA, 0xBB, 0xCC, 0xDD]) { r in
                var copy = r
                NMTest.equal(try r.u32be(), 0xAABBCCDD)
                NMTest.equal(try copy.u32le(), 0xDDCCBBAA)
            }
        }

        NMTest.test("unaligned loads read the right bytes") {
            // Packet data is never aligned. A plain load(as:) would misread here.
            try withBytes([0x00, 0x11, 0x22, 0x33, 0x44]) { r in
                try r.skip(1)
                NMTest.equal(try r.u32be(), 0x11223344)
            }
        }
    }

    NMTest.suite("ByteReader / bounds enforcement") {

        NMTest.test("reading past the end throws instead of returning garbage") {
            try withBytes([0x01, 0x02]) { r in
                NMTest.throwsError({ _ = try r.u32be() }, validate: { err in
                    guard case ParseError.truncated(let needed, let available) = err else { return false }
                    return needed == 4 && available == 2
                })
                NMTest.equal(r.offset, 0, "a failed read must not move the cursor")
            }
        }

        NMTest.test("an empty reader rejects everything") {
            try withBytes([]) { r in
                NMTest.throwsError({ _ = try r.u8() })
                NMTest.expect(r.isAtEnd)
                NMTest.equal(r.remaining, 0)
            }
        }

        // The reason need() is written as `limit - offset >= n` and not
        // `offset + n <= limit`: the latter overflows for a wire-supplied n and
        // the overflowed comparison PASSES, producing an out-of-bounds read.
        NMTest.test("an enormous length cannot overflow the bounds check") {
            try withBytes([0x01, 0x02, 0x03, 0x04]) { r in
                NMTest.throwsError({ try r.skip(Int.max) })
                NMTest.throwsError({ _ = try r.bytes(Int.max) })
                NMTest.throwsError({ _ = try r.sub(Int.max) })
                NMTest.equal(r.offset, 0)
            }
        }

        NMTest.test("negative lengths are rejected as malformed") {
            try withBytes([0x01, 0x02, 0x03, 0x04]) { r in
                NMTest.throwsError({ try r.skip(-1) }, validate: { err in
                    if case ParseError.malformed = err { return true }
                    return false
                })
                NMTest.throwsError({ _ = try r.bytes(-8) })
            }
        }
    }

    NMTest.suite("ByteReader / sub-readers") {

        NMTest.test("a sub-reader cannot escape its length-delimited field") {
            try withBytes([0x02, 0xAA, 0xBB, 0xCC, 0xDD]) { r in
                let n = Int(try r.u8())
                var field = try r.sub(n)
                NMTest.equal(field.count, 2)
                NMTest.equal(try field.u8(), 0xAA)
                NMTest.equal(try field.u8(), 0xBB)
                // 0xCC exists in the parent buffer but is outside this field.
                NMTest.throwsError({ _ = try field.u8() })
                NMTest.equal(try r.u8(), 0xCC, "parent advanced past the field exactly")
            }
        }

        NMTest.test("absolute sub-readers are bounds checked") {
            try withBytes([0x01, 0x02, 0x03, 0x04]) { r in
                NMTest.noThrow { _ = try r.reader(at: 2, count: 2) }
                NMTest.throwsError({ _ = try r.reader(at: 2, count: 3) })
                NMTest.throwsError({ _ = try r.reader(at: -1, count: 1) })
                NMTest.throwsError({ _ = try r.reader(at: 0, count: Int.max) })
                NMTest.throwsError({ _ = try r.reader(at: Int.max, count: 1) })
            }
        }

        NMTest.test("seek is clamped to the window") {
            try withBytes([0x01, 0x02, 0x03, 0x04]) { r in
                NMTest.noThrow { try r.seek(to: 4) }   // one-past-last is a valid cursor
                NMTest.expect(r.isAtEnd)
                NMTest.throwsError({ try r.seek(to: 5) })
                NMTest.throwsError({ try r.seek(to: -1) })
            }
        }
    }

    NMTest.suite("ByteReader / copies and strings") {

        NMTest.test("copyOut clamps to what is available and reports the real count") {
            var dest = [UInt8](repeating: 0, count: 8)
            try withBytes([0xDE, 0xAD, 0xBE, 0xEF]) { r in
                let n = dest.withUnsafeMutableBytes { r.copyOut(into: $0, max: 100) }
                NMTest.equal(n, 4, "must clamp to available, not to the requested amount")
                NMTest.expect(r.isAtEnd)
            }
            NMTest.equal(Array(dest.prefix(4)), [0xDE, 0xAD, 0xBE, 0xEF])
        }

        NMTest.test("cString stops at NUL and ignores trailing junk") {
            // pth_comm is a fixed 17-byte field: short name, NUL, then padding.
            var field = [UInt8]("Safari".utf8)
            field.append(0)
            field.append(contentsOf: [0xFF, 0xFE])
            field.append(contentsOf: [UInt8](repeating: 0, count: 8))
            try withBytes(field) { r in
                NMTest.equal(try r.cString(17), "Safari")
            }
        }

        NMTest.test("cString sanitizes non-printable bytes rather than failing") {
            try withBytes([0x41, 0x07, 0x42, 0x00]) { r in
                NMTest.equal(try r.cString(4), "A?B")
            }
        }

        NMTest.test("an unterminated cString consumes exactly the field width") {
            try withBytes([0x41, 0x42, 0x43, 0x44]) { r in
                NMTest.equal(try r.cString(4), "ABCD")
                NMTest.expect(r.isAtEnd)
            }
        }
    }

    NMTest.suite("ByteReader / randomized sweep") {

        // Drives random operation sequences against random buffers. The claim
        // under test is not that values are right -- it is that nothing traps
        // and the cursor invariant holds no matter what a caller asks for.
        NMTest.test("random operation sequences never violate the cursor invariant") {
            var rng = SystemRandomNumberGenerator()
            var violations = 0
            for _ in 0..<5000 {
                let len = Int.random(in: 0...64, using: &rng)
                let bytes = (0..<len).map { _ in UInt8.random(in: 0...255, using: &rng) }
                bytes.withUnsafeBytes { buf in
                    guard var r = ByteReader(buf) else { return }
                    for _ in 0..<20 {
                        if r.offset < 0 || r.offset > r.count { violations += 1 }
                        switch Int.random(in: 0...7, using: &rng) {
                        case 0: _ = try? r.u8()
                        case 1: _ = try? r.u16be()
                        case 2: _ = try? r.u32be()
                        case 3: _ = try? r.u64be()
                        case 4: try? r.skip(Int.random(in: -4...80, using: &rng))
                        case 5: _ = try? r.sub(Int.random(in: -4...80, using: &rng))
                        case 6: try? r.seek(to: Int.random(in: -4...80, using: &rng))
                        default: _ = try? r.cString(Int.random(in: 0...40, using: &rng))
                        }
                    }
                }
            }
            NMTest.equal(violations, 0, "cursor escaped 0...count")
        }
    }
}
