//
//  PktapDecoderTests.swift
//
//  Synthetic PKTAP headers, including deliberately hostile ones. This exercises
//  the rule that matters most in the decoder: field presence is decided by the
//  wire's pth_length, never by sizeof().
//

import CPktap
import NMCapture
import NMCore
import NMTestKit

private func decode(_ bytes: [UInt8], _ body: (Result<PktapMetadata, Error>) -> Void) {
    bytes.withUnsafeBytes { buf in
        guard var r = ByteReader(buf) else { return body(.failure(ParseError.malformed("nil buffer"))) }
        do { body(.success(try PktapDecoder.decode(&r))) }
        catch { body(.failure(error)) }
    }
}

func runPktapDecoderTests() {
    NMTest.suite("PktapDecoder / well-formed headers") {

        NMTest.test("a full 156-byte header decodes every field") {
            var b = PktapHeaderBuilder()
            b.pid = 4242
            b.comm = "Safari"
            b.epid = 4242
            b.ecomm = "Safari"
            b.ifname = "en0"
            decode(b.build(payload: [UInt8](repeating: 0x41, count: 64))) { result in
                guard case .success(let m) = result else {
                    return NMTest.expect(false, "decode failed: \(result)")
                }
                NMTest.equal(m.headerLength, 156)
                NMTest.equal(m.pid, 4242)
                NMTest.equal(m.comm, "Safari")
                NMTest.equal(m.epid, 4242)
                NMTest.equal(m.ecomm, "Safari")
                NMTest.equal(m.ifname, "en0")
                NMTest.equal(m.dlt, 1)
                NMTest.equal(m.protocolFamily, 2)
                NMTest.equal(m.framePreLength, 14)
                NMTest.equal(m.flowID, 0xDEADBEEF)
                NMTest.equal(m.ipProto, 6)
                NMTest.expect(m.uuid != nil && !(m.uuid!.isZero))
                NMTest.equal(m.l3Offset, 170, "156 header + 14 Ethernet")
            }
        }

        NMTest.test("pid is read host-order; big-endian would give a nonsense value") {
            var b = PktapHeaderBuilder()
            b.pid = 501
            decode(b.build()) { result in
                guard case .success(let m) = result else { return NMTest.expect(false, "\(result)") }
                NMTest.equal(m.pid, 501, "reading this field big-endian yields 0xF5010000")
            }
        }

        NMTest.test("process delegation is surfaced, not flattened away") {
            var b = PktapHeaderBuilder()
            b.pid = 130; b.comm = "nsurlsessiond"
            b.epid = 900; b.ecomm = "Mail"
            b.flags = 0x0002 | UInt32(NM_PTH_FLAG_PROC_DELEGATED)
            decode(b.build()) { result in
                guard case .success(let m) = result else { return NMTest.expect(false, "\(result)") }
                NMTest.expect(m.isProcessDelegated, "delegation flag must be visible")
                NMTest.equal(m.comm, "nsurlsessiond", "the proxy is preserved")
                NMTest.equal(m.ecomm, "Mail", "the real owner is preserved")
            }
        }

        NMTest.test("loopback is identified so byte accounting can de-duplicate") {
            var b = PktapHeaderBuilder()
            b.ifname = "lo0"
            b.ifType = 0x18                     // IFT_LOOP
            b.dlt = 0                           // DLT_NULL
            b.framePreLength = 4
            decode(b.build(payload: [UInt8](repeating: 0x45, count: 64))) { result in
                guard case .success(let m) = result else { return NMTest.expect(false, "\(result)") }
                NMTest.expect(m.isLoopback)
                NMTest.equal(m.l3Offset, 160, "156 header + 4 AF word")
            }

        }

        NMTest.test("a frame offset past the captured bytes is clamped, not trusted") {
            // Same header, but nothing was captured beyond it. 156 + 4 would
            // point past the record, so the pre-length must be discarded.
            var b = PktapHeaderBuilder()
            b.ifname = "lo0"; b.ifType = 0x18; b.dlt = 0; b.framePreLength = 4
            decode(b.build()) { result in
                guard case .success(let m) = result else { return NMTest.expect(false, "\(result)") }
                NMTest.equal(m.framePreLength, 0)
                NMTest.equal(m.l3Offset, 156)
            }
        }

        NMTest.test("a kernel drop record is reported as such, not parsed as a frame") {
            var b = PktapHeaderBuilder()
            b.typeNext = UInt32(NM_PTH_TYPE_DROP)
            decode(b.build()) { result in
                guard case .success(let m) = result else { return NMTest.expect(false, "\(result)") }
                if case .drop = m.kind {} else { NMTest.expect(false, "expected .drop, got \(m.kind)") }
            }
        }
    }

    NMTest.suite("PktapDecoder / forward and backward compatibility") {

        // The rule: read a field only when the WIRE's pth_length covers it.
        // Older macOS shipped shorter headers; using sizeof() would read
        // adjacent packet bytes as flowid/uuid and produce confident garbage.
        NMTest.test("a short 108-byte header decodes without inventing absent fields") {
            var b = PktapHeaderBuilder()
            b.headerLength = 108
            decode(b.build(payload: [UInt8](repeating: 0xFF, count: 40))) { result in
                guard case .success(let m) = result else { return NMTest.expect(false, "\(result)") }
                NMTest.equal(m.headerLength, 108)
                NMTest.equal(m.comm, "curl", "fields inside the short header still decode")
                NMTest.expect(m.flowID == nil, "flowid is beyond 108 bytes and must be nil")
                NMTest.expect(m.ipProto == nil)
                NMTest.expect(m.uuid == nil, "uuid must not be read from payload bytes")
            }
        }

        NMTest.test("a longer-than-known header is accepted and its extra bytes ignored") {
            var b = PktapHeaderBuilder()
            b.headerLength = 200            // a hypothetical future macOS
            decode(b.build(payload: [UInt8](repeating: 0, count: 64))) { result in
                guard case .success(let m) = result else { return NMTest.expect(false, "\(result)") }
                NMTest.equal(m.headerLength, 200)
                NMTest.equal(m.comm, "curl")
            }
        }
    }

    NMTest.suite("PktapDecoder / hostile and malformed input") {

        NMTest.test("a truncated record is rejected") {
            decode([0x01, 0x02, 0x03]) { result in
                if case .success = result { NMTest.expect(false, "must reject a 3-byte record") }
            }
        }

        NMTest.test("a header length below the historical minimum is rejected") {
            var b = PktapHeaderBuilder()
            b.headerLength = 40
            decode(b.build()) { result in
                if case .success = result { NMTest.expect(false, "must reject hdrLen 40") }
            }
        }

        NMTest.test("a header claiming to be longer than the capture is rejected") {
            let b = PktapHeaderBuilder()
            var bytes = b.build()
            // Claim 4 GB of header in a 156-byte record.
            bytes[0] = 0xFF; bytes[1] = 0xFF; bytes[2] = 0xFF; bytes[3] = 0xFF
            decode(bytes) { result in
                if case .success = result { NMTest.expect(false, "must reject an oversized hdrLen") }
            }
        }

        NMTest.test("an absurd frame_pre_length cannot push the L3 offset out of bounds") {
            var b = PktapHeaderBuilder()
            b.framePreLength = 0xFFFF_FFF0
            decode(b.build(payload: [UInt8](repeating: 0, count: 64))) { result in
                guard case .success(let m) = result else { return NMTest.expect(false, "\(result)") }
                NMTest.equal(m.framePreLength, 0, "an implausible pre-length is clamped to 0")
                NMTest.expect(m.l3Offset <= 156 + 64, "L3 offset must stay inside the record")
            }
        }

        NMTest.test("an unterminated comm field cannot run past its 17 bytes") {
            let b = PktapHeaderBuilder()
            var bytes = b.build()
            for i in 56..<(56 + 17) { bytes[i] = 0x41 }   // all 'A', no NUL
            decode(bytes) { result in
                guard case .success(let m) = result else { return NMTest.expect(false, "\(result)") }
                NMTest.equal(m.comm.count, 17, "stops at the field width")
                NMTest.expect(m.comm.count <= 17, "must never read past pth_comm[17]")
                NMTest.equal(m.ecomm, "curl", "the next field is still intact")
            }
        }

        NMTest.test("flag bits that claim both directions resolve to unknown, not a guess") {
            var b = PktapHeaderBuilder()
            b.flags = UInt32(NM_PTH_FLAG_DIR_IN) | UInt32(NM_PTH_FLAG_DIR_OUT)
            decode(b.build()) { result in
                guard case .success(let m) = result else { return NMTest.expect(false, "\(result)") }
                if case .unknown = m.flaggedDirection {} else {
                    NMTest.expect(false, "both bits set must yield .unknown, got \(m.flaggedDirection)")
                }
            }
        }

        NMTest.test("randomized garbage never crashes the decoder") {
            var rng = SystemRandomNumberGenerator()
            for _ in 0..<20000 {
                let n = Int.random(in: 0...200, using: &rng)
                let bytes = (0..<n).map { _ in UInt8.random(in: 0...255, using: &rng) }
                decode(bytes) { _ in }        // success or failure both fine; a trap is not
            }
            NMTest.expect(true, "survived 20k random inputs")
        }
    }
}
