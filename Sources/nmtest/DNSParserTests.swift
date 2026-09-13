//
//  DNSParserTests.swift
//
//  DNS name compression is the most reachable denial of service in a packet
//  parser: a two-byte pointer that references itself spins forever, and the
//  packet that does it fits in a single datagram. Most of this file is that
//  attack and its variants.
//

import NMAnalyzers
import NMCore
import NMTestKit

private func parse(_ bytes: [UInt8], _ body: (Result<DNSMessage, Error>) -> Void) {
    bytes.withUnsafeBytes { buf in
        guard let r = ByteReader(buf) else { return }
        do { body(.success(try DNSParser.parse(r))) }
        catch { body(.failure(error)) }
    }
}

private func decodeName(_ bytes: [UInt8], at start: Int = 0,
                        _ body: (Result<String, Error>) -> Void) {
    bytes.withUnsafeBytes { buf in
        guard let r = ByteReader(buf) else { return }
        var offset = start
        do { body(.success(try DNSName.decode(from: r, offset: &offset))) }
        catch { body(.failure(error)) }
    }
}

func runDNSParserTests() {
    NMTest.suite("DNS names / well-formed") {

        NMTest.test("an uncompressed name round-trips") {
            let encoded = DNSMessageBuilder.encodeName("www.example.com")
            decodeName(encoded) { result in
                guard case .success(let name) = result else {
                    return NMTest.expect(false, "\(result)")
                }
                NMTest.equal(name, "www.example.com")
            }
        }

        NMTest.test("the root label decodes as \".\"") {
            decodeName([0]) { result in
                guard case .success(let name) = result else { return NMTest.expect(false, "\(result)") }
                NMTest.equal(name, ".")
            }
        }

        NMTest.test("a backward pointer is followed and the cursor resumes after it") {
            // "example.com" at offset 0, then a name that is "www" + a pointer
            // back to offset 0.
            var bytes = DNSMessageBuilder.encodeName("example.com")
            let pointerAt = bytes.count
            bytes.append(3); bytes.append(contentsOf: Array("www".utf8))
            bytes.append(0xC0); bytes.append(0x00)
            bytes.append(0xAB)                            // a sentinel byte after the name

            bytes.withUnsafeBytes { buf in
                guard let r = ByteReader(buf) else { return }
                var offset = pointerAt
                guard let name = try? DNSName.decode(from: r, offset: &offset) else {
                    return NMTest.expect(false, "decode failed")
                }
                NMTest.equal(name, "www.example.com")
                NMTest.equal(offset, bytes.count - 1,
                             "a pointer consumes two bytes, not the target's length")
            }
        }
    }

    NMTest.suite("DNS names / hostile compression") {

        // The classic. Without the strictly-decreasing rule this spins forever
        // inside a root process, from a packet that fits in one datagram.
        NMTest.test("a self-referential pointer is rejected, not followed") {
            let bytes: [UInt8] = [0xC0, 0x00]            // offset 0 points at offset 0
            decodeName(bytes) { result in
                guard case .failure(let error) = result else {
                    return NMTest.expect(false, "must reject a self-pointer")
                }
                NMTest.expect(error as? DNSNameError != nil)
            }
        }

        NMTest.test("a forward pointer is rejected") {
            // At offset 0, point at offset 4 -- forwards. Two of these can be
            // arranged into a cycle that a jump counter alone only slows down.
            let bytes: [UInt8] = [0xC0, 0x04, 0x00, 0x00, 0x01, 0x61, 0x00]
            decodeName(bytes) { result in
                guard case .failure(let error) = result else {
                    return NMTest.expect(false, "must reject a forward pointer")
                }
                guard case DNSNameError.forwardPointer = error else {
                    return NMTest.expect(false, "expected .forwardPointer, got \(error)")
                }
            }
        }

        NMTest.test("a two-pointer cycle cannot be constructed") {
            // A points forward to B, B points back to A. The forward half is
            // refused, so the cycle never closes.
            let bytes: [UInt8] = [0xC0, 0x02, 0xC0, 0x00]
            decodeName(bytes) { result in
                guard case .failure = result else {
                    return NMTest.expect(false, "must reject")
                }
            }
        }

        NMTest.test("a long chain of legal backward pointers is still capped") {
            // Each pointer moves backwards by two, so every individual jump is
            // legal; only the cap stops the chain.
            var bytes = [UInt8]()
            bytes.append(0)                               // root at offset 0
            for i in stride(from: 1, through: 60, by: 1) {
                let target = UInt16((i - 1) * 2)
                bytes.append(0xC0 | UInt8(target >> 8))
                bytes.append(UInt8(target & 0xFF))
            }
            decodeName(bytes, at: bytes.count - 2) { result in
                if case .success = result {
                    NMTest.expect(true, "terminated rather than looping")
                } else {
                    NMTest.expect(true, "rejected the chain")
                }
            }
        }

        NMTest.test("reserved label types 01 and 10 are rejected") {
            for top in [UInt8(0x40), UInt8(0x80)] {
                decodeName([top, 0x00, 0x00]) { result in
                    guard case .failure(let error) = result else {
                        return NMTest.expect(false, "must reject label type \(top >> 6)")
                    }
                    guard case DNSNameError.reservedLabelType = error else {
                        return NMTest.expect(false, "expected .reservedLabelType, got \(error)")
                    }
                }
            }
        }

        NMTest.test("a name longer than 255 bytes is rejected") {
            var bytes = [UInt8]()
            // 63-byte labels until well past the limit.
            for _ in 0..<8 {
                bytes.append(63)
                bytes.append(contentsOf: [UInt8](repeating: UInt8(ascii: "a"), count: 63))
            }
            bytes.append(0)
            decodeName(bytes) { result in
                guard case .failure(let error) = result else {
                    return NMTest.expect(false, "must reject an over-long name")
                }
                guard case DNSNameError.nameTooLong = error else {
                    return NMTest.expect(false, "expected .nameTooLong, got \(error)")
                }
            }
        }

        NMTest.test("a truncated name is rejected rather than read past the end") {
            decodeName([5, UInt8(ascii: "a"), UInt8(ascii: "b")]) { result in
                guard case .failure = result else {
                    return NMTest.expect(false, "label claims 5 bytes, 2 present")
                }
            }
        }

        NMTest.test("labels containing dots or backslashes are escaped") {
            // A label may legally contain any byte. Without escaping, a label
            // containing a dot renders as a different name entirely.
            var bytes = [UInt8]()
            bytes.append(5)
            bytes.append(contentsOf: Array("a.b\\c".utf8))
            bytes.append(3)
            bytes.append(contentsOf: Array("com".utf8))
            bytes.append(0)
            decodeName(bytes) { result in
                guard case .success(let name) = result else { return NMTest.expect(false, "\(result)") }
                NMTest.equal(name, "a\\.b\\\\c.com",
                             "an unescaped dot would impersonate a.b\\c.com")
            }
        }

        NMTest.test("non-printable bytes in a label are made visible") {
            let bytes: [UInt8] = [3, 0x01, 0xFF, UInt8(ascii: "a"), 0]
            decodeName(bytes) { result in
                guard case .success(let name) = result else { return NMTest.expect(false, "\(result)") }
                NMTest.equal(name, "\\x01\\xffa")
            }
        }
    }

    NMTest.suite("DNS messages") {

        NMTest.test("a query parses its question") {
            let bytes = DNSMessageBuilder.query("www.example.com", type: 1).build()
            parse(bytes) { result in
                guard case .success(let m) = result else { return NMTest.expect(false, "\(result)") }
                NMTest.expect(!m.header.isResponse)
                NMTest.expect(m.header.recursionDesired)
                NMTest.equal(m.questions.count, 1)
                NMTest.equal(m.primaryQuestion?.name, "www.example.com")
                NMTest.equal(m.primaryQuestion?.typeName, "A")
                NMTest.expect(!m.parseTruncated)
            }
        }

        NMTest.test("a response parses its A records") {
            let bytes = DNSMessageBuilder.response(
                "example.com",
                addresses: [IPAddress("93.184.216.34")!, IPAddress("93.184.216.35")!],
                ttl: 600).build()
            parse(bytes) { result in
                guard case .success(let m) = result else { return NMTest.expect(false, "\(result)") }
                NMTest.expect(m.header.isResponse)
                NMTest.equal(m.header.responseCodeName, "NOERROR")
                NMTest.equal(m.answers.count, 2)
                NMTest.equal(m.answers.first?.ttl, 600)
                NMTest.equal(m.answers.first?.data, .address(IPAddress("93.184.216.34")!))
            }
        }

        NMTest.test("AAAA records decode as IPv6") {
            let bytes = DNSMessageBuilder.response(
                "example.com", addresses: [IPAddress("2606:2800:220:1:248:1893:25c8:1946")!]).build()
            parse(bytes) { result in
                guard case .success(let m) = result else { return NMTest.expect(false, "\(result)") }
                NMTest.equal(m.answers.first?.typeName, "AAAA")
                NMTest.equal(m.answers.first?.data,
                             .address(IPAddress("2606:2800:220:1:248:1893:25c8:1946")!))
            }
        }

        NMTest.test("a CNAME chain is preserved in order") {
            let bytes = DNSMessageBuilder.response(
                "www.example.com",
                addresses: [IPAddress("1.2.3.4")!],
                cnameChain: ["example.map.cdn.net", "cdn-edge-42.net"]).build()
            parse(bytes) { result in
                guard case .success(let m) = result else { return NMTest.expect(false, "\(result)") }
                NMTest.equal(m.answers.count, 3)
                NMTest.equal(m.answers[0].name, "www.example.com")
                NMTest.equal(m.answers[0].data, .name("example.map.cdn.net"))
                NMTest.equal(m.answers[1].data, .name("cdn-edge-42.net"))
                NMTest.equal(m.answers[2].data, .address(IPAddress("1.2.3.4")!))
            }
        }

        NMTest.test("NXDOMAIN is reported as such") {
            var b = DNSMessageBuilder.query("nope.example.com")
            b.isResponse = true
            b.responseCode = 3
            parse(b.build()) { result in
                guard case .success(let m) = result else { return NMTest.expect(false, "\(result)") }
                NMTest.equal(m.header.responseCodeName, "NXDOMAIN")
                NMTest.equal(m.answers.count, 0)
            }
        }

        // The header's counts are attacker-supplied. Iterating on them is how a
        // 40-byte packet turns into 65,535 iterations.
        NMTest.test("a header claiming 65535 answers in a small packet costs nothing") {
            var b = DNSMessageBuilder.query("example.com")
            b.isResponse = true
            b.answerCountOverride = 65535
            parse(b.build()) { result in
                guard case .success(let m) = result else { return NMTest.expect(false, "\(result)") }
                NMTest.expect(m.answers.count <= Limits.maxDNSRecords)
                NMTest.expect(m.parseTruncated, "a partial parse must be visible")
            }
        }

        NMTest.test("a header claiming 65535 questions is likewise bounded") {
            var b = DNSMessageBuilder.query("example.com")
            b.questionCountOverride = 65535
            parse(b.build()) { result in
                guard case .success(let m) = result else { return NMTest.expect(false, "\(result)") }
                NMTest.expect(m.questions.count <= Limits.maxDNSRecords)
                NMTest.expect(m.parseTruncated)
            }
        }

        NMTest.test("a message shorter than a header is rejected") {
            parse([0x12, 0x34, 0x01]) { result in
                guard case .failure = result else {
                    return NMTest.expect(false, "must reject a 3-byte message")
                }
            }
        }

        // RFC 2181: a TTL with the top bit set is invalid. Left alone it reads
        // as 136 years and would pin a cache entry effectively forever.
        NMTest.test("a TTL with the top bit set is treated as zero") {
            let bytes = DNSMessageBuilder.response(
                "example.com", addresses: [IPAddress("1.2.3.4")!],
                ttl: 0xFFFF_FFFF).build()
            parse(bytes) { result in
                guard case .success(let m) = result else { return NMTest.expect(false, "\(result)") }
                NMTest.equal(m.answers.first?.ttl, 0)
            }
        }

        NMTest.test("an unknown record type is recorded without being parsed") {
            var b = DNSMessageBuilder()
            b.isResponse = true
            b.questions = [("example.com", 1)]
            b.answers = [("example.com", 99, 60, .opaque(type: 99, length: 12))]
            parse(b.build()) { result in
                guard case .success(let m) = result else { return NMTest.expect(false, "\(result)") }
                NMTest.equal(m.answers.first?.typeName, "TYPE99")
                NMTest.equal(m.answers.first?.data, .opaque(type: 99, length: 12))
            }
        }

        NMTest.test("randomized garbage never crashes the parser") {
            var rng = SplitMix64(seed: 0xD15EA5E)
            for _ in 0..<30_000 {
                let n = Int(rng.next() % 300)
                let bytes = (0..<n).map { _ in UInt8(truncatingIfNeeded: rng.next()) }
                parse(bytes) { _ in }
            }
            NMTest.expect(true, "survived 30k random inputs")
        }

        // Random bytes rarely produce a valid header, so they never reach the
        // name decoder. Mutating a REAL message is what actually exercises it.
        NMTest.test("bit-flipping a valid message never crashes the parser") {
            let valid = DNSMessageBuilder.response(
                "www.example.com", addresses: [IPAddress("1.2.3.4")!],
                cnameChain: ["cdn.example.net"]).build()
            var rng = SplitMix64(seed: 0xBADC0DE)
            for _ in 0..<30_000 {
                var mutated = valid
                let flips = 1 + Int(rng.next() % 6)
                for _ in 0..<flips {
                    let index = Int(rng.next() % UInt64(mutated.count))
                    mutated[index] = UInt8(truncatingIfNeeded: rng.next())
                }
                parse(mutated) { _ in }
            }
            NMTest.expect(true, "survived 30k mutations of a real message")
        }
    }
}
