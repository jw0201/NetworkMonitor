//
//  TLSTests.swift
//

import NMAnalyzers
import NMCore
import NMFlow
import NMTestKit

private let client = IPAddress("192.168.0.31")!
private let server = IPAddress("93.184.216.34")!
private let base: Timestamp = 1_757_000_000_000_000

private func parseClientHello(_ bytes: [UInt8]) -> TLSClientHello? {
    var result: TLSClientHello?
    bytes.withUnsafeBytes { buf in
        guard let reader = ByteReader(buf) else { return }
        TLSRecordLayer.handshakeMessages(in: reader) { type, _, body in
            if type == .clientHello {
                result = try? TLSHandshakeParser.parseClientHello(body)
            }
            return true
        }
    }
    return result
}

private func parseServerHello(_ bytes: [UInt8]) -> TLSServerHello? {
    var result: TLSServerHello?
    bytes.withUnsafeBytes { buf in
        guard let reader = ByteReader(buf) else { return }
        TLSRecordLayer.handshakeMessages(in: reader) { type, _, body in
            if type == .serverHello {
                result = try? TLSHandshakeParser.parseServerHello(body)
            }
            return true
        }
    }
    return result
}

func runTLSTests() {
    NMTest.suite("TLS / ClientHello") {

        NMTest.test("SNI, ALPN and the negotiated version are extracted") {
            var b = TLSClientHelloBuilder()
            b.serverName = "www.example.com"
            guard let hello = parseClientHello(b.build()) else {
                return NMTest.expect(false, "parse failed")
            }
            NMTest.equal(hello.serverName, "www.example.com")
            NMTest.equal(hello.alpnProtocols, ["h2", "http/1.1"])
            NMTest.equal(hello.legacyVersion, 0x0303)
            NMTest.equal(hello.effectiveVersion, 0x0304,
                         "the legacy field says 1.2 even for a 1.3 client")
        }

        NMTest.test("a message split across TLS records still parses") {
            // A real ClientHello routinely arrives as several records, and a
            // post-quantum one always does.
            var b = TLSClientHelloBuilder()
            b.serverName = "split.example.com"
            b.recordSplits = 5
            guard let hello = parseClientHello(b.build()) else {
                return NMTest.expect(false, "parse failed across 5 records")
            }
            NMTest.equal(hello.serverName, "split.example.com")
        }

        NMTest.test("GREASE values are stripped from the real lists") {
            var b = TLSClientHelloBuilder()
            b.serverName = "grease.example.com"
            b.includeGREASE = true
            guard let hello = parseClientHello(b.build()) else {
                return NMTest.expect(false, "parse failed")
            }
            NMTest.expect(hello.cipherSuites.contains(0x0A0A), "raw list keeps GREASE")
            NMTest.expect(!hello.realCipherSuites.contains(0x0A0A))
            NMTest.expect(!hello.realExtensions.contains(0x1A1A))
            NMTest.expect(!hello.realSupportedGroups.contains(0x2A2A))
        }

        NMTest.test("the GREASE test matches the whole defined set and nothing else") {
            for value: UInt16 in [0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A,
                                  0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
                                  0xCACA, 0xDADA, 0xEAEA, 0xFAFA] {
                NMTest.expect(isGREASE(value), "\(String(value, radix: 16)) is GREASE")
            }
            for value: UInt16 in [0x1301, 0x0000, 0x0010, 0x002B, 0x0A0B, 0x0B0A, 0xFFFF] {
                NMTest.expect(!isGREASE(value), "\(String(value, radix: 16)) is not GREASE")
            }
        }

        // The visible SNI under ECH is the public outer name. Showing it as the
        // destination would be confidently wrong, which is worse than blank.
        NMTest.test("Encrypted Client Hello is detected") {
            var b = TLSClientHelloBuilder()
            b.serverName = "cloudflare-ech.com"
            b.encryptedClientHello = true
            guard let hello = parseClientHello(b.build()) else {
                return NMTest.expect(false, "parse failed")
            }
            NMTest.expect(hello.hasEncryptedClientHello)
        }

        NMTest.test("a hostile SNI cannot inject control characters into a log") {
            var b = TLSClientHelloBuilder()
            b.serverName = "evil\u{0}.com"
            guard let hello = parseClientHello(b.build()) else {
                return NMTest.expect(false, "parse failed")
            }
            NMTest.expect(hello.serverName?.contains("\u{0}") == false,
                          "got \(hello.serverName ?? "nil")")
        }

        NMTest.test("SNI is folded to lower case so one host is one row") {
            var b = TLSClientHelloBuilder()
            b.serverName = "WWW.Example.COM"
            NMTest.equal(parseClientHello(b.build())?.serverName, "www.example.com")
        }

        NMTest.test("a ClientHello with no extensions parses") {
            var b = TLSClientHelloBuilder()
            b.serverName = nil
            b.alpn = []
            b.supportedVersions = []
            b.supportedGroups = []
            b.ecPointFormats = []
            b.signatureAlgorithms = []
            b.includeGREASE = false
            guard let hello = parseClientHello(b.build()) else {
                return NMTest.expect(false, "parse failed")
            }
            NMTest.expect(hello.serverName == nil)
            NMTest.equal(hello.effectiveVersion, 0x0303, "falls back to the legacy field")
        }
    }

    NMTest.suite("TLS / ServerHello") {

        NMTest.test("the selected version comes from the extension, not the legacy field") {
            var b = TLSServerHelloBuilder()
            b.legacyVersion = 0x0303
            b.selectedVersion = 0x0304
            guard let hello = parseServerHello(b.build()) else {
                return NMTest.expect(false, "parse failed")
            }
            NMTest.equal(hello.effectiveVersion, 0x0304)
            NMTest.expect(hello.isTLS13)
            NMTest.equal(hello.cipherSuite, 0x1301)
            NMTest.equal(hello.selectedGroup, 0x001D)
        }

        NMTest.test("a TLS 1.2 server hello has no supported_versions extension") {
            var b = TLSServerHelloBuilder()
            b.legacyVersion = 0x0303
            b.selectedVersion = nil
            b.cipherSuite = 0xC02F
            guard let hello = parseServerHello(b.build()) else {
                return NMTest.expect(false, "parse failed")
            }
            NMTest.equal(hello.effectiveVersion, 0x0303)
            NMTest.expect(!hello.isTLS13)
        }
    }

    NMTest.suite("TLS / fingerprints") {

        NMTest.test("JA4 has the documented shape") {
            var b = TLSClientHelloBuilder()
            b.serverName = "example.com"
            guard let hello = parseClientHello(b.build()) else {
                return NMTest.expect(false, "parse failed")
            }
            let (hash, raw) = TLSFingerprinter.ja4(hello)
            let parts = hash.split(separator: "_")
            NMTest.equal(parts.count, 3)
            NMTest.equal(parts[0].count, 10, "JA4_a is ten characters: \(parts[0])")
            NMTest.equal(parts[1].count, 12)
            NMTest.equal(parts[2].count, 12)
            NMTest.expect(hash.hasPrefix("t13d"),
                          "TCP, TLS 1.3, SNI present -- got \(hash)")
            NMTest.expect(hash.hasSuffix("h2") == false)
            NMTest.expect(raw.contains("1301"), "the raw form keeps the real values")
        }

        NMTest.test("no SNI flips the fourth character from d to i") {
            var withSNI = TLSClientHelloBuilder()
            withSNI.serverName = "example.com"
            var without = TLSClientHelloBuilder()
            without.serverName = nil

            guard let a = parseClientHello(withSNI.build()),
                  let b = parseClientHello(without.build()) else {
                return NMTest.expect(false, "parse failed")
            }
            NMTest.expect(TLSFingerprinter.ja4(a).hash.hasPrefix("t13d"))
            NMTest.expect(TLSFingerprinter.ja4(b).hash.hasPrefix("t13i"))
        }

        NMTest.test("the ALPN code is the first and last character of the first protocol") {
            func code(for alpn: [String]) -> String {
                var b = TLSClientHelloBuilder()
                b.serverName = "example.com"
                b.alpn = alpn
                guard let hello = parseClientHello(b.build()) else { return "??" }
                return String(TLSFingerprinter.ja4(hello).hash.prefix(10).suffix(2))
            }
            NMTest.equal(code(for: ["h2"]), "h2")
            NMTest.equal(code(for: ["http/1.1"]), "h1")
            NMTest.equal(code(for: ["h3"]), "h3")
            NMTest.equal(code(for: []), "00")
            NMTest.equal(code(for: ["x"]), "xx", "a one-character value doubles")
        }

        // The property that makes JA4 worth having. Chrome and BoringSSL
        // deliberately shuffle extensions on every connection; JA3 changes with
        // them, which is what made it unusable for modern browsers.
        NMTest.test("JA4 survives extension shuffling and JA3 does not") {
            var ordered = TLSClientHelloBuilder()
            ordered.serverName = "example.com"
            ordered.extensions = [(0x0015, [0, 0]), (0x0017, []), (0x001B, [2])]

            var shuffled = TLSClientHelloBuilder()
            shuffled.serverName = "example.com"
            shuffled.extensions = [(0x001B, [2]), (0x0015, [0, 0]), (0x0017, [])]

            guard let a = parseClientHello(ordered.build()),
                  let b = parseClientHello(shuffled.build()) else {
                return NMTest.expect(false, "parse failed")
            }
            NMTest.equal(TLSFingerprinter.ja4(a).hash, TLSFingerprinter.ja4(b).hash,
                         "JA4 sorts before hashing, so order must not matter")
            NMTest.expect(TLSFingerprinter.ja3(a).hash != TLSFingerprinter.ja3(b).hash,
                          "JA3 preserves wire order, which is exactly its weakness")
        }

        NMTest.test("cipher order does not change JA4 either") {
            var a = TLSClientHelloBuilder()
            a.serverName = "example.com"
            a.cipherSuites = [0x1301, 0x1302, 0x1303]
            var b = TLSClientHelloBuilder()
            b.serverName = "example.com"
            b.cipherSuites = [0x1303, 0x1301, 0x1302]

            guard let x = parseClientHello(a.build()), let y = parseClientHello(b.build()) else {
                return NMTest.expect(false, "parse failed")
            }
            NMTest.equal(TLSFingerprinter.ja4(x).hash, TLSFingerprinter.ja4(y).hash)
        }

        // Different clients must not collide, or the fingerprint says nothing.
        NMTest.test("a genuinely different client produces a different JA4") {
            var a = TLSClientHelloBuilder()
            a.serverName = "example.com"
            var b = TLSClientHelloBuilder()
            b.serverName = "example.com"
            b.cipherSuites = [0xC02B, 0xC02C, 0xC030]
            b.signatureAlgorithms = [0x0601, 0x0501]

            guard let x = parseClientHello(a.build()), let y = parseClientHello(b.build()) else {
                return NMTest.expect(false, "parse failed")
            }
            NMTest.expect(TLSFingerprinter.ja4(x).hash != TLSFingerprinter.ja4(y).hash)
        }

        NMTest.test("the destination does not change the client fingerprint") {
            var a = TLSClientHelloBuilder()
            a.serverName = "one.example.com"
            var b = TLSClientHelloBuilder()
            b.serverName = "a-completely-different-host.example.net"

            guard let x = parseClientHello(a.build()), let y = parseClientHello(b.build()) else {
                return NMTest.expect(false, "parse failed")
            }
            NMTest.equal(TLSFingerprinter.ja4(x).hash, TLSFingerprinter.ja4(y).hash,
                         "SNI is excluded from JA4_c precisely so this holds")
        }

        // External validation. The JA4 specification's worked example publishes
        // t13d1516h2_8daaf6152771_02713d6af862 for a client offering this
        // cipher list. Our JA4_b must equal that middle field, which pins the
        // GREASE stripping, the 4-hex rendering, the ascending sort, the comma
        // join and the SHA-256 truncation all at once -- any one of them wrong
        // produces a different digest.
        NMTest.test("JA4_b matches the published reference value for a known cipher list") {
            var b = TLSClientHelloBuilder()
            b.serverName = "www.example.com"
            b.cipherSuites = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030,
                              0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D,
                              0x002F, 0x0035]
            guard let hello = parseClientHello(b.build()) else {
                return NMTest.expect(false, "parse failed")
            }
            let (hash, raw) = TLSFingerprinter.ja4(hello)
            let ja4b = String(hash.split(separator: "_")[1])
            NMTest.equal(ja4b, "8daaf6152771",
                         "JA4_b diverged from the reference; raw was \(raw)")
            NMTest.equal(hello.realCipherSuites.count, 15)
        }

        NMTest.test("JA3 is a 32-character hex digest") {
            var b = TLSClientHelloBuilder()
            b.serverName = "example.com"
            guard let hello = parseClientHello(b.build()) else {
                return NMTest.expect(false, "parse failed")
            }
            let (hash, raw) = TLSFingerprinter.ja3(hello)
            NMTest.equal(hash.count, 32)
            NMTest.equal(raw.split(separator: ",", omittingEmptySubsequences: false).count, 5,
                         "version,ciphers,extensions,curves,formats")
        }
    }

    NMTest.suite("TLS / analyzer end to end") {

        final class Collector {
            var ssl: [SSLRecord] = []
            var conns: [ConnRecord] = []
        }

        func makeEngine() -> (FlowEngine, TLSAnalyzer, Collector) {
            let engine = FlowEngine()
            let analyzer = TLSAnalyzer()
            engine.analyzers.register(analyzer)
            let collector = Collector()
            engine.onSSLRecord = { collector.ssl.append($0) }
            engine.onConnectionRecord = { r, _ in collector.conns.append(r) }
            return (engine, analyzer, collector)
        }

        func send(_ engine: FlowEngine, _ payload: [UInt8], seq: UInt32,
                  fromClient: Bool, at ts: Timestamp) {
            let p = fromClient
                ? PacketFixture.ipv4TCP(.init(source: client, sourcePort: 49152,
                                              destination: server, destinationPort: 443,
                                              flags: [.psh, .ack], sequence: seq,
                                              payload: payload))
                : PacketFixture.ipv4TCP(.init(source: server, sourcePort: 443,
                                              destination: client, destinationPort: 49152,
                                              flags: [.psh, .ack], sequence: seq,
                                              payload: payload))
            let context = PacketContext(timestamp: ts, interfaceName: "en0",
                                        interfaceType: 0x06,
                                        direction: fromClient ? .outbound : .inbound,
                                        pid: 842, processName: "Safari")
            p.withUnsafeBytes { buf in
                guard var r = ByteReader(buf) else { return }
                engine.process(context, l3: &r)
            }
        }

        NMTest.test("a handshake produces an ssl row with SNI and fingerprints") {
            let (engine, _, collected) = makeEngine()
            var hello = TLSClientHelloBuilder()
            hello.serverName = "www.example.com"

            send(engine, hello.build(), seq: 1000, fromClient: true, at: base)
            send(engine, TLSServerHelloBuilder().build(), seq: 5000,
                 fromClient: false, at: base + 20_000)
            engine.flush()

            NMTest.equal(collected.ssl.count, 1)
            guard let r = collected.ssl.first else { return }
            NMTest.equal(r.sni, "www.example.com")
            NMTest.equal(r.versionName, "TLS 1.3")
            NMTest.equal(r.cipher, 0x1301)
            NMTest.equal(r.curve, 0x001D)
            NMTest.expect(r.established)
            NMTest.expect(r.ja4 != nil && r.ja3 != nil && r.ja4s != nil)
            NMTest.expect(r.ja4Raw != nil, "the unhashed form is kept for debugging")
            NMTest.equal(r.exec?.name, "Safari")
            NMTest.equal(r.sslHistory, "Cs")
        }

        // TLS 1.3 encrypts the Certificate message. "Encrypted" is a fact;
        // "unknown" would be a shrug, and the UI has to tell them apart.
        NMTest.test("a TLS 1.3 session reports its certificate as encrypted, not unknown") {
            let (engine, _, collected) = makeEngine()
            var hello = TLSClientHelloBuilder()
            hello.serverName = "tls13.example.com"

            send(engine, hello.build(), seq: 1000, fromClient: true, at: base)
            send(engine, TLSServerHelloBuilder().build(), seq: 5000,
                 fromClient: false, at: base + 20_000)
            engine.flush()

            guard let r = collected.ssl.first else { return NMTest.expect(false, "no row") }
            NMTest.expect(r.certsEncrypted, "must say encrypted rather than leaving it blank")
            NMTest.expect(r.subject == nil)
        }

        // The payoff: SNI is what the client asked THIS server for, so it beats
        // an inference from an earlier lookup.
        NMTest.test("SNI outranks the DNS cache on the conn row") {
            let engine = FlowEngine()
            engine.analyzers.register(TLSAnalyzer())
            var conns: [ConnRecord] = []
            engine.onConnectionRecord = { r, _ in conns.append(r) }

            // Seed the cache with a different name for the same address.
            engine.hostnames.insert(address: server, name: "stale.example.net",
                                    ttl: 300, requestingPID: 842, now: base)

            var hello = TLSClientHelloBuilder()
            hello.serverName = "real.example.com"
            send(engine, hello.build(), seq: 1000, fromClient: true, at: base + 1000)
            engine.flush()

            let tcp = conns.first { $0.respPort == 443 }
            NMTest.equal(tcp?.hostname, "real.example.com")
            NMTest.equal(tcp?.hostnameSource, .tlsSNI)
        }

        NMTest.test("an ECH connection does not assert the outer name") {
            let engine = FlowEngine()
            engine.analyzers.register(TLSAnalyzer())
            var conns: [ConnRecord] = []
            var ssl: [SSLRecord] = []
            engine.onConnectionRecord = { r, _ in conns.append(r) }
            engine.onSSLRecord = { ssl.append($0) }

            var hello = TLSClientHelloBuilder()
            hello.serverName = "cloudflare-ech.com"
            hello.encryptedClientHello = true
            send(engine, hello.build(), seq: 1000, fromClient: true, at: base)
            engine.flush()

            NMTest.expect(ssl.first?.sniIsOuter == true)
            NMTest.expect(conns.first { $0.respPort == 443 }?.hostname == nil,
                          "the outer name must not be presented as the destination")
        }

        NMTest.test("a ClientHello split across TCP segments is still parsed") {
            let (engine, _, collected) = makeEngine()
            var hello = TLSClientHelloBuilder()
            hello.serverName = "segmented.example.com"
            let bytes = hello.build()

            // Three segments, the split landing mid-extension.
            let third = bytes.count / 3
            send(engine, Array(bytes[0..<third]), seq: 1000, fromClient: true, at: base)
            send(engine, Array(bytes[third..<(third * 2)]), seq: UInt32(1000 + third),
                 fromClient: true, at: base + 1000)
            send(engine, Array(bytes[(third * 2)...]), seq: UInt32(1000 + third * 2),
                 fromClient: true, at: base + 2000)
            send(engine, TLSServerHelloBuilder().build(), seq: 5000,
                 fromClient: false, at: base + 3000)
            engine.flush()

            NMTest.equal(collected.ssl.count, 1)
            NMTest.equal(collected.ssl.first?.sni, "segmented.example.com")
        }

        NMTest.test("an abandoned handshake still yields a row with the SNI") {
            let (engine, _, collected) = makeEngine()
            var hello = TLSClientHelloBuilder()
            hello.serverName = "noreply.example.com"
            send(engine, hello.build(), seq: 1000, fromClient: true, at: base)
            engine.flush()

            NMTest.equal(collected.ssl.count, 1, "a ClientHello with no answer is a finding")
            NMTest.expect(collected.ssl.first?.established == false)
            NMTest.equal(collected.ssl.first?.sni, "noreply.example.com")
        }

        NMTest.test("non-TLS traffic on 443 is not labelled ssl") {
            let (engine, analyzer, collected) = makeEngine()
            send(engine, [UInt8](repeating: 0x47, count: 200), seq: 1000,
                 fromClient: true, at: base)
            engine.flush()
            NMTest.equal(collected.ssl.count, 0)
            NMTest.expect(analyzer.stats.notTLS > 0)
            NMTest.expect(collected.conns.first?.service != "ssl")
        }

        NMTest.test("the session table is bounded") {
            let engine = FlowEngine()
            let analyzer = TLSAnalyzer()
            analyzer.maximumSessions = 32
            engine.analyzers.register(analyzer)

            var hello = TLSClientHelloBuilder()
            hello.serverName = "flood.example.com"
            let bytes = hello.build()
            for i in 0..<500 {
                let p = PacketFixture.ipv4TCP(.init(
                    source: client, sourcePort: UInt16(20000 + i),
                    destination: server, destinationPort: 443,
                    flags: [.psh, .ack], sequence: 1000, payload: bytes))
                let context = PacketContext(timestamp: base + Timestamp(i),
                                            interfaceName: "en0", interfaceType: 0x06,
                                            direction: .outbound, pid: 842,
                                            processName: "Safari")
                p.withUnsafeBytes { buf in
                    guard var r = ByteReader(buf) else { return }
                    engine.process(context, l3: &r)
                }
            }
            NMTest.expect(analyzer.sessionCount <= 32,
                          "grew to \(analyzer.sessionCount)")
        }

        NMTest.test("bit-flipping a real handshake never crashes the parser") {
            var hello = TLSClientHelloBuilder()
            hello.serverName = "fuzz.example.com"
            let valid = hello.build()
            var rng = SplitMix64(seed: 0xF1FA)

            for _ in 0..<30_000 {
                var mutated = valid
                for _ in 0..<(1 + Int(rng.next() % 8)) {
                    let index = Int(rng.next() % UInt64(mutated.count))
                    mutated[index] = UInt8(truncatingIfNeeded: rng.next())
                }
                mutated.withUnsafeBytes { buf in
                    guard let reader = ByteReader(buf) else { return }
                    TLSRecordLayer.handshakeMessages(in: reader) { type, _, body in
                        if type == .clientHello {
                            _ = try? TLSHandshakeParser.parseClientHello(body)
                        } else if type == .serverHello {
                            _ = try? TLSHandshakeParser.parseServerHello(body)
                        }
                        return true
                    }
                }
            }
            NMTest.expect(true, "survived 30k mutations")
        }
    }
}
