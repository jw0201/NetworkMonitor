//
//  HostnameCacheTests.swift
//
//  The pid-keyed cache is the feature that distinguishes this from an IP-only
//  tool, so the tests that matter are the ones where an IP-only cache gives a
//  confidently wrong answer.
//

import NMAnalyzers
import NMCore
import NMFlow
import NMTestKit

private let cdn = IPAddress("151.101.1.1")!
private let client = IPAddress("192.168.0.31")!
private let resolver = IPAddress("192.168.0.1")!
private let base: Timestamp = 1_757_000_000_000_000

func runHostnameCacheTests() {
    NMTest.suite("HostnameCache / per-process resolution") {

        // The case that motivates the whole design. Two applications resolve
        // different names to the same CDN address; an IP-only cache keeps
        // whichever was last and presents it as fact for both.
        NMTest.test("two processes sharing a CDN address each get their own name") {
            let cache = HostnameCache()
            cache.insert(address: cdn, name: "news.example.com", ttl: 300,
                         requestingPID: 100, now: base)
            cache.insert(address: cdn, name: "cdn.othersite.net", ttl: 300,
                         requestingPID: 200, now: base + 200_000)

            NMTest.equal(cache.lookup(address: cdn, pid: 100, at: base + 1_000_000)?.name,
                         "news.example.com")
            NMTest.equal(cache.lookup(address: cdn, pid: 200, at: base + 1_000_000)?.name,
                         "cdn.othersite.net")
        }

        NMTest.test("a process that never resolved falls back to the wildcard") {
            let cache = HostnameCache()
            cache.insert(address: cdn, name: "news.example.com", ttl: 300,
                         requestingPID: 100, now: base)

            let hit = cache.lookup(address: cdn, pid: 999, at: base + 1_000_000)
            NMTest.equal(hit?.name, "news.example.com")
            NMTest.equal(hit?.source, .dnsWildcard, "and the fallback is labelled as such")
            NMTest.equal(cache.lookup(address: cdn, pid: 100, at: base + 1_000_000)?.source,
                         .dnsPerProcess)
        }

        // Presenting one of several possible names as the answer would be a
        // coin flip dressed as a fact.
        NMTest.test("several names for one address are reported as ambiguous") {
            let cache = HostnameCache()
            cache.insert(address: cdn, name: "a.example.com", ttl: 300,
                         requestingPID: 100, now: base)
            cache.insert(address: cdn, name: "b.example.com", ttl: 300,
                         requestingPID: 100, now: base + 1000)

            let hit = cache.lookup(address: cdn, pid: 100, at: base + 2000)
            NMTest.expect(hit?.ambiguous == true)
            NMTest.equal(hit?.name, "b.example.com", "newest wins, but the doubt is recorded")
        }

        NMTest.test("only a limited number of candidates is kept per address") {
            let cache = HostnameCache()
            for i in 0..<20 {
                cache.insert(address: cdn, name: "host\(i).example.com", ttl: 300,
                             requestingPID: 100, now: base + Timestamp(i))
            }
            NMTest.equal(cache.lookup(address: cdn, pid: 100, at: base + 100)?.name,
                         "host19.example.com")
        }

        NMTest.test("re-resolving the same name refreshes rather than duplicates") {
            let cache = HostnameCache()
            cache.insert(address: cdn, name: "same.example.com", ttl: 300,
                         requestingPID: 100, now: base)
            cache.insert(address: cdn, name: "same.example.com", ttl: 300,
                         requestingPID: 100, now: base + 10 * Time.microsPerSecond)
            let hit = cache.lookup(address: cdn, pid: 100, at: base + 11 * Time.microsPerSecond)
            NMTest.expect(hit?.ambiguous == false, "one name is not ambiguity")
        }
    }

    NMTest.suite("HostnameCache / time") {

        // CDNs hand out 5-30 second TTLs. Honouring them literally means the
        // connection that immediately follows the lookup finds nothing.
        NMTest.test("a short TTL is floored so the connection that follows still resolves") {
            let cache = HostnameCache()
            cache.insert(address: cdn, name: "short.example.com", ttl: 5,
                         requestingPID: 100, now: base)
            let hit = cache.lookup(address: cdn, pid: 100, at: base + 30 * Time.microsPerSecond)
            NMTest.equal(hit?.name, "short.example.com")
            NMTest.equal(hit?.originalTTL, 5,
                         "but the TTL the server actually gave is preserved for display")
        }

        NMTest.test("a very long TTL is capped so an answer cannot go stale forever") {
            let cache = HostnameCache()
            cache.insert(address: cdn, name: "forever.example.com", ttl: 86_400 * 30,
                         requestingPID: 100, now: base)
            NMTest.expect(cache.lookup(address: cdn, pid: 100,
                                       at: base + 7200 * Time.microsPerSecond) == nil,
                          "capped at an hour")
        }

        // Enrichment happens at flow creation, so the answer must reflect what
        // was known then -- not what the cache learned afterwards.
        NMTest.test("a lookup as of an earlier moment does not see later entries") {
            let cache = HostnameCache()
            cache.insert(address: cdn, name: "later.example.com", ttl: 300,
                         requestingPID: 100, now: base + 10 * Time.microsPerSecond)
            NMTest.expect(cache.lookup(address: cdn, pid: 100, at: base) == nil,
                          "the name was not known yet at that moment")
            NMTest.expect(cache.lookup(address: cdn, pid: 100,
                                       at: base + 11 * Time.microsPerSecond) != nil)
        }

        NMTest.test("expired entries are swept") {
            let cache = HostnameCache()
            cache.insert(address: cdn, name: "gone.example.com", ttl: 60,
                         requestingPID: 100, now: base)
            NMTest.equal(cache.count, 2, "per-process and wildcard")
            cache.sweep(now: base + 120 * Time.microsPerSecond)
            NMTest.equal(cache.count, 0)
        }

        NMTest.test("the cache is bounded") {
            let cache = HostnameCache()
            cache.capacity = 500
            for i in 0..<5000 {
                let address = IPAddress(v4HostOrder: UInt32(0x0A000000 + i))
                cache.insert(address: address, name: "host\(i).example.com", ttl: 3600,
                             requestingPID: Int32(i), now: base + Timestamp(i))
            }
            NMTest.expect(cache.count <= 1200,
                          "grew to \(cache.count); DGA malware would choose our memory use")
            NMTest.expect(cache.stats.evicted > 0)
        }
    }

    NMTest.suite("Enrichment / DNS lookup then connection") {

        func makeEngine() -> (FlowEngine, [ConnRecord]) {
            let engine = FlowEngine()
            engine.analyzers.register(DNSAnalyzer())
            return (engine, [])
        }

        func feed(_ engine: FlowEngine, _ bytes: [UInt8], _ ts: Timestamp,
                  pid: Int32, name: String, inbound: Bool = false) {
            let context = PacketContext(timestamp: ts, interfaceName: "en0",
                                        interfaceType: 0x06,
                                        direction: inbound ? .inbound : .outbound,
                                        pid: pid, processName: name)
            bytes.withUnsafeBytes { buf in
                guard var r = ByteReader(buf) else { return }
                engine.process(context, l3: &r)
            }
        }

        NMTest.test("a connection is labelled with the name the process looked up") {
            let engine = FlowEngine()
            engine.analyzers.register(DNSAnalyzer())
            var conns: [ConnRecord] = []
            engine.onConnectionRecord = { r, _ in conns.append(r) }

            var t = base
            // Safari resolves example.com.
            feed(engine, PacketFixture.ipv4UDP(
                    source: client, sourcePort: 54321,
                    destination: resolver, destinationPort: 53,
                    payload: DNSMessageBuilder.query("example.com").build()),
                 t, pid: 842, name: "Safari")
            t += 5000
            feed(engine, PacketFixture.ipv4UDP(
                    source: resolver, sourcePort: 53,
                    destination: client, destinationPort: 54321,
                    payload: DNSMessageBuilder.response(
                        "example.com", addresses: [cdn], ttl: 300).build()),
                 t, pid: 842, name: "Safari", inbound: true)

            // Then it connects there.
            t += 10_000
            feed(engine, PacketFixture.ipv4TCP(.init(
                    source: client, sourcePort: 49152,
                    destination: cdn, destinationPort: 443, flags: [.syn])),
                 t, pid: 842, name: "Safari")
            engine.flush()

            let tcp = conns.first { $0.proto == 6 }
            NMTest.equal(tcp?.hostname, "example.com",
                         "the conn row shows a name, not a bare address")
            NMTest.equal(tcp?.hostnameSource, .dnsPerProcess)
            NMTest.expect(tcp?.hostnameAmbiguous == false)
            NMTest.expect(engine.stats.hostnamesResolved > 0)
        }

        // The payoff of keying on pid. Both processes connect to the same
        // address; each row shows the name that process actually asked for.
        NMTest.test("two processes connecting to one address get different names") {
            let engine = FlowEngine()
            engine.analyzers.register(DNSAnalyzer())
            var conns: [ConnRecord] = []
            engine.onConnectionRecord = { r, _ in conns.append(r) }

            var t = base
            for (pid, name, host, port) in [(Int32(842), "Safari", "news.example.com", UInt16(54321)),
                                            (Int32(904), "Mail", "mail.othersite.net", UInt16(54322))] {
                feed(engine, PacketFixture.ipv4UDP(
                        source: client, sourcePort: port,
                        destination: resolver, destinationPort: 53,
                        payload: DNSMessageBuilder.query(host).build()),
                     t, pid: pid, name: name)
                t += 1000
                feed(engine, PacketFixture.ipv4UDP(
                        source: resolver, sourcePort: 53,
                        destination: client, destinationPort: port,
                        payload: DNSMessageBuilder.response(host, addresses: [cdn],
                                                            ttl: 300).build()),
                     t, pid: pid, name: name, inbound: true)
                t += 1000
            }

            for (pid, name, sport) in [(Int32(842), "Safari", UInt16(49152)),
                                       (Int32(904), "Mail", UInt16(49153))] {
                feed(engine, PacketFixture.ipv4TCP(.init(
                        source: client, sourcePort: sport,
                        destination: cdn, destinationPort: 443, flags: [.syn])),
                     t, pid: pid, name: name)
                t += 1000
            }
            engine.flush()

            let safari = conns.first { $0.exec?.name == "Safari" && $0.proto == 6 }
            let mail = conns.first { $0.exec?.name == "Mail" && $0.proto == 6 }
            NMTest.equal(safari?.hostname, "news.example.com")
            NMTest.equal(mail?.hostname, "mail.othersite.net",
                         "an IP-only cache would show both as whichever resolved last")
            NMTest.equal(safari?.hostnameSource, .dnsPerProcess)
            NMTest.equal(mail?.hostnameSource, .dnsPerProcess)
        }

        NMTest.test("an address nobody resolved stays unlabelled rather than guessed") {
            let engine = FlowEngine()
            engine.analyzers.register(DNSAnalyzer())
            var conns: [ConnRecord] = []
            engine.onConnectionRecord = { r, _ in conns.append(r) }

            feed(engine, PacketFixture.ipv4TCP(.init(
                    source: client, sourcePort: 49152,
                    destination: IPAddress("8.8.8.8")!, destinationPort: 443,
                    flags: [.syn])),
                 base, pid: 842, name: "Safari")
            engine.flush()

            NMTest.expect(conns.first?.hostname == nil)
            NMTest.equal(conns.first?.hostnameSource, HostnameSource.none)
        }
    }
}
