//
//  DNSAnalyzerTests.swift
//
//  End to end: UDP packets in, dns.log rows out, via the flow engine.
//

import NMAnalyzers
import NMCore
import NMFlow
import NMTestKit

private let client = IPAddress("192.168.0.31")!
private let resolver = IPAddress("192.168.0.1")!

private func dnsPacket(_ message: [UInt8], fromClient: Bool,
                       clientPort: UInt16 = 54321) -> [UInt8] {
    fromClient
        ? PacketFixture.ipv4UDP(source: client, sourcePort: clientPort,
                                destination: resolver, destinationPort: 53,
                                payload: message)
        : PacketFixture.ipv4UDP(source: resolver, sourcePort: 53,
                                destination: client, destinationPort: clientPort,
                                payload: message)
}

private struct Harness {
    let engine = FlowEngine()
    let analyzer = DNSAnalyzer()
    var dnsRecords: [DNSRecord] = []
    var connRecords: [ConnRecord] = []
    var resolved: [(IPAddress, String, UInt32, Int32)] = []

    init() {
        engine.analyzers.register(analyzer)
    }
}

private final class Collector {
    var dns: [DNSRecord] = []
    var conns: [ConnRecord] = []
    var resolved: [(address: IPAddress, name: String, ttl: UInt32, pid: Int32)] = []
}

private func makeEngine() -> (FlowEngine, DNSAnalyzer, Collector) {
    let engine = FlowEngine()
    let analyzer = DNSAnalyzer()
    engine.analyzers.register(analyzer)
    let collector = Collector()
    engine.onDNSRecord = { collector.dns.append($0) }
    engine.onConnectionRecord = { r, _ in collector.conns.append(r) }
    engine.onResolvedName = { a, n, t, p in
        collector.resolved.append((a, n, t, p))
    }
    return (engine, analyzer, collector)
}

private func feed(_ engine: FlowEngine, _ bytes: [UInt8], _ ts: Timestamp,
                  pid: Int32 = 8080, name: String = "Safari",
                  inbound: Bool = false) {
    let context = PacketContext(timestamp: ts, interfaceName: "en0",
                                interfaceType: 0x06,
                                direction: inbound ? .inbound : .outbound,
                                pid: pid, processName: name)
    bytes.withUnsafeBytes { buf in
        guard var r = ByteReader(buf) else { return }
        engine.process(context, l3: &r)
    }
}

func runDNSAnalyzerTests() {
    NMTest.suite("DNSAnalyzer / query and response") {

        NMTest.test("a query and its answer produce one row with a round trip time") {
            let (engine, _, collected) = makeEngine()
            var t: Timestamp = 1_757_000_000_000_000

            feed(engine, dnsPacket(DNSMessageBuilder.query("example.com").build(),
                                   fromClient: true), t)
            t += 12_500                                   // 12.5 ms later
            feed(engine, dnsPacket(DNSMessageBuilder.response(
                    "example.com", addresses: [IPAddress("93.184.216.34")!], ttl: 300).build(),
                 fromClient: false), t, inbound: true)

            NMTest.equal(collected.dns.count, 1)
            guard let r = collected.dns.first else { return }
            NMTest.equal(r.query, "example.com")
            NMTest.equal(r.rttUs, 12_500, "round trip time comes from the pairing")
            NMTest.equal(r.rcode, 0)
            NMTest.equal(r.answers, ["93.184.216.34"])
            NMTest.equal(r.ttls, [300])
            NMTest.expect(!r.rejected)
            NMTest.equal(r.exec?.name, "Safari",
                         "attribution is taken from the QUERY, not the response")
        }

        NMTest.test("the resolved address is offered to the enrichment cache") {
            let (engine, _, collected) = makeEngine()
            let t: Timestamp = 1_757_000_000_000_000
            feed(engine, dnsPacket(DNSMessageBuilder.query("example.com").build(),
                                   fromClient: true), t)
            feed(engine, dnsPacket(DNSMessageBuilder.response(
                    "example.com", addresses: [IPAddress("93.184.216.34")!], ttl: 600).build(),
                 fromClient: false), t + 1000, inbound: true)

            NMTest.equal(collected.resolved.count, 1)
            NMTest.equal(collected.resolved.first?.address, IPAddress("93.184.216.34")!)
            NMTest.equal(collected.resolved.first?.name, "example.com")
            NMTest.equal(collected.resolved.first?.ttl, 600)
            NMTest.equal(collected.resolved.first?.pid, 8080,
                         "the REQUESTING process, which is what makes the cache unambiguous")
        }

        // A CDN answer is a chain of aliases. Reporting the final edge-node
        // name would be technically true and useless -- the application asked
        // for the original name and that is what the user recognises.
        NMTest.test("a CNAME chain resolves back to the name originally asked for") {
            let (engine, _, collected) = makeEngine()
            let t: Timestamp = 1_757_000_000_000_000
            feed(engine, dnsPacket(DNSMessageBuilder.query("www.example.com").build(),
                                   fromClient: true), t)
            feed(engine, dnsPacket(DNSMessageBuilder.response(
                    "www.example.com",
                    addresses: [IPAddress("151.101.1.1")!],
                    cnameChain: ["example.map.fastly.net", "dualstack.edge-42.net"]).build(),
                 fromClient: false), t + 1000, inbound: true)

            NMTest.equal(collected.resolved.count, 1)
            NMTest.equal(collected.resolved.first?.name, "www.example.com",
                         "not dualstack.edge-42.net")
            NMTest.equal(collected.dns.first?.answers.count, 3,
                         "the chain is still recorded in full in the log row")
        }

        NMTest.test("multiple A records all reach the cache") {
            let (engine, _, collected) = makeEngine()
            let t: Timestamp = 1_757_000_000_000_000
            feed(engine, dnsPacket(DNSMessageBuilder.query("example.com").build(),
                                   fromClient: true), t)
            feed(engine, dnsPacket(DNSMessageBuilder.response(
                    "example.com",
                    addresses: [IPAddress("1.1.1.1")!, IPAddress("1.0.0.1")!,
                                IPAddress("2606:4700:4700::1111")!]).build(),
                 fromClient: false), t + 1000, inbound: true)
            NMTest.equal(collected.resolved.count, 3)
        }

        NMTest.test("NXDOMAIN is recorded with its response code") {
            let (engine, _, collected) = makeEngine()
            let t: Timestamp = 1_757_000_000_000_000
            feed(engine, dnsPacket(DNSMessageBuilder.query("nope.example.com").build(),
                                   fromClient: true), t)
            var response = DNSMessageBuilder.query("nope.example.com")
            response.isResponse = true
            response.responseCode = 3
            feed(engine, dnsPacket(response.build(), fromClient: false), t + 2000,
                 inbound: true)

            NMTest.equal(collected.dns.first?.rcode, 3)
            NMTest.equal(collected.dns.first?.answers.count, 0)
            NMTest.equal(collected.resolved.count, 0, "nothing to cache")
        }

        NMTest.test("the flow is labelled with the service it turned out to carry") {
            let (engine, _, collected) = makeEngine()
            let t: Timestamp = 1_757_000_000_000_000
            feed(engine, dnsPacket(DNSMessageBuilder.query("example.com").build(),
                                   fromClient: true), t)
            engine.flush()
            NMTest.equal(collected.conns.first?.service, "dns")
        }

        NMTest.test("mDNS is labelled separately from unicast DNS") {
            let (engine, _, collected) = makeEngine()
            let t: Timestamp = 1_757_000_000_000_000
            let mdns = PacketFixture.ipv4UDP(
                source: client, sourcePort: 5353,
                destination: IPAddress("224.0.0.251")!, destinationPort: 5353,
                payload: DNSMessageBuilder.query("_airplay._tcp.local").build())
            feed(engine, mdns, t, pid: 234, name: "mDNSResponder")
            engine.flush()
            NMTest.equal(collected.conns.first?.service, "mdns")
        }
    }

    NMTest.suite("DNSAnalyzer / unanswered queries") {

        // The diagnostically valuable case. A pairing that only fires on
        // responses shows nothing at all in exactly the situation a user is
        // trying to debug: a resolver that has stopped answering.
        NMTest.test("a query with no answer is reported as rejected") {
            let (engine, analyzer, collected) = makeEngine()
            let t: Timestamp = 1_757_000_000_000_000
            feed(engine, dnsPacket(DNSMessageBuilder.query("blackhole.example.com").build(),
                                   fromClient: true), t)
            NMTest.equal(collected.dns.count, 0, "not yet -- it might still be answered")
            NMTest.equal(analyzer.pendingCount, 1)

            engine.tick(now: t + 10 * Time.microsPerSecond)

            NMTest.equal(collected.dns.count, 1)
            NMTest.expect(collected.dns.first?.rejected == true)
            NMTest.equal(collected.dns.first?.query, "blackhole.example.com")
            NMTest.expect(collected.dns.first?.rttUs == nil, "there was no round trip")
            NMTest.equal(collected.dns.first?.exec?.name, "Safari")
            NMTest.equal(analyzer.pendingCount, 0)
        }

        NMTest.test("a slow answer is still paired, not declared unanswered") {
            let (engine, analyzer, collected) = makeEngine()
            let t: Timestamp = 1_757_000_000_000_000
            feed(engine, dnsPacket(DNSMessageBuilder.query("slow.example.com").build(),
                                   fromClient: true), t)
            engine.tick(now: t + 2 * Time.microsPerSecond)     // under the timeout
            NMTest.equal(collected.dns.count, 0)

            feed(engine, dnsPacket(DNSMessageBuilder.response(
                    "slow.example.com", addresses: [IPAddress("1.2.3.4")!]).build(),
                 fromClient: false), t + 3 * Time.microsPerSecond, inbound: true)

            NMTest.equal(collected.dns.count, 1)
            NMTest.expect(collected.dns.first?.rejected == false)
            NMTest.equal(collected.dns.first?.rttUs, 3 * Time.microsPerSecond)
            NMTest.equal(analyzer.pendingCount, 0)
        }

        NMTest.test("the pending table is bounded under a query flood") {
            let (engine, analyzer, _) = makeEngine()
            var t: Timestamp = 1_757_000_000_000_000
            for i in 0..<20_000 {
                let message = DNSMessageBuilder.query("host\(i).example.com",
                                                      transactionID: UInt16(i & 0xFFFF)).build()
                feed(engine, dnsPacket(message, fromClient: true,
                                       clientPort: UInt16(20_000 + (i % 4000))), t)
                t += 10
            }
            NMTest.expect(analyzer.pendingCount <= analyzer.maximumPending,
                          "pending grew to \(analyzer.pendingCount)")
            NMTest.expect(analyzer.stats.pendingEvicted > 0)
        }

        // mDNS is broadcast with no expectation of a matching response on the
        // same flow, so pairing it would manufacture "unanswered" rows forever.
        NMTest.test("multicast DNS queries are not paired") {
            let (engine, analyzer, collected) = makeEngine()
            let t: Timestamp = 1_757_000_000_000_000
            let mdns = PacketFixture.ipv4UDP(
                source: client, sourcePort: 5353,
                destination: IPAddress("224.0.0.251")!, destinationPort: 5353,
                payload: DNSMessageBuilder.query("_companion-link._tcp.local").build())
            feed(engine, mdns, t, pid: 234, name: "mDNSResponder")
            NMTest.equal(analyzer.pendingCount, 0)
            engine.tick(now: t + 30 * Time.microsPerSecond)
            NMTest.equal(collected.dns.count, 0, "no phantom unanswered row")
        }
    }

    NMTest.suite("DNSAnalyzer / misidentified traffic") {

        NMTest.test("non-DNS traffic on port 53 is counted, not mistaken for DNS") {
            let (engine, analyzer, collected) = makeEngine()
            let t: Timestamp = 1_757_000_000_000_000
            let junk = PacketFixture.ipv4UDP(source: client, sourcePort: 54321,
                                             destination: resolver, destinationPort: 53,
                                             payload: [UInt8](repeating: 0xFF, count: 40))
            feed(engine, junk, t)
            NMTest.equal(collected.dns.count, 0)
            NMTest.expect(analyzer.stats.malformed > 0)
        }

        NMTest.test("an empty payload does not reach the analyzer") {
            let (engine, analyzer, _) = makeEngine()
            let t: Timestamp = 1_757_000_000_000_000
            let empty = PacketFixture.ipv4UDP(source: client, sourcePort: 54321,
                                              destination: resolver, destinationPort: 53)
            feed(engine, empty, t)
            NMTest.equal(analyzer.stats.queries, 0)
            NMTest.equal(analyzer.stats.malformed, 0)
        }

        NMTest.test("DNS over TCP handles the two-byte length prefix") {
            let (engine, _, collected) = makeEngine()
            let t: Timestamp = 1_757_000_000_000_000
            let query = DNSMessageBuilder.query("tcp.example.com").build()
            var framed = [UInt8(query.count >> 8), UInt8(query.count & 0xFF)]
            framed.append(contentsOf: query)

            let packet = PacketFixture.ipv4TCP(.init(
                source: client, sourcePort: 54321,
                destination: resolver, destinationPort: 53,
                flags: [.psh, .ack], payload: framed))
            feed(engine, packet, t)
            engine.flush()
            NMTest.equal(collected.conns.first?.service, "dns")
        }
    }
}
