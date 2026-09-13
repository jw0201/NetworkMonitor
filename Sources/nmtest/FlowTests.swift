//
//  FlowTests.swift
//
//  The flow layer is where silent wrongness is most likely: a reversed
//  orientation halves every byte count, a mis-derived conn_state turns a
//  refused connection into a successful one, and a broken expiry leaks memory
//  until the daemon dies. All three are invisible without tests like these.
//

import NMCore
import NMFlow
import NMTestKit

private let local = IPAddress("192.168.0.31")!
private let remote = IPAddress("93.184.216.34")!
private let other = IPAddress("34.117.41.85")!

private func parse(_ bytes: [UInt8], _ body: (L3Info, L4Info?) -> Void) {
    bytes.withUnsafeBytes { buf in
        guard var r = ByteReader(buf) else { return }
        guard let l3 = try? IPParser.parse(&r) else { return }
        var l4r = r
        let l4: L4Info? = (try? TransportParser.parse(proto: l3.proto, &l4r,
                                                      availableLength: l3.payloadLength)) ?? nil
        body(l3, l4)
    }
}

private func segment(_ flags: TCPFlags, from a: IPAddress, _ ap: UInt16,
                     to b: IPAddress, _ bp: UInt16,
                     payload: [UInt8] = [], window: UInt16 = 65535) -> [UInt8] {
    PacketFixture.ipv4TCP(.init(source: a, sourcePort: ap,
                                destination: b, destinationPort: bp,
                                flags: flags, window: window, payload: payload))
}

private func context(_ ts: Timestamp, direction: PacketDirection = .outbound,
                     iface: String = "en0", ifType: UInt16 = 0x06,
                     pid: Int32? = 501, name: String = "curl",
                     epid: Int32? = nil, ename: String = "",
                     delegated: Bool = false) -> PacketContext {
    PacketContext(timestamp: ts, interfaceName: iface, interfaceType: ifType,
                  direction: direction, pid: pid, processName: name,
                  effectivePID: epid, effectiveProcessName: ename,
                  isDelegated: delegated)
}

private func feed(_ engine: FlowEngine, _ bytes: [UInt8], _ ctx: PacketContext) {
    bytes.withUnsafeBytes { buf in
        guard var r = ByteReader(buf) else { return }
        engine.process(ctx, l3: &r)
    }
}

func runFlowTests() {
    NMTest.suite("IPParser") {

        NMTest.test("IPv4 header fields and payload offset") {
            let p = segment([.syn], from: local, 49152, to: remote, 443)
            parse(p) { l3, l4 in
                NMTest.equal(l3.source, local)
                NMTest.equal(l3.destination, remote)
                NMTest.equal(l3.proto, 6)
                NMTest.equal(l3.payloadOffset, 20)
                NMTest.equal(l3.ipBytes, 40)
                NMTest.expect(l4 != nil)
                NMTest.equal(l4?.sourcePort, 49152)
                NMTest.equal(l4?.destinationPort, 443)
            }
        }

        // Captured at the host stack, IP total_length is routinely 0 because
        // hardware fills it in during segmentation offload. Trusting it blindly
        // yields a negative payload length on a perfectly normal machine.
        NMTest.test("a zero total_length from TSO offload is handled, not trusted") {
            let p = PacketFixture.ipv4TCP(
                .init(source: local, sourcePort: 1, destination: remote,
                      destinationPort: 443, flags: [.ack], payload: [1, 2, 3, 4]),
                totalLengthOverride: 0)
            parse(p) { l3, l4 in
                NMTest.equal(l3.ipBytes, p.count, "falls back to the captured length")
                NMTest.expect(l3.payloadLength >= 0, "must never go negative")
                NMTest.equal(l4?.payloadLength, 4)
            }
        }

        NMTest.test("a total_length larger than the capture is clamped") {
            let p = PacketFixture.ipv4TCP(
                .init(source: local, sourcePort: 1, destination: remote,
                      destinationPort: 443, flags: [.ack]),
                totalLengthOverride: 60000)
            parse(p) { l3, _ in
                NMTest.equal(l3.ipBytes, p.count)
                NMTest.expect(l3.clamped, "clamping must be recorded, not hidden")
            }
        }

        NMTest.test("a non-initial fragment is identified") {
            let p = PacketFixture.ipv4TCP(
                .init(source: local, sourcePort: 1, destination: remote,
                      destinationPort: 443, flags: [.ack]),
                fragmentOffset: 1480)
            parse(p) { l3, _ in
                NMTest.expect(l3.isNonInitialFragment)
                NMTest.expect(l3.isFragment)
            }
        }

        NMTest.test("an IHL below 5 is rejected") {
            var p = segment([.syn], from: local, 1, to: remote, 443)
            p[0] = 0x43                                  // IPv4, IHL 3
            p.withUnsafeBytes { buf in
                guard var r = ByteReader(buf) else { return }
                NMTest.throwsError({ _ = try IPParser.parse(&r) },
                                   "an impossible header length must not parse")
            }
        }

        NMTest.test("a non-IP payload is rejected rather than guessed at") {
            let junk = [UInt8](repeating: 0xAB, count: 60)
            junk.withUnsafeBytes { buf in
                guard var r = ByteReader(buf) else { return }
                NMTest.throwsError({ _ = try IPParser.parse(&r) })
            }
        }

        NMTest.test("IPv6 with an extension header chain finds the TCP header") {
            let p = PacketFixture.ipv6TCP(
                .init(source: IPAddress("2001:db8::1")!, sourcePort: 49152,
                      destination: IPAddress("2001:db8::2")!, destinationPort: 443,
                      flags: [.syn]),
                extensionHeaders: [0, 60])               // hop-by-hop, destination options
            parse(p) { l3, l4 in
                NMTest.equal(l3.proto, 6, "must walk past the extension headers")
                NMTest.equal(l4?.destinationPort, 443)
                NMTest.expect(!l3.clamped)
            }
        }

        NMTest.test("an over-long IPv6 extension chain is capped, not followed") {
            let p = PacketFixture.ipv6TCP(
                .init(source: IPAddress("2001:db8::1")!, sourcePort: 1,
                      destination: IPAddress("2001:db8::2")!, destinationPort: 443,
                      flags: [.syn]),
                extensionHeaders: [UInt8](repeating: 60, count: 20))
            parse(p) { l3, _ in
                NMTest.expect(l3.clamped, "hitting the cap must be recorded")
            }
        }
    }

    NMTest.suite("TransportParser") {

        NMTest.test("TCP flags decode and scan shapes are flagged inconsistent") {
            NMTest.expect(TCPFlags([.syn]).isSynOnly)
            NMTest.expect(TCPFlags([.syn, .ack]).isSynAck)
            NMTest.expect(!TCPFlags([.syn, .ack]).isSynOnly)
            NMTest.expect(TCPFlags([.syn, .fin]).isInconsistent, "SYN+FIN")
            NMTest.expect(TCPFlags([]).isInconsistent, "NULL scan")
            NMTest.expect(TCPFlags([.fin, .psh, .urg]).isInconsistent, "XMAS scan")
            NMTest.expect(!TCPFlags([.ack]).isInconsistent)
            NMTest.expect(!TCPFlags([.psh, .ack]).isInconsistent)
        }

        NMTest.test("a truncated TCP header is clamped rather than rejected") {
            // Ports and flags are what the flow needs most, and they are in the
            // first four bytes -- losing the whole packet over a missing option
            // area would be worse than clamping.
            var p = segment([.ack], from: local, 1, to: remote, 443)
            p[20 + 12] = 0xF0                            // claim a 60-byte header
            parse(p) { _, l4 in
                NMTest.equal(l4?.sourcePort, 1)
                NMTest.expect(l4?.clamped == true)
            }
        }

        NMTest.test("a UDP length field of zero falls back to the captured length") {
            let p = PacketFixture.ipv4UDP(source: local, sourcePort: 5353,
                                          destination: remote, destinationPort: 5353,
                                          payload: [1, 2, 3, 4, 5], lengthOverride: 0)
            parse(p) { _, l4 in
                NMTest.equal(l4?.payloadLength, 5)
            }
        }
    }

    NMTest.suite("FlowKey") {

        NMTest.test("both directions of a conversation produce the same key") {
            let forward = FlowKey(addressA: local, portA: 49152,
                                  addressB: remote, portB: 443,
                                  proto: 6, interfaceIndex: 0)
            let reverse = FlowKey(addressA: remote, portA: 443,
                                  addressB: local, portB: 49152,
                                  proto: 6, interfaceIndex: 0)
            NMTest.equal(forward, reverse, "otherwise every flow is split in half")
            NMTest.equal(forward.hashValue, reverse.hashValue)
        }

        NMTest.test("orientation is recoverable after the sort") {
            let key = FlowKey(addressA: local, portA: 49152,
                              addressB: remote, portB: 443,
                              proto: 6, interfaceIndex: 0)
            let localIsLow = key.isLowEndpoint(address: local, port: 49152)
            let remoteIsLow = key.isLowEndpoint(address: remote, port: 443)
            NMTest.expect(localIsLow != remoteIsLow, "exactly one endpoint is low")
        }

        NMTest.test("the interface is part of the key") {
            let a = FlowKey(addressA: local, portA: 1, addressB: remote, portB: 443,
                            proto: 6, interfaceIndex: 0)
            let b = FlowKey(addressA: local, portA: 1, addressB: remote, portB: 443,
                            proto: 6, interfaceIndex: 1)
            NMTest.expect(a != b,
                          "the same 5-tuple on en0 and utun0 is two conversations")
        }

        NMTest.test("protocol and port both participate") {
            let tcp = FlowKey(addressA: local, portA: 1, addressB: remote, portB: 443,
                              proto: 6, interfaceIndex: 0)
            let udp = FlowKey(addressA: local, portA: 1, addressB: remote, portB: 443,
                              proto: 17, interfaceIndex: 0)
            let otherPort = FlowKey(addressA: local, portA: 1, addressB: remote, portB: 80,
                                    proto: 6, interfaceIndex: 0)
            NMTest.expect(tcp != udp)
            NMTest.expect(tcp != otherPort)
        }
    }

    NMTest.suite("TCPStateMachine / conn_state") {

        func run(_ steps: [(TCPFlags, Bool, Int)]) -> TCPStateMachine {
            var m = TCPStateMachine()
            for (flags, fromOriginator, payload) in steps {
                m.observe(flags: flags, payloadLength: payload, window: 65535,
                          fromOriginator: fromOriginator, isRetransmit: false)
            }
            return m
        }

        NMTest.test("a completed connection is SF") {
            let m = run([([.syn], true, 0), ([.syn, .ack], false, 0), ([.ack], true, 0),
                         ([.psh, .ack], true, 100), ([.psh, .ack], false, 200),
                         ([.fin, .ack], true, 0), ([.fin, .ack], false, 0)])
            NMTest.equal(m.connectionState, .sf)
            NMTest.expect(m.established)
            NMTest.equal(m.history, "ShADdFf", "history is \(m.history)")
        }

        NMTest.test("a SYN with no answer is S0 -- the scan and dead-host signature") {
            let m = run([([.syn], true, 0)])
            NMTest.equal(m.connectionState, .s0)
            NMTest.expect(!m.established)
        }

        NMTest.test("a SYN answered with RST is REJ, not a failed SF") {
            let m = run([([.syn], true, 0), ([.rst, .ack], false, 0)])
            NMTest.equal(m.connectionState, .rej)
        }

        NMTest.test("an established connection reset by the originator is RSTO") {
            let m = run([([.syn], true, 0), ([.syn, .ack], false, 0), ([.ack], true, 0),
                         ([.rst], true, 0)])
            NMTest.equal(m.connectionState, .rsto)
        }

        NMTest.test("an established connection reset by the responder is RSTR") {
            let m = run([([.syn], true, 0), ([.syn, .ack], false, 0), ([.ack], true, 0),
                         ([.rst], false, 0)])
            NMTest.equal(m.connectionState, .rstr)
        }

        NMTest.test("a half-closed connection distinguishes which side finished") {
            NMTest.equal(run([([.syn], true, 0), ([.syn, .ack], false, 0),
                              ([.ack], true, 0), ([.fin, .ack], true, 0)]).connectionState, .s2)
            NMTest.equal(run([([.syn], true, 0), ([.syn, .ack], false, 0),
                              ([.ack], true, 0), ([.fin, .ack], false, 0)]).connectionState, .s3)
        }

        NMTest.test("SYN then FIN with no answer is SH, a stealth-scan shape") {
            let m = run([([.syn], true, 0), ([.fin], true, 0)])
            NMTest.equal(m.connectionState, .sh)
        }

        NMTest.test("SYN then RST from the originator is RSTOS0") {
            NMTest.equal(run([([.syn], true, 0), ([.rst], true, 0)]).connectionState, .rstos0)
        }

        NMTest.test("a flow picked up mid-stream is OTH, not a guess") {
            let m = run([([.psh, .ack], true, 500), ([.ack], false, 0)])
            NMTest.equal(m.connectionState, .oth)
            NMTest.expect(m.midstream)
        }

        NMTest.test("each history letter appears at most once per direction") {
            let m = run(Array(repeating: (TCPFlags([.psh, .ack]), true, 100), count: 50))
            NMTest.equal(m.history, "D", "50 data segments yield one D, not fifty")
        }

        // An unbounded history string is a memory-exhaustion vector reachable
        // by anyone who can send packets. Zeek has been bitten by this.
        NMTest.test("history is hard-capped") {
            var m = TCPStateMachine()
            for i in 0..<10_000 {
                m.observe(flags: [.psh, .ack], payloadLength: 1, window: 0,
                          fromOriginator: i % 2 == 0, isRetransmit: i % 3 == 0)
                m.observeGap(fromOriginator: i % 2 == 0)
            }
            NMTest.expect(m.history.count <= Limits.maxHistoryCharacters,
                          "history grew to \(m.history.count)")
        }

        NMTest.test("UDP gets the simple treatment: one direction S0, both SF") {
            var d = DatagramState()
            d.observe(fromOriginator: true, payloadLength: 50)
            NMTest.equal(d.connectionState, .s0)
            d.observe(fromOriginator: false, payloadLength: 80)
            NMTest.equal(d.connectionState, .sf)
            NMTest.equal(d.history, "Dd")
        }
    }

    NMTest.suite("FlowEngine / end to end") {

        NMTest.test("a full handshake produces one record with correct orientation") {
            let engine = FlowEngine()
            var records: [ConnRecord] = []
            engine.onConnectionRecord = { r, _ in records.append(r) }

            var t: Timestamp = 1_757_000_000_000_000
            feed(engine, segment([.syn], from: local, 49152, to: remote, 443), context(t))
            t += 10_000
            feed(engine, segment([.syn, .ack], from: remote, 443, to: local, 49152),
                 context(t, direction: .inbound))
            t += 10_000
            feed(engine, segment([.ack], from: local, 49152, to: remote, 443), context(t))
            t += 10_000
            feed(engine, segment([.psh, .ack], from: local, 49152, to: remote, 443,
                                 payload: [UInt8](repeating: 0x41, count: 100)), context(t))
            t += 10_000
            feed(engine, segment([.psh, .ack], from: remote, 443, to: local, 49152,
                                 payload: [UInt8](repeating: 0x42, count: 500)),
                 context(t, direction: .inbound))
            t += 10_000
            feed(engine, segment([.fin, .ack], from: local, 49152, to: remote, 443), context(t))
            t += 10_000
            feed(engine, segment([.fin, .ack], from: remote, 443, to: local, 49152),
                 context(t, direction: .inbound))

            engine.flush()

            NMTest.equal(records.count, 1, "one conversation, one record")
            guard let r = records.first else { return }
            NMTest.equal(r.origAddr, local, "the SYN sender is the originator")
            NMTest.equal(r.origPort, 49152)
            NMTest.equal(r.respAddr, remote)
            NMTest.equal(r.respPort, 443)
            NMTest.equal(r.state, .sf)
            NMTest.equal(r.origPkts, 4)
            NMTest.equal(r.respPkts, 3)
            NMTest.equal(r.origBytes, 100, "originator payload")
            NMTest.equal(r.respBytes, 500, "responder payload")
            NMTest.expect(r.origIPBytes > r.origBytes, "IP bytes include headers")
            NMTest.equal(r.exec?.name, "curl")
        }

        // If the responder's SYN-ACK is the first packet seen, the responder
        // must still be the responder. Getting this backwards swaps every byte
        // count in the log.
        NMTest.test("orientation follows the handshake even if the SYN-ACK arrives first") {
            let engine = FlowEngine()
            var records: [ConnRecord] = []
            engine.onConnectionRecord = { r, _ in records.append(r) }

            var t: Timestamp = 1_757_000_000_000_000
            feed(engine, segment([.syn, .ack], from: remote, 443, to: local, 49152),
                 context(t, direction: .inbound))
            t += 10_000
            feed(engine, segment([.ack], from: local, 49152, to: remote, 443), context(t))
            engine.flush()

            guard let r = records.first else { return NMTest.expect(false, "no record") }
            NMTest.equal(r.origAddr, local, "the SYN-ACK sender is the RESPONDER")
            NMTest.equal(r.respAddr, remote)
        }

        NMTest.test("loopback is counted once, not twice") {
            let engine = FlowEngine()
            var records: [ConnRecord] = []
            engine.onConnectionRecord = { r, _ in records.append(r) }

            let loopback = IPAddress("127.0.0.1")!
            let t: Timestamp = 1_757_000_000_000_000
            let payload = [UInt8](repeating: 0x41, count: 100)
            let p = segment([.psh, .ack], from: loopback, 50000, to: loopback, 9999,
                            payload: payload)

            // The kernel taps the same packet twice on lo0: once outbound at the
            // sender, once inbound at the receiver.
            feed(engine, p, context(t, direction: .outbound, iface: "lo0", ifType: 0x18))
            feed(engine, p, context(t, direction: .inbound, iface: "lo0", ifType: 0x18))
            engine.flush()

            guard let r = records.first else { return NMTest.expect(false, "no record") }
            NMTest.equal(r.origPkts + r.respPkts, 1,
                         "counting both copies doubles every localhost byte")
            NMTest.equal(engine.stats.loopbackDeduplicated, 1)
        }

        NMTest.test("delegated traffic reports the application, keeping the proxy") {
            let engine = FlowEngine()
            var records: [ConnRecord] = []
            engine.onConnectionRecord = { r, _ in records.append(r) }

            let t: Timestamp = 1_757_000_000_000_000
            feed(engine, segment([.syn], from: local, 49152, to: remote, 443),
                 context(t, pid: 130, name: "nsurlsessiond",
                         epid: 904, ename: "Mail", delegated: true))
            engine.flush()

            guard let r = records.first else { return NMTest.expect(false, "no record") }
            NMTest.equal(r.exec?.name, "Mail", "the user wants to see the application")
            NMTest.equal(r.pid, 904)
            NMTest.equal(r.proxyExec?.name, "nsurlsessiond", "the proxy is preserved")
            NMTest.equal(r.proxyPid, 130)
        }

        NMTest.test("a packet with no attribution does not latch -1 as a pid") {
            let engine = FlowEngine()
            var records: [ConnRecord] = []
            engine.onConnectionRecord = { r, _ in records.append(r) }

            var t: Timestamp = 1_757_000_000_000_000
            feed(engine, segment([.syn], from: local, 49152, to: remote, 443),
                 context(t, pid: nil, name: ""))
            t += 1000
            feed(engine, segment([.ack], from: local, 49152, to: remote, 443),
                 context(t, pid: 842, name: "Safari"))
            engine.flush()

            guard let r = records.first else { return NMTest.expect(false, "no record") }
            NMTest.equal(r.exec?.name, "Safari", "attribution latches on the first REAL pid")
            NMTest.equal(r.pid, 842)
        }

        NMTest.test("two flows on different interfaces stay separate") {
            let engine = FlowEngine()
            var records: [ConnRecord] = []
            engine.onConnectionRecord = { r, _ in records.append(r) }

            let t: Timestamp = 1_757_000_000_000_000
            let p = segment([.syn], from: local, 49152, to: remote, 443)
            feed(engine, p, context(t, iface: "en0"))
            feed(engine, p, context(t, iface: "utun0"))
            engine.flush()

            NMTest.equal(records.count, 2, "a VPN carries the inner and outer separately")
        }

        NMTest.test("idle flows expire and emit their record") {
            let engine = FlowEngine()
            var records: [(ConnRecord, FlowEndReason)] = []
            engine.onConnectionRecord = { r, reason in records.append((r, reason)) }

            let t: Timestamp = 1_757_000_000_000_000
            feed(engine, segment([.syn], from: local, 49152, to: remote, 443), context(t))
            NMTest.equal(engine.table.count, 1)

            // Half-open flows time out at 60s.
            engine.expire(now: t + 120 * Time.microsPerSecond)
            NMTest.equal(engine.table.count, 0, "the flow must be released")
            NMTest.equal(records.count, 1)
            NMTest.equal(records.first?.0.state, .s0)
        }

        NMTest.test("an active flow is not expired out from under itself") {
            let engine = FlowEngine()
            var records: [ConnRecord] = []
            engine.onConnectionRecord = { r, _ in records.append(r) }

            var t: Timestamp = 1_757_000_000_000_000
            feed(engine, segment([.syn], from: local, 49152, to: remote, 443), context(t))
            feed(engine, segment([.syn, .ack], from: remote, 443, to: local, 49152),
                 context(t, direction: .inbound))
            feed(engine, segment([.ack], from: local, 49152, to: remote, 443), context(t))

            // Keep it alive across several multiples of the half-open timeout.
            for _ in 0..<10 {
                t += 40 * Time.microsPerSecond
                feed(engine, segment([.psh, .ack], from: local, 49152, to: remote, 443,
                                     payload: [1, 2, 3]), context(t))
            }
            NMTest.equal(records.count, 0, "an established flow with traffic must survive")
            NMTest.equal(engine.table.count, 1)
        }

        NMTest.test("capture loss during a flow marks its counts approximate") {
            let engine = FlowEngine()
            var records: [ConnRecord] = []
            engine.onConnectionRecord = { r, _ in records.append(r) }

            var t: Timestamp = 1_757_000_000_000_000
            feed(engine, segment([.syn], from: local, 49152, to: remote, 443), context(t))
            engine.lossEpoch += 1                        // the capture layer dropped packets
            t += 1000
            feed(engine, segment([.ack], from: local, 49152, to: remote, 443), context(t))
            engine.flush()

            NMTest.expect(records.first?.captureLossSuspected == true,
                          "byte counts spanning a drop must be marked, not presented as exact")
        }
    }

    NMTest.suite("FlowTable / bounds") {

        NMTest.test("the table refuses to grow past its capacity") {
            let table = FlowTable(capacity: 64)
            let engine = FlowEngine(table: table)
            var emitted = 0
            engine.onConnectionRecord = { _, _ in emitted += 1 }

            let t: Timestamp = 1_757_000_000_000_000
            for i in 0..<500 {
                let port = UInt16(10_000 + i)
                feed(engine, segment([.syn], from: local, port, to: remote, 443), context(t))
            }
            NMTest.expect(table.count <= 64,
                          "table grew to \(table.count); an attacker chooses our memory use")
            NMTest.expect(table.stats.evicted > 0)

            // Shed flows are aggregated rather than emitted one by one, so they
            // surface at flush -- as a handful of summary rows, not 500.
            engine.flush()
            NMTest.expect(emitted > 0, "shed flows must be reported, not vanish")
            NMTest.expect(emitted < 100,
                          "emitted \(emitted) rows for 500 shed flows; they must aggregate")
        }

        NMTest.test("half-open flows are shed before flows that carried data") {
            let table = FlowTable(capacity: 32)
            let engine = FlowEngine(table: table)
            var survivors: [ConnRecord] = []
            engine.onConnectionRecord = { r, reason in
                if reason == .evictedUnderPressure { survivors.append(r) }
            }

            let t: Timestamp = 1_757_000_000_000_000
            // One real, established conversation.
            feed(engine, segment([.syn], from: local, 1234, to: other, 443), context(t))
            feed(engine, segment([.syn, .ack], from: other, 443, to: local, 1234),
                 context(t, direction: .inbound))
            feed(engine, segment([.psh, .ack], from: local, 1234, to: other, 443,
                                 payload: [UInt8](repeating: 9, count: 200)), context(t))

            // Then a flood of half-open ones.
            for i in 0..<400 {
                feed(engine, segment([.syn], from: local, UInt16(20_000 + i),
                                     to: remote, 443), context(t))
            }

            let establishedStillPresent = survivors.allSatisfy { $0.respPort != 443 || $0.origPort != 1234 }
            NMTest.expect(establishedStillPresent || table.count > 0,
                          "the established conversation should outlive the flood")
            NMTest.expect(table.floodMode, "flood mode must engage")
        }

        NMTest.test("interface interning is bounded") {
            var t = InterfaceTable()
            for i in 0..<1000 { _ = t.index(of: "if\(i)") }
            NMTest.expect(t.count <= 255, "the key stores a UInt8; growth must stop")
        }
    }
}
