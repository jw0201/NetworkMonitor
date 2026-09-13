//
//  StreamBufferTests.swift
//
//  The cases that matter are the ones where a stream is not a clean sequence of
//  in-order segments: retransmissions, overlaps, holes, and sequence wrap.
//  Getting any of them wrong produces a spliced stream that parses into
//  plausible nonsense rather than failing visibly.
//

import NMCore
import NMFlow
import NMTestKit

private func offer(_ pool: ReassemblyPool, slot: Int32 = 1, fromOriginator: Bool = true,
                   seq: UInt32, _ bytes: [UInt8]) -> StreamDirection.Outcome {
    bytes.withUnsafeBytes { pool.accept(slot: slot, fromOriginator: fromOriginator,
                                        sequence: seq, payload: $0) }
}

private func contents(_ pool: ReassemblyPool, slot: Int32 = 1,
                      fromOriginator: Bool = true) -> [UInt8] {
    pool.direction(slot: slot, fromOriginator: fromOriginator)?.bytes ?? []
}

func runStreamBufferTests() {
    NMTest.suite("ReassemblyPool / in-order") {

        NMTest.test("contiguous segments concatenate") {
            let pool = ReassemblyPool()
            _ = offer(pool, seq: 1000, [1, 2, 3])
            _ = offer(pool, seq: 1003, [4, 5, 6])
            _ = offer(pool, seq: 1006, [7, 8])
            NMTest.equal(contents(pool), [1, 2, 3, 4, 5, 6, 7, 8])
            NMTest.expect(pool.direction(slot: 1, fromOriginator: true)?.hasGap == false)
        }

        NMTest.test("the two directions are independent") {
            let pool = ReassemblyPool()
            _ = offer(pool, fromOriginator: true, seq: 100, [0xAA, 0xBB])
            _ = offer(pool, fromOriginator: false, seq: 500, [0xCC])
            NMTest.equal(contents(pool, fromOriginator: true), [0xAA, 0xBB])
            NMTest.equal(contents(pool, fromOriginator: false), [0xCC])
        }

        NMTest.test("an empty segment is ignored rather than resetting state") {
            let pool = ReassemblyPool()
            _ = offer(pool, seq: 100, [1, 2])
            NMTest.equal(offer(pool, seq: 102, []), .ignored)
            NMTest.equal(contents(pool), [1, 2])
        }
    }

    NMTest.suite("ReassemblyPool / retransmission and overlap") {

        NMTest.test("an exact retransmission adds nothing") {
            let pool = ReassemblyPool()
            _ = offer(pool, seq: 1000, [1, 2, 3, 4])
            NMTest.equal(offer(pool, seq: 1000, [1, 2, 3, 4]), .duplicate)
            NMTest.equal(contents(pool), [1, 2, 3, 4])
        }

        // First-seen bytes win. That is what macOS itself does, so our view of
        // the stream matches the endpoint's -- the divergence between the two
        // is precisely what TCP evasion attacks exploit.
        NMTest.test("an overlapping segment keeps the bytes seen first") {
            let pool = ReassemblyPool()
            _ = offer(pool, seq: 1000, [0x41, 0x41, 0x41, 0x41])
            // Overlaps the last two bytes with different content, plus two new.
            _ = offer(pool, seq: 1002, [0xFF, 0xFF, 0x42, 0x42])
            NMTest.equal(contents(pool), [0x41, 0x41, 0x41, 0x41, 0x42, 0x42],
                         "the rewrite of bytes 1002-1003 must not take effect")
        }

        NMTest.test("a segment entirely behind the cursor is a duplicate") {
            let pool = ReassemblyPool()
            _ = offer(pool, seq: 1000, [1, 2, 3, 4, 5, 6])
            NMTest.equal(offer(pool, seq: 1001, [2, 3]), .duplicate)
            NMTest.equal(contents(pool).count, 6)
        }
    }

    NMTest.suite("ReassemblyPool / gaps") {

        // A spliced stream parses into plausible nonsense. Stopping visibly is
        // the only honest option, and it is what lets missed_bytes be real.
        NMTest.test("a hole stops buffering and reports the missing count") {
            let pool = ReassemblyPool()
            _ = offer(pool, seq: 1000, [1, 2, 3])
            NMTest.equal(offer(pool, seq: 1503, [9, 9, 9]), .gap(missing: 500))
            NMTest.equal(contents(pool), [1, 2, 3], "nothing past the hole is kept")
            NMTest.expect(pool.direction(slot: 1, fromOriginator: true)?.hasGap == true)
            NMTest.equal(pool.direction(slot: 1, fromOriginator: true)?.missedBytes, 500)
        }

        NMTest.test("segments arriving after a gap are ignored, not spliced") {
            let pool = ReassemblyPool()
            _ = offer(pool, seq: 1000, [1, 2, 3])
            _ = offer(pool, seq: 2000, [4, 5])
            NMTest.equal(offer(pool, seq: 2002, [6, 7]), .ignored)
            NMTest.equal(contents(pool), [1, 2, 3])
        }

        NMTest.test("a gap in one direction does not affect the other") {
            let pool = ReassemblyPool()
            _ = offer(pool, fromOriginator: true, seq: 100, [1])
            _ = offer(pool, fromOriginator: true, seq: 999, [2])
            _ = offer(pool, fromOriginator: false, seq: 500, [3, 4])
            NMTest.expect(pool.direction(slot: 1, fromOriginator: true)?.hasGap == true)
            NMTest.expect(pool.direction(slot: 1, fromOriginator: false)?.hasGap == false)
            NMTest.equal(contents(pool, fromOriginator: false), [3, 4])
        }
    }

    NMTest.suite("ReassemblyPool / bounds") {

        // Sequence numbers wrap at 2^32, which any long-lived transfer reaches.
        // Comparing with < or > rather than a signed difference turns the wrap
        // into a 4 GB phantom gap.
        NMTest.test("a sequence number wrap is continuity, not a 4GB hole") {
            let pool = ReassemblyPool()
            _ = offer(pool, seq: 0xFFFF_FFFE, [1, 2])
            let outcome = offer(pool, seq: 0x0000_0000, [3, 4])
            NMTest.equal(outcome, .appended(2), "wrap must read as contiguous")
            NMTest.equal(contents(pool), [1, 2, 3, 4])
        }

        NMTest.test("the per-direction buffer is capped") {
            let pool = ReassemblyPool(capacity: 16, bytesPerDirection: 64)
            var seq: UInt32 = 1000
            for _ in 0..<20 {
                _ = offer(pool, seq: seq, [UInt8](repeating: 0x41, count: 32))
                seq &+= 32
            }
            NMTest.equal(contents(pool).count, 64, "stops at the limit")
            NMTest.expect(pool.direction(slot: 1, fromOriginator: true)?.full == true)
        }

        NMTest.test("the pool refuses new flows past its capacity") {
            let pool = ReassemblyPool(capacity: 8, bytesPerDirection: 64)
            for slot in 0..<100 {
                _ = offer(pool, slot: Int32(slot), seq: 1000, [1, 2, 3])
            }
            NMTest.expect(pool.count <= 8, "pool grew to \(pool.count)")
            NMTest.expect(pool.refusedForCapacity > 0)
        }

        NMTest.test("releasing a slot frees its capacity for another flow") {
            let pool = ReassemblyPool(capacity: 2, bytesPerDirection: 64)
            _ = offer(pool, slot: 1, seq: 100, [1])
            _ = offer(pool, slot: 2, seq: 100, [2])
            _ = offer(pool, slot: 3, seq: 100, [3])
            NMTest.equal(pool.count, 2)

            pool.release(slot: 1)
            _ = offer(pool, slot: 3, seq: 100, [3])
            NMTest.equal(pool.count, 2)
            NMTest.equal(contents(pool, slot: 3), [3], "the new flow got a buffer")
        }
    }

    NMTest.suite("ReassemblyPool / through the engine") {

        // The reason this exists: a ClientHello routinely spans two or three
        // segments, and an analyzer handed a fragment reports every handshake
        // as malformed.
        NMTest.test("a payload split across segments is seen whole by an analyzer") {
            final class Recorder: PacketAnalyzer {
                let identifier = "recorder"
                var triggers: [AnalyzerTrigger] {
                    [.port(proto: TransportParser.tcp, port: 9999)]
                }
                var lastSeen: [UInt8] = []
                var calls = 0
                var sawStream = false
                func analyze(_ context: AnalyzerContext, payload: ByteReader,
                             emit: (AnalyzerOutput) -> Void) -> AnalyzerVerdict {
                    calls += 1
                    sawStream = context.isStream
                    var r = payload
                    lastSeen = (try? r.bytes(r.remaining)).map(Array.init) ?? []
                    return .wantMore
                }
            }

            let engine = FlowEngine()
            let recorder = Recorder()
            engine.analyzers.register(recorder)

            let client = IPAddress("192.168.0.31")!
            let server = IPAddress("10.0.0.5")!
            var t: Timestamp = 1_757_000_000_000_000

            func send(_ payload: [UInt8], seq: UInt32) {
                let p = PacketFixture.ipv4TCP(.init(
                    source: client, sourcePort: 40000, destination: server,
                    destinationPort: 9999, flags: [.psh, .ack],
                    sequence: seq, payload: payload))
                let context = PacketContext(timestamp: t, interfaceName: "en0",
                                            interfaceType: 0x06, direction: .outbound,
                                            pid: 501, processName: "test")
                p.withUnsafeBytes { buf in
                    guard var r = ByteReader(buf) else { return }
                    engine.process(context, l3: &r)
                }
                t += 1000
            }

            send([0x16, 0x03, 0x01], seq: 1000)
            send([0x02, 0x00], seq: 1003)
            send([0xAA, 0xBB], seq: 1005)

            NMTest.expect(recorder.sawStream, "TCP analyzers must be told it is a stream")
            NMTest.equal(recorder.lastSeen, [0x16, 0x03, 0x01, 0x02, 0x00, 0xAA, 0xBB],
                         "the analyzer must see the whole prefix, not the last segment")
            NMTest.equal(recorder.calls, 3)
        }
    }
}
