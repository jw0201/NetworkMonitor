//
//  IPCTests.swift
//
//  The XPC layer is tested over an ANONYMOUS listener, which needs neither root
//  nor a registered Mach service, so the whole request/reply/push path runs
//  in-process. The only thing that cannot be exercised this way is the
//  launchd-registered service name itself.
//

import Foundation
import NMCore
import NMIPC
import NMTestKit

private let base: Timestamp = 1_757_000_000_000_000

// MARK: - Backend double

private final class MockBackend: DaemonBackend, @unchecked Sendable {
    var config = SystemConfig()
    var capturing = true
    var ring = LiveRing(historySeconds: 60, maximumFlows: 8, maximumProcesses: 4)

    var applyCalls = 0
    var retentionCalls = 0
    var rotateCalls = 0
    var rejectNextApply: DaemonError?

    func currentStatus(callerUID: uid_t) -> DaemonStatus {
        DaemonStatus(version: "test", startedAt: base, capturing: capturing,
                     interfaces: ["en0"], snaplen: 2048,
                     callerCanReadStore: false, databaseDirectory: "/tmp")
    }

    func currentConfiguration() -> SystemConfig { config }

    func snapshot(backfillSeconds: Int) -> LiveSnapshot {
        ring.snapshot(now: Timestamp(Date().timeIntervalSince1970 * 1_000_000),
                      backfillSeconds: backfillSeconds)
    }

    func applyConfiguration(_ config: SystemConfig) -> DaemonError? {
        applyCalls += 1
        if let error = rejectNextApply { rejectNextApply = nil; return error }
        self.config = config
        return nil
    }

    func setCaptureEnabled(_ enabled: Bool) -> DaemonError? {
        capturing = enabled
        return nil
    }

    func runRetentionNow() -> DaemonError? { retentionCalls += 1; return nil }
    func rotateNow() -> DaemonError? { rotateCalls += 1; return nil }
}

private func makePair(allowFallback: Bool = true) -> (DaemonServer, DaemonClient, MockBackend) {
    let backend = MockBackend()
    let listener = NSXPCListener.anonymous()
    let server = DaemonServer(listener: listener, backend: backend)
    server.allowGroupMembershipFallback = allowFallback
    server.start()
    let client = DaemonClient(target: .endpoint(listener.endpoint))
    return (server, client, backend)
}

func runIPCTests() async {

    NMTest.suite("LiveRing / sampling") {

        NMTest.test("per-second buckets accumulate and roll over") {
            let ring = LiveRing(historySeconds: 60)
            ring.record(now: base, bytesIn: 100, bytesOut: 50, packetsIn: 1, packetsOut: 1)
            ring.record(now: base + 500_000, bytesIn: 100, bytesOut: 50)
            ring.record(now: base + Time.microsPerSecond, bytesIn: 7)

            let snapshot = ring.snapshot(now: base + Time.microsPerSecond, backfillSeconds: 60)
            NMTest.equal(snapshot.samples.count, 2)
            NMTest.equal(snapshot.samples[0].bytesIn, 200, "same second accumulates")
            NMTest.equal(snapshot.samples[0].bytesOut, 100)
            NMTest.equal(snapshot.samples[1].bytesIn, 7, "the next second is its own bucket")
        }

        // A chart that interpolates across a gap implies traffic that did not
        // happen. Idle seconds have to be present and zero.
        NMTest.test("an idle gap is filled with zeroes, not skipped") {
            let ring = LiveRing(historySeconds: 60)
            ring.record(now: base, bytesIn: 100)
            ring.record(now: base + 5 * Time.microsPerSecond, bytesIn: 200)

            let snapshot = ring.snapshot(now: base + 5 * Time.microsPerSecond,
                                         backfillSeconds: 60)
            NMTest.equal(snapshot.samples.count, 6, "seconds 0 through 5")
            NMTest.equal(snapshot.samples[1].bytesIn, 0)
            NMTest.equal(snapshot.samples[4].bytesIn, 0)
            NMTest.equal(snapshot.samples[5].bytesIn, 200)
        }

        NMTest.test("the history ring is bounded and keeps the newest") {
            let ring = LiveRing(historySeconds: 10)
            for second in 0..<100 {
                ring.record(now: base + Timestamp(second) * Time.microsPerSecond,
                            bytesIn: Int64(second))
            }
            let snapshot = ring.snapshot(now: base + 99 * Time.microsPerSecond,
                                         backfillSeconds: 1000)
            NMTest.expect(snapshot.samples.count <= 11,
                          "got \(snapshot.samples.count)")
            NMTest.equal(snapshot.samples.last?.bytesIn, 99, "the newest survives")
        }

        NMTest.test("backfill is limited to what was asked for") {
            let ring = LiveRing(historySeconds: 600)
            for second in 0..<300 {
                ring.record(now: base + Timestamp(second) * Time.microsPerSecond, bytesIn: 1)
            }
            let short = ring.snapshot(now: base + 300 * Time.microsPerSecond,
                                      backfillSeconds: 5)
            NMTest.expect(short.samples.count <= 5)
        }
    }

    NMTest.suite("LiveRing / flows") {

        NMTest.test("open flows appear and closed ones disappear") {
            let ring = LiveRing(historySeconds: 60, maximumFlows: 8)
            ring.openFlow(LiveFlow(uid: 1, startedAt: base, proto: 6,
                                   localAddress: "192.168.0.31", localPort: 49152,
                                   remoteAddress: "93.184.216.34", remotePort: 443,
                                   processName: "Safari"))
            NMTest.equal(ring.activeFlowCount, 1)

            ring.updateFlow(uid: 1, bytesOut: 500, bytesIn: 1200, state: "SF",
                            hostname: "example.com")
            let snapshot = ring.snapshot(now: base, backfillSeconds: 10)
            NMTest.equal(snapshot.flows.first?.hostname, "example.com")
            NMTest.equal(snapshot.flows.first?.bytesIn, 1200)

            ring.closeFlow(uid: 1)
            NMTest.equal(ring.activeFlowCount, 0)
        }

        NMTest.test("the flow list is bounded") {
            let ring = LiveRing(historySeconds: 60, maximumFlows: 8)
            for uid in 0..<100 {
                ring.openFlow(LiveFlow(uid: UInt64(uid), startedAt: base, proto: 6,
                                       localAddress: "10.0.0.1", localPort: 1,
                                       remoteAddress: "8.8.8.8", remotePort: 443))
            }
            NMTest.equal(ring.activeFlowCount, 8)
            NMTest.expect(ring.flowsDroppedForCapacity > 0)
        }

        // With a cap on what is sent, the ones that survive truncation should
        // be the ones worth looking at.
        NMTest.test("the busiest flows survive truncation") {
            let ring = LiveRing(historySeconds: 60, maximumFlows: 32)
            for uid in 0..<20 {
                ring.openFlow(LiveFlow(uid: UInt64(uid), startedAt: base, proto: 6,
                                       localAddress: "10.0.0.1", localPort: UInt16(uid),
                                       remoteAddress: "8.8.8.8", remotePort: 443))
                ring.updateFlow(uid: UInt64(uid), bytesOut: Int64(uid) * 1000,
                                bytesIn: 0, state: "S1")
            }
            let snapshot = ring.snapshot(now: base, backfillSeconds: 10, flowLimit: 3)
            NMTest.equal(snapshot.flows.count, 3)
            NMTest.equal(snapshot.flows.first?.bytesOut, 19000)
        }
    }

    NMTest.suite("CaptureHealth") {

        NMTest.test("no drops reads as healthy") {
            let health = CaptureHealthAssessor.assess(packetsReceived: 100_000,
                                                      kernelDropped: 0, ringDropped: 0,
                                                      decodeFailures: 0, flowsShed: 0,
                                                      bpfBufferBytes: 16 << 20)
            NMTest.equal(health.level, .healthy)
        }

        // A tenth of a percent still produces numbers that look reasonable,
        // which is exactly why it has to be surfaced.
        NMTest.test("a small drop rate is degraded, a large one failing") {
            let small = CaptureHealthAssessor.assess(packetsReceived: 1_000_000,
                                                     kernelDropped: 100, ringDropped: 0,
                                                     decodeFailures: 0, flowsShed: 0,
                                                     bpfBufferBytes: 16 << 20)
            NMTest.equal(small.level, .degraded)

            let large = CaptureHealthAssessor.assess(packetsReceived: 1000,
                                                     kernelDropped: 500, ringDropped: 0,
                                                     decodeFailures: 0, flowsShed: 0,
                                                     bpfBufferBytes: 16 << 20)
            NMTest.equal(large.level, .failing)
        }

        // The two drop counters imply different remedies, so they are never
        // merged into one number.
        NMTest.test("the dominant drop source decides the explanation") {
            let kernel = CaptureHealthAssessor.assess(packetsReceived: 1000,
                                                      kernelDropped: 500, ringDropped: 1,
                                                      decodeFailures: 0, flowsShed: 0,
                                                      bpfBufferBytes: 16 << 20)
            NMTest.expect(kernel.explanation.contains("kernel capture buffer"),
                          kernel.explanation)

            let ring = CaptureHealthAssessor.assess(packetsReceived: 1000,
                                                    kernelDropped: 0, ringDropped: 500,
                                                    decodeFailures: 0, flowsShed: 0,
                                                    bpfBufferBytes: 16 << 20)
            NMTest.expect(ring.explanation.contains("Analysis fell behind"), ring.explanation)
        }

        NMTest.test("shed flows are mentioned separately from dropped packets") {
            let health = CaptureHealthAssessor.assess(packetsReceived: 1000,
                                                      kernelDropped: 1, ringDropped: 0,
                                                      decodeFailures: 0, flowsShed: 5000,
                                                      bpfBufferBytes: 16 << 20)
            NMTest.expect(health.explanation.contains("aggregated"), health.explanation)
        }
    }

    NMTest.suite("Wire format") {

        NMTest.test("a snapshot round-trips") {
            var snapshot = LiveSnapshot(generatedAt: base)
            snapshot.samples = [ThroughputSample(second: 1, bytesIn: 10, bytesOut: 20)]
            snapshot.flows = [LiveFlow(uid: 7, startedAt: base, proto: 6,
                                       localAddress: "10.0.0.1", localPort: 1,
                                       remoteAddress: "8.8.8.8", remotePort: 443,
                                       hostname: "dns.google")]
            let data = WireCoder.encode(snapshot)
            guard let back = WireCoder.decode(LiveSnapshot.self, from: data) else {
                return NMTest.expect(false, "decode failed")
            }
            NMTest.equal(back.samples.first?.bytesIn, 10)
            NMTest.equal(back.flows.first?.hostname, "dns.google")
            NMTest.equal(back.wireVersion, 1)
        }

        NMTest.test("a reply carries either a value or an error, never both") {
            let ok = DaemonReply(value: true)
            NMTest.equal(try ok.get(), true)

            let failed = DaemonReply<Bool>(error: .notAuthorized)
            NMTest.throwsError({ _ = try failed.get() }, validate: { error in
                (error as? DaemonError) == .notAuthorized
            })
        }

        NMTest.test("garbage decodes to nil rather than a half-built value") {
            NMTest.expect(WireCoder.decode(LiveSnapshot.self,
                                           from: Data([0xFF, 0x00, 0x42])) == nil)
        }
    }

    await NMTest.suite("XPC / end to end over an anonymous listener") {

        await NMTest.test("status and configuration round-trip across the boundary") {
            let (server, client, backend) = makePair()
            defer { server.stop() }

            backend.config.snaplen = 4096
            let status = try await client.status()
            NMTest.equal(status.version, "test")
            NMTest.expect(status.capturing)
            NMTest.equal(status.interfaces, ["en0"])

            let config = try await client.configuration()
            NMTest.equal(config.snaplen, 4096)
            await client.stop()
        }

        await NMTest.test("a subscription receives a backfilled first snapshot") {
            let (server, client, backend) = makePair()
            defer { server.stop() }

            for second in 0..<30 {
                backend.ring.record(now: base + Timestamp(second) * Time.microsPerSecond,
                                    bytesIn: Int64(second) * 100)
            }

            let stream = await client.snapshots()
            await client.subscribe(backfillSeconds: 60, hertz: 4)

            var received: LiveSnapshot?
            for await snapshot in stream {
                received = snapshot
                break
            }
            NMTest.expect(received != nil, "no snapshot arrived")
            NMTest.expect((received?.samples.count ?? 0) > 1,
                          "the first snapshot must carry history, not one sample")
            await client.stop()
        }

        // A daemon that keeps serialising snapshots for a window nobody is
        // looking at burns battery for nothing.
        await NMTest.test("unsubscribing stops the daemon producing snapshots") {
            let (server, client, _) = makePair()
            defer { server.stop() }

            _ = await client.snapshots()
            await client.subscribe(backfillSeconds: 5, hertz: 4)
            try? await Task.sleep(nanoseconds: 300_000_000)
            NMTest.equal(server.subscriberCount, 1)

            await client.pause()
            try? await Task.sleep(nanoseconds: 300_000_000)
            NMTest.equal(server.subscriberCount, 0, "the daemon must stop pushing")
            await client.stop()
        }

        await NMTest.test("an invalidated connection removes its subscription") {
            let (server, client, _) = makePair()
            defer { server.stop() }

            _ = await client.snapshots()
            await client.subscribe(backfillSeconds: 5, hertz: 4)
            try? await Task.sleep(nanoseconds: 300_000_000)
            NMTest.equal(server.subscriberCount, 1)

            await client.stop()
            try? await Task.sleep(nanoseconds: 500_000_000)
            NMTest.equal(server.subscriberCount, 0,
                         "a client that went away must not be pushed to forever")
        }

        // The check that matters: a request with no authorization is refused by
        // the DAEMON, regardless of what the client believes about itself.
        await NMTest.test("an unauthorized write is refused and changes nothing") {
            let backend = MockBackend()
            let listener = NSXPCListener.anonymous()
            let server = DaemonServer(listener: listener, backend: backend)
            server.allowGroupMembershipFallback = false      // no fallback
            server.start()
            defer { server.stop() }
            let client = DaemonClient(target: .endpoint(listener.endpoint))

            var config = SystemConfig()
            config.payloadCaptureEnabled = true

            do {
                _ = try await client.setConfiguration(config, authorization: Data())
                NMTest.expect(false, "an empty authorization must be refused")
            } catch {
                NMTest.equal(error as? DaemonError, .notAuthorized)
            }
            NMTest.equal(backend.applyCalls, 0,
                         "the backend must not be reached at all")
            NMTest.expect(!backend.config.payloadCaptureEnabled)
            await client.stop()
        }

        await NMTest.test("a wire version mismatch is reported, not silently accepted") {
            let (server, client, backend) = makePair()
            defer { server.stop() }

            // Hand-build a payload claiming a future version.
            var config = SystemConfig()
            config.wireVersion = 999
            do {
                _ = try await client.setConfiguration(config, authorization: Data([1, 2, 3]))
                NMTest.expect(false, "should not succeed")
            } catch {
                // Either refusal is correct; what must not happen is silent
                // acceptance of a payload from an incompatible version.
                let code = error as? DaemonError
                NMTest.expect(code == .wireVersionMismatch || code == .notAuthorized,
                              "got \(String(describing: code))")
            }
            NMTest.equal(backend.config.wireVersion, 1)
            await client.stop()
        }

        await NMTest.test("permissions tell the UI what is locked before it tries") {
            let (server, client, _) = makePair()
            defer { server.stop() }

            let permissions = try await client.permissions()
            if permissions.callerIsAdmin {
                NMTest.expect(permissions.lockedFields.isEmpty)
            } else {
                NMTest.expect(permissions.lockedFields.contains("retention"),
                              "a non-admin must see retention as locked")
            }
            await client.stop()
        }

        await NMTest.test("several clients each receive the stream") {
            let backend = MockBackend()
            let listener = NSXPCListener.anonymous()
            let server = DaemonServer(listener: listener, backend: backend)
            server.start()
            defer { server.stop() }

            let a = DaemonClient(target: .endpoint(listener.endpoint))
            let b = DaemonClient(target: .endpoint(listener.endpoint))
            _ = await a.snapshots()
            _ = await b.snapshots()
            await a.subscribe(backfillSeconds: 5, hertz: 4)
            await b.subscribe(backfillSeconds: 5, hertz: 4)
            try? await Task.sleep(nanoseconds: 300_000_000)

            NMTest.equal(server.subscriberCount, 2,
                         "a menu bar extra and a main window are two subscribers")
            await a.stop()
            await b.stop()
        }
    }
}
