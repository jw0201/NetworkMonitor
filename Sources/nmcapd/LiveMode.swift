//
//  LiveMode.swift
//
//  `nmcapd --live [seconds]` -- the live pipeline end to end, rendered.
//
//  Server and client run in one process over an anonymous XPC listener. That is
//  not a shortcut around the real path: snapshots are genuinely encoded, sent
//  across the XPC boundary and decoded, so the wire format, the push cadence,
//  the subscription lifecycle and the payload size are all exercised. The only
//  thing it does not cover is the launchd-registered Mach service name, which
//  needs the install script.
//
//  Without root it drives the pipeline from synthetic traffic; with root it
//  captures for real. Both take exactly the same path from PacketContext
//  onwards.
//

import Darwin
import Foundation
import NMCapture
import NMCore
import NMFlow
import NMIPC
import NMSource
import NMStore

func runLiveMode(seconds: Double, useCapture: Bool) async -> Int32 {
    let root = NSTemporaryDirectory() + "nm-live-\(getpid())"
    defer { try? FileManager.default.removeItem(atPath: root) }
    let paths = Paths.temporary(root)
    try? FileManager.default.createDirectory(atPath: paths.databaseDirectory,
                                             withIntermediateDirectories: true)

    let backend = LiveBackend(paths: paths)
    let listener = NSXPCListener.anonymous()
    let server = DaemonServer(listener: listener, backend: backend)
    server.allowGroupMembershipFallback = true
    server.start()
    defer { server.stop() }

    let client = DaemonClient(target: .endpoint(listener.endpoint))

    print("""
    NetworkMonitor live
    ===================
    source     \(useCapture ? "live capture (pktap,all)" : "synthetic traffic")
    transport  anonymous XPC endpoint (the real encode/push/decode path)
    duration   \(Int(seconds))s

    """)

    let status = try? await client.status()
    if let status {
        print("daemon     \(status.version), capture \(status.capturing ? "on" : "off")")
        print("store      \(status.databaseDirectory)")
        print("direct DB read allowed for this user: \(status.callerCanReadStore)\n")
    }

    // Feed the engine.
    let stopFlag = StopFlag()
    if useCapture {
        guard startCapture(backend: backend, stop: stopFlag) else { return 1 }
    } else {
        startSynthetic(backend: backend, stop: stopFlag)
    }

    // Subscribe and render.
    let stream = await client.snapshots()
    await client.subscribe(backfillSeconds: 120, hertz: 2)

    let deadline = Date().addingTimeInterval(seconds)
    var renders = 0

    let renderTask = Task {
        for await snapshot in stream {
            render(snapshot, renders: renders)
            renders += 1
            if Date() >= deadline { break }
        }
    }

    while Date() < deadline && !Task.isCancelled {
        try? await Task.sleep(nanoseconds: 200_000_000)
    }
    renderTask.cancel()
    stopFlag.stop()
    await client.stop()

    print("""

    XPC
    \(String(repeating: "-", count: 78))
      snapshots pushed   \(server.stats.snapshotsPushed)
      connections        \(server.stats.connectionsAccepted)
      auth denied        \(server.stats.authorizationsDenied)
    """)
    return 0
}

// MARK: - Sources

private final class StopFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var stopped = false
    func stop() { lock.lock(); stopped = true; lock.unlock() }
    var isStopped: Bool { lock.lock(); defer { lock.unlock() }; return stopped }
}

private func startSynthetic(backend: LiveBackend, stop: StopFlag) {
    var config = SyntheticSource.Config()
    config.connsPerMinute = 6_000
    config.realTime = true
    let source = SyntheticSource(config: config)

    let thread = Thread {
        let client = IPAddress("192.168.0.31")!
        var sequence: UInt32 = 1000
        while !stop.isStopped {
            let now = Timestamp(Date().timeIntervalSince1970 * 1_000_000)
            let batch = source.generate(connCount: 12)

            // Turn the synthetic records back into packets so the whole flow
            // path runs, rather than injecting records at the far end and
            // testing nothing between here and there.
            for conn in batch.conns {
                let packet = PacketFixture.ipv4TCP(.init(
                    source: client, sourcePort: conn.origPort,
                    destination: conn.respAddr, destinationPort: conn.respPort,
                    flags: [.psh, .ack], sequence: sequence,
                    payload: [UInt8](repeating: 0x41, count: 512)))
                sequence &+= 512

                let context = PacketContext(timestamp: now, interfaceName: conn.iface,
                                            interfaceType: 0x06, direction: .outbound,
                                            pid: conn.pid,
                                            processName: conn.exec?.name ?? "")
                packet.withUnsafeBytes { buffer in
                    guard var reader = ByteReader(buffer) else { return }
                    backend.engine.process(context, l3: &reader)
                }
                backend.observe(context: context, l3Bytes: packet.count, fromOriginator: true)
            }
            Thread.sleep(forTimeInterval: 0.05)
        }
    }
    thread.name = "nm.live.synthetic"
    thread.start()
}

private func startCapture(backend: LiveBackend, stop: StopFlag) -> Bool {
    let session = CaptureSession()
    do {
        try session.open()
    } catch {
        print("capture failed: \(error)")
        if case CaptureError.notRoot = error {
            print("""

            Run in a Terminal window, or drop --capture to drive the same
            pipeline from synthetic traffic:
                sudo .build/release/nmcapd --live 20 --capture
            """)
        }
        return false
    }
    print("capture    \(session.bpfCeiling.explanation)\n")

    let thread = Thread {
        while !stop.isStopped {
            _ = session.drain(count: 256) { meta, record, timestamp in
                var l3 = (try? record.reader(at: meta.l3Offset,
                                             count: record.count - meta.l3Offset))
                guard l3 != nil else { return }
                let context = makeContext(meta, timestamp: timestamp,
                                          lossEpoch: backend.engine.lossEpoch)
                backend.engine.process(context, l3: &l3!)
                backend.observe(context: context,
                                l3Bytes: record.count - meta.l3Offset,
                                fromOriginator: context.direction == .outbound)
            }
            if let stats = session.stats() {
                backend.noteCaptureStats(received: Int64(stats.received),
                                         kernelDropped: Int64(stats.kernelDropped),
                                         bufferBytes: session.bpfCeiling.after)
            }
        }
        session.close()
    }
    thread.name = "nm.live.capture"
    thread.qualityOfService = .userInitiated
    thread.start()
    return true
}

// MARK: - Rendering

private func render(_ snapshot: LiveSnapshot, renders: Int) {
    // Redraw in place after the first frame, so this reads like a live view
    // rather than a scrolling log.
    if renders > 0 { print("\u{001B}[2J\u{001B}[H", terminator: "") }

    let recent = snapshot.samples.suffix(60)
    let inRate = recent.last?.bytesIn ?? 0
    let outRate = recent.last?.bytesOut ?? 0

    print("NetworkMonitor live    \(shortTimeOf(snapshot.generatedAt))"
          + "    \(healthLabel(snapshot.health))")
    print(String(repeating: "=", count: 78))
    print("  down \(pad(rate(inRate), 14))  up \(pad(rate(outRate), 14))"
          + "  flows \(snapshot.flows.count)")
    print("  " + sparkline(recent.map { $0.totalBytes }))
    if !snapshot.health.explanation.isEmpty && snapshot.health.level != .healthy {
        print("  \(snapshot.health.explanation)")
    }

    if !snapshot.topProcesses.isEmpty {
        print("\n  Top processes")
        print("  " + String(repeating: "-", count: 74))
        for process in snapshot.topProcesses.prefix(6) {
            var label = process.name
            if let proxy = process.viaProxy { label += " (via \(proxy))" }
            print("  " + pad(label, 30) + pad(bytes(process.totalBytes), 12)
                  + String(repeating: "#", count: min(30, Int(process.totalBytes / 20000))))
        }
    }

    if !snapshot.flows.isEmpty {
        print("\n  Open connections")
        print("  " + String(repeating: "-", count: 74))
        for flow in snapshot.flows.prefix(8) {
            let remote = flow.hostname ?? flow.remoteAddress
            print("  " + pad(flow.processName ?? "-", 18)
                  + pad("\(remote):\(flow.remotePort)", 34)
                  + pad(flow.state, 6)
                  + bytes(flow.bytesIn + flow.bytesOut))
        }
    }
}

private func healthLabel(_ health: CaptureHealth) -> String {
    switch health.level {
    case .healthy: return "capture OK"
    case .degraded: return "DEGRADED (\(health.totalDropped) dropped)"
    case .failing: return "FAILING (\(health.totalDropped) dropped)"
    }
}

private func sparkline(_ values: [Int64]) -> String {
    guard let maximum = values.max(), maximum > 0 else {
        return String(repeating: "_", count: values.count)
    }
    let blocks = Array("_▁▂▃▄▅▆▇█")
    return String(values.map { value in
        let index = Int(Double(value) / Double(maximum) * Double(blocks.count - 1))
        return blocks[min(max(index, 0), blocks.count - 1)]
    })
}

private func rate(_ bytesPerSecond: Int64) -> String {
    bytes(bytesPerSecond) + "/s"
}

private func bytes(_ n: Int64) -> String {
    if n < 1024 { return "\(n) B" }
    if n < 1024 * 1024 { return String(format: "%.1f KB", Double(n) / 1024) }
    return String(format: "%.1f MB", Double(n) / 1_048_576)
}

private func pad(_ s: String, _ width: Int) -> String {
    s.count >= width ? String(s.prefix(width - 1)) + " "
                     : s + String(repeating: " ", count: width - s.count)
}

private func shortTimeOf(_ ts: Timestamp) -> String {
    let seconds = ts / 1_000_000
    let h = (seconds % 86400) / 3600, m = (seconds % 3600) / 60, s = seconds % 60
    func p(_ n: Int64) -> String { n < 10 ? "0\(n)" : "\(n)" }
    return "\(p(h)):\(p(m)):\(p(s))"
}
