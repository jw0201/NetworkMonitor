//
//  DemoDaemon.swift
//
//  A daemon running inside the app, for when none is installed.
//
//  This exists so the app is demonstrable and developable without root and
//  without the installer -- the same reason SyntheticSource exists for the
//  storage layer. It uses the REAL DaemonServer and DaemonClient over an
//  anonymous XPC listener, so the app's data path is genuinely the production
//  one: encode, push across the boundary, decode. A demo that bypassed the
//  transport would prove nothing about it.
//
//  The traffic it invents is shaped rather than uniform: a few heavy talkers,
//  a long tail of system daemons, delegated traffic, and occasional capture
//  loss -- because a UI built against tidy data is a UI that breaks the first
//  time it meets real data.
//

import Foundation
import NMCore
import NMIPC

final class DemoDaemon: @unchecked Sendable {

    private let listener = NSXPCListener.anonymous()
    private let backend = DemoBackend()
    private var server: DaemonServer?
    private var thread: Thread?
    private var stopped = false

    init() {
        let server = DaemonServer(listener: listener, backend: backend)
        server.allowGroupMembershipFallback = true
        server.start()
        self.server = server
        startGenerating()
    }

    func makeClient() -> DaemonClient {
        DaemonClient(target: .endpoint(listener.endpoint))
    }

    func stop() {
        stopped = true
        server?.stop()
    }

    private func startGenerating() {
        let thread = Thread { [weak self] in
            guard let self else { return }
            while !self.stopped {
                self.backend.tick()
                Thread.sleep(forTimeInterval: 0.25)
            }
        }
        thread.name = "nm.demo"
        thread.qualityOfService = .utility
        thread.start()
        self.thread = thread
    }
}

private final class DemoBackend: DaemonBackend, @unchecked Sendable {

    private let ring = LiveRing()
    private let lock = NSLock()
    private var random = SplitMix64(seed: 0x0B57_ACE5)
    private var config = SystemConfig()
    private var capturing = true
    private let startedAt = Timestamp(Date().timeIntervalSince1970 * 1_000_000)

    private var nextUID: UInt64 = 1
    private var open: [UInt64: LiveFlow] = [:]
    private var packets: Int64 = 0
    private var dropped: Int64 = 0

    private struct Actor {
        let name: String
        let weight: Int
        let hosts: [String]
        let port: UInt16
        let scale: Int64
        let proxy: String?
    }

    private let actors: [Actor] = [
        Actor(name: "Safari", weight: 30,
              hosts: ["www.apple.com", "news.ycombinator.com", "github.com",
                      "static.cloudfront.net"], port: 443, scale: 140_000, proxy: nil),
        Actor(name: "Slack", weight: 16,
              hosts: ["edgeapi.slack.com", "files.slack.com"], port: 443,
              scale: 60_000, proxy: nil),
        Actor(name: "Spotify", weight: 14,
              hosts: ["audio-fa.scdn.co", "gew1-spclient.spotify.com"], port: 443,
              scale: 320_000, proxy: nil),
        Actor(name: "Mail", weight: 8, hosts: ["imap.mail.me.com"], port: 993,
              scale: 30_000, proxy: "nsurlsessiond"),
        Actor(name: "mDNSResponder", weight: 18,
              hosts: ["_airplay._tcp.local", "_companion-link._tcp.local"],
              port: 5353, scale: 600, proxy: nil),
        Actor(name: "trustd", weight: 6, hosts: ["ocsp.apple.com"], port: 80,
              scale: 2_000, proxy: nil),
    ]

    private lazy var weighted: [Int] = {
        var out: [Int] = []
        for (index, actor) in actors.enumerated() {
            out.append(contentsOf: Array(repeating: index, count: actor.weight))
        }
        return out
    }()

    func tick() {
        lock.lock()
        defer { lock.unlock() }

        let now = Timestamp(Date().timeIntervalSince1970 * 1_000_000)

        // Open a few flows.
        for _ in 0..<Int(random.next() % 4 + 1) {
            let actor = actors[weighted[Int(random.next() % UInt64(weighted.count))]]
            let host = actor.hosts[Int(random.next() % UInt64(actor.hosts.count))]
            let uid = nextUID
            nextUID += 1

            let flow = LiveFlow(uid: uid, startedAt: now,
                                proto: actor.port == 5353 ? 17 : 6,
                                localAddress: "192.168.0.31",
                                localPort: UInt16(49152 + random.next() % 15000),
                                remoteAddress: randomPublicAddress(),
                                remotePort: actor.port,
                                hostname: host,
                                hostnameSource: HostnameSource.dnsPerProcess.rawValue,
                                service: actor.port == 443 ? "ssl"
                                    : (actor.port == 5353 ? "dns" : "http"),
                                processName: actor.name,
                                proxyName: actor.proxy,
                                bytesOut: 0, bytesIn: 0, state: "S1")
            open[uid] = flow
            ring.openFlow(flow)
        }

        // Move some bytes.
        var totalIn: Int64 = 0
        var totalOut: Int64 = 0
        for (uid, var flow) in open {
            let actor = actors.first { $0.name == flow.processName } ?? actors[0]
            let out = Int64(random.next() % UInt64(max(1, actor.scale / 40)))
            let inbound = Int64(random.next() % UInt64(max(1, actor.scale / 8)))
            flow.bytesOut += out
            flow.bytesIn += inbound
            open[uid] = flow
            totalOut += out
            totalIn += inbound
            ring.updateFlow(uid: uid, bytesOut: flow.bytesOut, bytesIn: flow.bytesIn,
                            state: flow.state)
        }

        packets += Int64(open.count)
        ring.record(now: now, bytesIn: totalIn, bytesOut: totalOut,
                    packetsIn: Int64(open.count), packetsOut: Int64(open.count))

        // Close some.
        for (uid, _) in open where random.next() % 20 == 0 {
            open.removeValue(forKey: uid)
            ring.closeFlow(uid: uid)
        }

        // Occasional capture loss, so the UI's "approximate" and degraded-health
        // paths are exercised in development rather than discovered in the field.
        if random.next() % 400 == 0 {
            dropped += Int64(random.next() % 500 + 1)
            ring.noteLoss()
        }

        ring.setHealth(CaptureHealthAssessor.assess(
            packetsReceived: packets, kernelDropped: dropped, ringDropped: 0,
            decodeFailures: 0, flowsShed: 0, bpfBufferBytes: 16 << 20))

        // Per-process totals from the open flows, matching what the real
        // backend does.
        var totals: [String: ProcessTraffic] = [:]
        for flow in open.values {
            let key = flow.processName ?? "(unattributed)"
            var entry = totals[key] ?? ProcessTraffic(
                execID: Int64(key.hashValue & 0x7FFF_FFFF), name: key,
                bytesIn: 0, bytesOut: 0, flows: 0, viaProxy: flow.proxyName)
            entry.bytesIn += flow.bytesIn
            entry.bytesOut += flow.bytesOut
            entry.flows += 1
            totals[key] = entry
        }
        ring.setProcessTotals(totals.values.sorted { $0.totalBytes > $1.totalBytes })
    }

    private func randomPublicAddress() -> String {
        var a = UInt32(random.next() % 223) + 1
        while a == 10 || a == 127 || a == 172 || a == 192 || a == 169 {
            a = UInt32(random.next() % 223) + 1
        }
        return "\(a).\(random.next() % 256).\(random.next() % 256).\(random.next() % 254 + 1)"
    }

    // MARK: DaemonBackend

    func currentStatus(callerUID: uid_t) -> DaemonStatus {
        lock.lock(); defer { lock.unlock() }
        return DaemonStatus(version: "demo", startedAt: startedAt, capturing: capturing,
                            interfaces: ["demo"], snaplen: 2048,
                            bpfBufferBytes: 16 << 20,
                            health: ring.snapshot(now: startedAt, backfillSeconds: 1).health,
                            callerCanReadStore: false,
                            databaseDirectory: "(none — demo mode)")
    }

    func currentConfiguration() -> SystemConfig {
        lock.lock(); defer { lock.unlock() }
        return config
    }

    func snapshot(backfillSeconds: Int) -> LiveSnapshot {
        lock.lock(); defer { lock.unlock() }
        return ring.snapshot(now: Timestamp(Date().timeIntervalSince1970 * 1_000_000),
                             backfillSeconds: backfillSeconds)
    }

    func applyConfiguration(_ newConfig: SystemConfig) -> DaemonError? {
        lock.lock(); config = newConfig; lock.unlock()
        return nil
    }

    func setCaptureEnabled(_ enabled: Bool) -> DaemonError? {
        lock.lock(); capturing = enabled; lock.unlock()
        return nil
    }

    func runRetentionNow() -> DaemonError? { nil }
    func rotateNow() -> DaemonError? { nil }
}
