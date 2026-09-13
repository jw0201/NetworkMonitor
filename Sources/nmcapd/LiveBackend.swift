//
//  LiveBackend.swift
//
//  The real DaemonBackend: the flow engine and the store, behind the XPC
//  interface.
//
//  This is where the two halves of the design meet. The engine feeds LiveRing
//  at packet rate; the XPC server reads a snapshot from it a few times a second.
//  Nothing in the engine knows XPC exists, and nothing in the server knows about
//  packets -- the ring is the whole interface between them, which is what keeps
//  the packet path free of anything that could block on a client.
//

import Darwin
import Foundation
import NMAnalyzers
import NMCore
import NMFlow
import NMIPC
import NMStore

final class LiveBackend: DaemonBackend, @unchecked Sendable {

    let engine: FlowEngine
    let ring: LiveRing
    private let paths: Paths
    private let startedAt: Timestamp
    private var config = SystemConfig()
    private var capturing = true

    /// Guards the ring, which the packet thread writes and the XPC timer reads.
    private let lock = NSLock()

    private var bpfBufferBytes = 0
    private var packetsReceived: Int64 = 0
    private var kernelDropped: Int64 = 0
    private var processWindowStarted: Timestamp = 0
    /// Flows that ended within the current window. Merged with the open ones so
    /// a short burst is not invisible just because it finished.
    private var recentlyClosed: [String: ProcessTraffic] = [:]

    init(paths: Paths, engine: FlowEngine = FlowEngine()) {
        self.paths = paths
        self.engine = engine
        self.ring = LiveRing()
        self.startedAt = Timestamp(Date().timeIntervalSince1970 * 1_000_000)

        engine.analyzers.register(DNSAnalyzer())
        engine.analyzers.register(TLSAnalyzer())
        wireEngine()
    }

    /// Mirrors flow lifecycle into the live ring.
    ///
    /// Closed flows are REMOVED from the live list here, not left to age out:
    /// the live view should show what is open now, and a closed connection
    /// lingering in it is the same lie as a stale cache entry.
    private func wireEngine() {
        engine.onConnectionRecord = { [weak self] record, _ in
            guard let self else { return }
            self.lock.lock()
            self.ring.closeFlow(uid: record.uid.raw)
            // Flows that closed inside the current window still count toward
            // "who is talking", so their bytes are held until the window rolls.
            let key = record.exec?.name ?? "(unattributed)"
            var entry = self.recentlyClosed[key]
                ?? ProcessTraffic(execID: Int64(record.pid), name: key,
                                  bytesIn: 0, bytesOut: 0, flows: 0,
                                  viaProxy: record.proxyExec?.name)
            entry.bytesIn += record.respIPBytes
            entry.bytesOut += record.origIPBytes
            entry.flows += 1
            self.recentlyClosed[key] = entry
            self.lock.unlock()
        }
    }

    /// Records a closed flow in the live view.
    ///
    /// Split out from the engine callback because the daemon needs the same
    /// record for the store, and having two subscribers to one closure would
    /// mean whichever was installed last silently replaced the other.
    func noteFlowClosed(_ record: ConnRecord) {
        lock.lock()
        ring.closeFlow(uid: record.uid.raw)
        let key = record.exec?.name ?? "(unattributed)"
        var entry = recentlyClosed[key]
            ?? ProcessTraffic(execID: Int64(record.pid), name: key,
                              bytesIn: 0, bytesOut: 0, flows: 0,
                              viaProxy: record.proxyExec?.name)
        entry.bytesIn += record.respIPBytes
        entry.bytesOut += record.origIPBytes
        entry.flows += 1
        recentlyClosed[key] = entry
        lock.unlock()
    }

    /// Called from the packet path for every processed packet.
    func observe(context: PacketContext, l3Bytes: Int, fromOriginator: Bool) {
        lock.lock()
        if context.direction == .inbound {
            ring.record(now: context.timestamp, bytesIn: Int64(l3Bytes), packetsIn: 1)
        } else {
            ring.record(now: context.timestamp, bytesOut: Int64(l3Bytes), packetsOut: 1)
        }

        // Top talkers mean "recently", not "since boot", so the window rolls.
        if processWindowStarted == 0 { processWindowStarted = context.timestamp }
        if context.timestamp - processWindowStarted > 60 * Time.microsPerSecond {
            recentlyClosed.removeAll(keepingCapacity: true)
            ring.rollProcessWindow()
            processWindowStarted = context.timestamp
        }
        lock.unlock()
    }

    /// Publishes the currently open flows into the live ring.
    ///
    /// Done on a cadence rather than per packet: the live list only has to be
    /// right several times a second, and rebuilding it on the packet path would
    /// put dictionary work where the budget is tightest.
    func refreshOpenFlows(now: Timestamp, limit: Int = 512) {
        var live: [LiveFlow] = []
        live.reserveCapacity(min(limit, engine.table.count))

        engine.table.forEachActive(limit: limit) { entry in
            let originator = entry.originatorIsLow ? entry.key.lowAddress : entry.key.highAddress
            let responder = entry.originatorIsLow ? entry.key.highAddress : entry.key.lowAddress
            let originatorPort = entry.originatorIsLow ? entry.key.lowPort : entry.key.highPort
            let responderPort = entry.originatorIsLow ? entry.key.highPort : entry.key.lowPort
            let state = entry.isTCP ? entry.tcp.connectionState : entry.datagram.connectionState

            live.append(LiveFlow(uid: entry.uid.raw,
                                 startedAt: entry.firstSeen,
                                 proto: entry.key.proto,
                                 localAddress: originator.description,
                                 localPort: originatorPort,
                                 remoteAddress: responder.description,
                                 remotePort: responderPort,
                                 hostname: entry.hostname,
                                 hostnameSource: entry.hostnameSource.rawValue,
                                 service: entry.serviceHint,
                                 processName: entry.wasDelegated && !entry.effectiveProcessName.isEmpty
                                     ? entry.effectiveProcessName : entry.processName,
                                 proxyName: entry.wasDelegated ? entry.processName : nil,
                                 bytesOut: entry.originatorIPBytes,
                                 bytesIn: entry.responderIPBytes,
                                 state: state.rawValue))
        }

        lock.lock()
        for flow in live {
            ring.openFlow(flow)
            ring.updateFlow(uid: flow.uid, bytesOut: flow.bytesOut, bytesIn: flow.bytesIn,
                            state: flow.state, hostname: flow.hostname,
                            service: flow.service)
        }

        // Per-process totals are recomputed from the open flows plus anything
        // that closed inside the window, rather than accumulated. Accumulating
        // would count a flow once while open and again when it closed.
        var totals = recentlyClosed
        for flow in live {
            let key = flow.processName ?? "(unattributed)"
            var entry = totals[key]
                ?? ProcessTraffic(execID: Int64(key.hashValue & 0x7FFF_FFFF), name: key,
                                  bytesIn: 0, bytesOut: 0, flows: 0, viaProxy: flow.proxyName)
            entry.bytesIn += flow.bytesIn
            entry.bytesOut += flow.bytesOut
            entry.flows += 1
            totals[key] = entry
        }
        ring.setProcessTotals(totals.values.sorted { $0.totalBytes > $1.totalBytes })
        ring.setHealth(currentHealth())
        lock.unlock()
    }

    func noteCaptureStats(received: Int64, kernelDropped: Int64, bufferBytes: Int) {
        lock.lock()
        if kernelDropped > self.kernelDropped {
            ring.noteLoss()
            engine.lossEpoch += 1
        }
        self.packetsReceived = received
        self.kernelDropped = kernelDropped
        self.bpfBufferBytes = bufferBytes
        lock.unlock()
    }

    private func currentHealth() -> CaptureHealth {
        CaptureHealthAssessor.assess(packetsReceived: packetsReceived,
                                     kernelDropped: kernelDropped,
                                     ringDropped: 0,
                                     decodeFailures: engine.stats.nonIPPackets,
                                     flowsShed: engine.table.stats.evicted,
                                     bpfBufferBytes: bpfBufferBytes)
    }

    // MARK: - DaemonBackend

    func currentStatus(callerUID: uid_t) -> DaemonStatus {
        lock.lock()
        let health = currentHealth()
        lock.unlock()

        return DaemonStatus(
            version: "0.1.0-dev",
            startedAt: startedAt,
            capturing: capturing,
            interfaces: ["pktap,all"],
            snaplen: config.snaplen,
            bpfBufferBytes: bpfBufferBytes,
            health: health,
            liveDay: Time.utcDayString(Timestamp(Date().timeIntervalSince1970 * 1_000_000)),
            archiveCount: Partition.archives(paths: paths).count,
            databaseBytes: Partition.fileSize(paths.liveDatabase),
            freeSpaceBytes: Partition.freeSpace(at: paths.databaseDirectory),
            // Tells the client whether to take the fast direct-read path or the
            // XPC fallback, rather than making it discover that by failing.
            callerCanReadStore: NMAuthorization.isInReadersGroup(uid: callerUID),
            databaseDirectory: paths.databaseDirectory)
    }

    func currentConfiguration() -> SystemConfig {
        lock.lock(); defer { lock.unlock() }
        return config
    }

    func snapshot(backfillSeconds: Int) -> LiveSnapshot {
        let now = Timestamp(Date().timeIntervalSince1970 * 1_000_000)
        refreshOpenFlows(now: now)
        lock.lock(); defer { lock.unlock() }
        return ring.snapshot(now: now, backfillSeconds: backfillSeconds)
    }

    func applyConfiguration(_ newConfig: SystemConfig) -> DaemonError? {
        lock.lock()
        config = newConfig
        lock.unlock()
        return nil
    }

    func setCaptureEnabled(_ enabled: Bool) -> DaemonError? {
        lock.lock(); capturing = enabled; lock.unlock()
        return nil
    }

    func runRetentionNow() -> DaemonError? {
        let today = Time.utcDayString(Timestamp(Date().timeIntervalSince1970 * 1_000_000))
        var policy = RetentionPolicy()
        policy.connDays = config.retention.connDays
        policy.dnsDays = config.retention.dnsDays
        policy.sslDays = config.retention.sslDays
        policy.payloadDays = config.retention.payloadDays
        policy.pcapBudgetBytes = config.retention.pcapBudgetBytes
        _ = Retention.run(paths: paths, policy: policy, today: today)
        return nil
    }

    func rotateNow() -> DaemonError? { nil }
}
