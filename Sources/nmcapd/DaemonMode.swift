//
//  DaemonMode.swift
//
//  `nmcapd --daemon` -- the real service, as launchd runs it.
//
//  Everything that has been exercised separately up to now is wired together
//  here: capture feeds the flow engine, the engine feeds both the store and the
//  live ring, XPC serves the app, and maintenance runs on its own cadence.
//
//  Three properties matter more than the wiring:
//
//    * The packet thread never waits on anything. Records go to the writer
//      through a queue drained elsewhere, so a slow disk costs rows rather than
//      packets -- packets dropped at the BPF layer are gone and their loss is
//      invisible.
//    * Shutdown is orderly. launchd gives a deadline (ExitTimeOut in the
//      plist); within it the capture stops, pending records are written, the
//      WAL is checkpointed and open flows are finalised rather than lost.
//    * Failures are reported through os_log rather than stdout, because under
//      launchd stdout goes to a file nobody reads.
//

import Darwin
import Foundation
import NMAnalyzers
import NMCapture
import NMCore
import NMFlow
import NMIPC
import NMStore
import os

private let log = Logger(subsystem: "com.narusec.networkmonitor", category: "daemon")

func runDaemon(rootOverride: String?) async -> Int32 {
    let paths = rootOverride.map { Paths(root: $0) } ?? Paths()

    log.notice("nmcapd starting, store at \(paths.root, privacy: .public)")

    guard geteuid() == 0 else {
        log.error("nmcapd must run as root; /dev/bpf* is mode 0600 root:wheel")
        FileHandle.standardError.write(Data("nmcapd must run as root\n".utf8))
        return 1
    }

    // Storage first: if the store cannot be opened there is no point capturing.
    let writer: StoreWriter
    do {
        writer = try StoreWriter(paths: paths)
    } catch {
        log.error("cannot open store: \(String(describing: error), privacy: .public)")
        return 1
    }

    let backend = LiveBackend(paths: paths)
    let coordinator = DaemonCoordinator(paths: paths, writer: writer, backend: backend)

    // XPC before capture, so an app that is already running connects promptly
    // rather than waiting for the first packet.
    let server = DaemonServer.machService(backend: backend,
                                          peerRequirement: PeerPinning.appRequirement(paths: paths))
    server.allowGroupMembershipFallback = PeerPinning.appRequirement(paths: paths) == nil
    server.start()
    log.notice("XPC listening on \(nmDaemonMachServiceName, privacy: .public)")

    if server.allowGroupMembershipFallback {
        // Worth saying out loud: without a pinned peer identity the only thing
        // standing between an arbitrary local process and a privileged call is
        // group membership.
        log.notice("""
            no peers.plist -- peer code-signing checks are disabled and             administrator checks fall back to group membership
            """)
    }

    coordinator.startCapture()
    coordinator.startMaintenance()

    // launchd sends SIGTERM and then waits ExitTimeOut before SIGKILL.
    // Installing a handler is what turns that into an orderly stop instead of
    // losing whatever was in flight.
    let shutdown = ShutdownSignal()
    installSignalHandlers(shutdown)

    log.notice("nmcapd ready")
    await shutdown.wait()

    log.notice("nmcapd stopping")
    server.stop()
    await coordinator.shutdown()
    log.notice("nmcapd stopped cleanly")
    return 0
}

// MARK: - Coordinator

/// Owns the threads and the schedules.
private final class DaemonCoordinator: @unchecked Sendable {

    private let paths: Paths
    private let writer: StoreWriter
    private let backend: LiveBackend
    private let pending = PendingRecords()

    private var captureThread: Thread?
    private var session: CaptureSession?
    private var maintenanceTimer: DispatchSourceTimer?
    private let queue = DispatchQueue(label: "com.narusec.networkmonitor.maintenance")
    /// Read by the capture thread and written by the async shutdown path, so
    /// it is an atomic rather than a lock: NSLock is unavailable from an async
    /// context, and a lock here would only ever guard one Bool.
    private let stopping = OSAllocatedUnfairLock(initialState: false)

    init(paths: Paths, writer: StoreWriter, backend: LiveBackend) {
        self.paths = paths
        self.writer = writer
        self.backend = backend

        // The engine hands records to a queue rather than to the store: the
        // writer is an actor and awaiting it on the packet path would put a
        // suspension point where the budget is roughly a microsecond.
        backend.engine.onConnectionRecord = { [weak self] record, _ in
            self?.backend.noteFlowClosed(record)
            self?.pending.add(conn: record)
        }
        backend.engine.onDNSRecord = { [weak self] record in self?.pending.add(dns: record) }
        backend.engine.onSSLRecord = { [weak self] record in self?.pending.add(ssl: record) }
    }

    func startCapture() {
        let session = CaptureSession()
        do {
            try session.open()
        } catch {
            log.error("capture failed: \(String(describing: error), privacy: .public)")
            return
        }
        self.session = session
        log.notice("capture open: \(session.bpfCeiling.explanation, privacy: .public)")

        let thread = Thread { [weak self] in
            guard let self else { return }
            var lastStatsCheck = Date()

            while !self.isStopping {
                _ = session.drain(count: 512) { meta, record, timestamp in
                    var l3 = (try? record.reader(at: meta.l3Offset,
                                                 count: record.count - meta.l3Offset))
                    guard l3 != nil else { return }
                    let context = makeContext(meta, timestamp: timestamp,
                                              lossEpoch: self.backend.engine.lossEpoch)
                    self.backend.engine.process(context, l3: &l3!)
                    self.backend.observe(context: context,
                                         l3Bytes: record.count - meta.l3Offset,
                                         fromOriginator: context.direction == .outbound)
                }

                // Sampled rather than read per packet: pcap_stats is an ioctl
                // and the drop counters do not need microsecond resolution.
                if Date().timeIntervalSince(lastStatsCheck) >= 1 {
                    lastStatsCheck = Date()
                    if let stats = session.stats() {
                        self.backend.noteCaptureStats(received: Int64(stats.received),
                                                      kernelDropped: Int64(stats.kernelDropped),
                                                      bufferBytes: session.bpfCeiling.after)
                    }
                }
            }
            session.close()
        }
        thread.name = "nm.capture"
        thread.qualityOfService = .userInitiated
        captureThread = thread
        thread.start()
    }

    func startMaintenance() {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 1, repeating: 1)
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            Task { await self.tick() }
        }
        timer.resume()
        maintenanceTimer = timer
    }

    private var lastRetention = Date.distantPast
    private var lastFlush = Date()
    private var lastCheckpoint = Date()

    private func tick() async {
        let now = Timestamp(Date().timeIntervalSince1970 * 1_000_000)
        backend.refreshOpenFlows(now: now)
        backend.engine.tick(now: now)

        // Records are written in batches. Four times a second keeps the
        // transaction count at a handful per second rather than thousands,
        // which is the difference between SQLite being irrelevant to
        // performance and SQLite being the bottleneck.
        if Date().timeIntervalSince(lastFlush) >= 0.25 {
            lastFlush = Date()
            let batch = pending.take()
            if !batch.isEmpty {
                do { try await writer.write(batch) }
                catch {
                    log.error("write failed: \(String(describing: error), privacy: .public)")
                }
            }
        }

        // The WAL needs its own schedule. With wal_autocheckpoint off -- so a
        // checkpoint cannot land mid-batch -- nothing else would ever shrink
        // it: observed on a live install, 45 minutes of browsing produced an
        // 8 KB database and a 48 MB WAL.
        if Date().timeIntervalSince(lastCheckpoint) >= 30 {
            lastCheckpoint = Date()
            let after = await writer.checkpointIfNeeded()
            if after > 256 * 1024 * 1024 {
                log.error("""
                    write-ahead log is \(after) bytes after a checkpoint;                     a long-running reader may be holding it open
                    """)
            }
        }

        // Hourly, and separate from rotation: rotation is driven by the day
        // changing, retention by the clock, and coupling them would make a
        // quiet machine skip cleanups.
        if Date().timeIntervalSince(lastRetention) >= 3600 {
            lastRetention = Date()
            let report = await writer.runRetention(now: now)
            if report.didAnything {
                log.notice("""
                    retention: deleted \(report.filesDeleted.count) file(s), \
                    trimmed \(report.filesTrimmed.count), \
                    reclaimed \(report.bytesReclaimed) bytes
                    """)
            }
            for error in report.errors {
                log.error("retention: \(error, privacy: .public)")
            }
        }
    }

    private var isStopping: Bool {
        stopping.withLock { $0 }
    }

    /// Stops in the order that loses the least: capture first, then whatever is
    /// still in flight, then the store.
    func shutdown() async {
        stopping.withLock { $0 = true }
        maintenanceTimer?.cancel()

        // Give the capture thread a moment to notice. Bounded, because launchd
        // is counting.
        for _ in 0..<20 where captureThread?.isFinished == false {
            try? await Task.sleep(nanoseconds: 100_000_000)
        }

        // Open flows are finalised rather than discarded: a connection that was
        // still running at shutdown is a real record, not a partial one.
        backend.engine.flush()
        let remaining = pending.take()
        if !remaining.isEmpty {
            try? await writer.write(remaining)
        }
        try? await writer.flush()
        await writer.close()
    }
}

/// Records waiting to be written.
///
/// A plain lock rather than an actor: the producer is the packet thread, and an
/// actor hop there costs more than the lock does.
private final class PendingRecords: @unchecked Sendable {
    private let lock = NSLock()
    private var batch = RecordBatch()
    /// Bounded. If the writer stalls, shedding rows is the correct failure --
    /// unbounded growth would turn a slow disk into an out-of-memory kill, and
    /// the capture would stop entirely.
    private let limit = 200_000
    private(set) var shed: Int64 = 0

    func add(conn: ConnRecord) {
        lock.lock(); defer { lock.unlock() }
        guard batch.count < limit else { shed += 1; return }
        batch.conns.append(conn)
    }

    func add(dns: DNSRecord) {
        lock.lock(); defer { lock.unlock() }
        guard batch.count < limit else { shed += 1; return }
        batch.dns.append(dns)
    }

    func add(ssl: SSLRecord) {
        lock.lock(); defer { lock.unlock() }
        guard batch.count < limit else { shed += 1; return }
        batch.ssl.append(ssl)
    }

    func take() -> RecordBatch {
        lock.lock(); defer { lock.unlock() }
        let taken = batch
        batch = RecordBatch()
        return taken
    }
}

// MARK: - Signals

private final class ShutdownSignal: @unchecked Sendable {
    private let semaphore = DispatchSemaphore(value: 0)
    private let signalled = OSAllocatedUnfairLock(initialState: false)

    func fire() {
        let alreadyFired = signalled.withLock { state -> Bool in
            let previous = state
            state = true
            return previous
        }
        if !alreadyFired { semaphore.signal() }
    }

    func wait() async {
        await withCheckedContinuation { continuation in
            DispatchQueue.global().async {
                self.semaphore.wait()
                continuation.resume()
            }
        }
    }
}

private nonisolated(unsafe) var shutdownSignal: ShutdownSignal?

private func installSignalHandlers(_ signal: ShutdownSignal) {
    shutdownSignal = signal
    // SIG_IGN first: the DispatchSource handlers below are what actually run,
    // and leaving the default disposition in place would kill the process
    // before they fire.
    Darwin.signal(SIGTERM, SIG_IGN)
    Darwin.signal(SIGINT, SIG_IGN)

    for number in [SIGTERM, SIGINT] {
        let source = DispatchSource.makeSignalSource(signal: number,
                                                     queue: .global())
        source.setEventHandler { shutdownSignal?.fire() }
        source.resume()
        signalSources.append(source)
    }
}

private nonisolated(unsafe) var signalSources: [DispatchSourceSignal] = []

// MARK: - Peer pinning

enum PeerPinning {
    /// The app's code-signing requirement, read from peers.plist.
    ///
    /// Neither binary can contain the other's cdhash -- each would change the
    /// other's -- so the installer computes both after signing and writes them
    /// here. Absent, the daemon says so and falls back to group membership.
    static func appRequirement(paths: Paths) -> String? {
        guard let data = FileManager.default.contents(atPath: paths.peersFile),
              let plist = try? PropertyListSerialization.propertyList(
                from: data, format: nil) as? [String: String],
              let hash = plist["appCDHash"], !hash.isEmpty,
              let identifier = plist["appIdentifier"] else {
            return nil
        }
        return "identifier \"\(identifier)\" and cdhash H\"\(hash)\""
    }

    static func daemonRequirement(paths: Paths) -> String? {
        guard let data = FileManager.default.contents(atPath: paths.peersFile),
              let plist = try? PropertyListSerialization.propertyList(
                from: data, format: nil) as? [String: String],
              let hash = plist["daemonCDHash"], !hash.isEmpty,
              let identifier = plist["daemonIdentifier"] else {
            return nil
        }
        return "identifier \"\(identifier)\" and cdhash H\"\(hash)\""
    }
}
