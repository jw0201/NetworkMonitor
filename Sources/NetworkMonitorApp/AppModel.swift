//
//  AppModel.swift
//
//  What the UI observes.
//
//  The app talks to the daemon over XPC for live state and reads the sealed
//  archives directly for history -- it never imports the capture or flow
//  modules, so nothing here can accidentally end up on the packet path.
//
//  When no daemon is installed it starts one IN PROCESS against a synthetic
//  source. That is not a mock: the same DaemonServer and DaemonClient are used,
//  over an anonymous XPC listener, so snapshots are genuinely encoded, pushed
//  and decoded. The app cannot tell the difference, which is the point --
//  a demo path that bypassed the transport would not prove the real one works.
//

import Observation
import SwiftUI
import NMCore
import NMIPC

@MainActor
@Observable
final class AppModel {

    enum Mode: Equatable {
        case connecting
        /// Talking to the installed daemon.
        case daemon
        /// No daemon installed; driving a synthetic source in this process.
        case demo
        case failed(String)
    }

    private(set) var mode: Mode = .connecting
    private(set) var linkState: DaemonClient.LinkState = .disconnected

    /// Rolling per-second history. A fixed-capacity buffer, appended and
    /// dropped from the front, so the chart never rebuilds its whole dataset.
    private(set) var samples: [ThroughputSample] = []
    private(set) var topProcesses: [ProcessTraffic] = []
    private(set) var flows: [LiveFlow] = []
    private(set) var health = CaptureHealth()
    private(set) var status: DaemonStatus?
    private(set) var lastUpdate: Date?

    /// Advancing means packets were dropped, so counts spanning it are
    /// approximate. Surfaced rather than smoothed over.
    private(set) var lossEpoch: UInt64 = 0

    var chartWindowSeconds = 120 {
        didSet { trimSamples() }
    }

    private var client: DaemonClient?
    private var demo: DemoDaemon?
    private var streamTask: Task<Void, Never>?

    // MARK: - Lifecycle

    func start() async {
        guard case .connecting = mode else { return }

        // Try the installed daemon first. A short probe rather than a long
        // wait: if it is not there, the demo path should come up immediately
        // instead of leaving the window blank.
        //
        // The requirement is symmetric to the daemon's check on us. Without it
        // another local process could impersonate the monitoring service and
        // feed this UI fabricated data -- which for a security tool is a worse
        // failure than not connecting at all.
        let real = DaemonClient(target: .machService(nmDaemonMachServiceName),
                                daemonRequirement: PeerPinning.daemonRequirement())
        if let status = try? await withTimeout(seconds: 1.5, operation: {
            try await real.status()
        }) {
            self.status = status
            self.client = real
            self.mode = .daemon
            await subscribe(to: real)
            return
        }
        await real.stop()

        let demo = DemoDaemon()
        self.demo = demo
        let client = demo.makeClient()
        self.client = client
        self.mode = .demo
        self.status = try? await client.status()
        await subscribe(to: client)
    }

    private func subscribe(to client: DaemonClient) async {
        let stream = await client.snapshots()
        await client.subscribe(backfillSeconds: 300, hertz: 2)

        streamTask?.cancel()
        streamTask = Task { [weak self] in
            for await snapshot in stream {
                await self?.apply(snapshot)
            }
        }
    }

    /// Called when the window is occluded or closed. The daemon stops
    /// producing the moment nobody is looking, which is the difference between
    /// a background tool people keep and one they uninstall.
    func pause() async {
        await client?.pause()
    }

    func resume() async {
        await client?.subscribe(backfillSeconds: 30, hertz: 2)
    }

    func stop() async {
        streamTask?.cancel()
        await client?.stop()
        demo?.stop()
    }

    // MARK: - Updates

    private func apply(_ snapshot: LiveSnapshot) {
        // Merge rather than replace: subsequent snapshots carry only a few
        // seconds so the payload stays small, and replacing would throw away
        // the history the first one backfilled.
        let known = Set(samples.map(\.second))
        for sample in snapshot.samples where !known.contains(sample.second) {
            samples.append(sample)
        }
        // The in-progress second arrives repeatedly with growing counts.
        if let last = snapshot.samples.last,
           let index = samples.lastIndex(where: { $0.second == last.second }) {
            samples[index] = last
        }
        samples.sort { $0.second < $1.second }
        trimSamples()

        topProcesses = snapshot.topProcesses
        flows = snapshot.flows
        health = snapshot.health
        lossEpoch = snapshot.lossEpoch
        lastUpdate = Date()
        linkState = .connected
    }

    private func trimSamples() {
        let limit = max(chartWindowSeconds, 30)
        if samples.count > limit {
            samples.removeFirst(samples.count - limit)
        }
    }

    // MARK: - Derived

    var currentInRate: Int64 { samples.last?.bytesIn ?? 0 }
    var currentOutRate: Int64 { samples.last?.bytesOut ?? 0 }

    var peakRate: Int64 {
        max(samples.map(\.totalBytes).max() ?? 0, 1)
    }

    var activeFlowCount: Int { flows.count }

    var linkDescription: String {
        switch mode {
        case .connecting: return "Connecting…"
        case .daemon:
            if case .reconnecting(let attempt) = linkState {
                return "Reconnecting (attempt \(attempt))…"
            }
            return "Connected"
        case .demo: return "Demo data — no monitoring service installed"
        case .failed(let reason): return reason
        }
    }

    var isDemo: Bool { mode == .demo }

    var currentConfig: SystemConfig? { config }
    private var config: SystemConfig?

    func loadConfiguration() async {
        config = try? await client?.configuration()
    }

    /// Whether this user may change collection policy.
    ///
    /// Asked of the daemon rather than worked out locally: the answer has to
    /// come from the side that enforces it, and asking lets the UI render a
    /// lock instead of discovering the answer by being refused.
    func callerIsAdministrator() async -> Bool {
        guard let permissions = try? await client?.permissions() else { return false }
        return permissions.callerIsAdmin
    }
}

// MARK: - Helpers

/// Races an operation against a deadline.
///
/// Used so a missing daemon costs a second and a half rather than however long
/// XPC takes to give up, which would leave the window empty.
func withTimeout<T: Sendable>(seconds: Double,
                              operation: @escaping @Sendable () async throws -> T) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask { try await operation() }
        group.addTask {
            try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
            throw CancellationError()
        }
        guard let result = try await group.next() else { throw CancellationError() }
        group.cancelAll()
        return result
    }
}

extension CaptureHealth {
    var tint: Color {
        switch level {
        case .healthy: return .green
        case .degraded: return .orange
        case .failing: return .red
        }
    }
}
