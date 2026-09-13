//
//  DaemonClient.swift
//
//  The app's side of the connection.
//
//  Two behaviours here are the difference between a tool people keep and one
//  they uninstall:
//
//    * It unsubscribes when nobody is looking. A background monitor that keeps
//      the daemon serialising snapshots for an occluded window burns battery
//      for nothing.
//    * It reconnects on its own, with backoff. The daemon restarts -- on
//      upgrade, on crash, on a KeepAlive bounce -- and an app that needs
//      relaunching after every one of those is broken in practice even though
//      each individual failure is "correct".
//

import Foundation
import NMCore

public actor DaemonClient {

    public enum LinkState: Sendable, Equatable {
        case disconnected
        case connected
        case reconnecting(attempt: Int)
        /// The daemon answered but speaks a different wire version. Retrying
        /// will not help and the UI should say so rather than spin.
        case versionMismatch
    }

    private var connection: NSXPCConnection?
    private var receiver: SnapshotReceiver?
    private var continuation: AsyncStream<LiveSnapshot>.Continuation?
    private var reconnectAttempt = 0
    private var subscribed = false
    private var wantsSubscription = false
    private var backfillSeconds = 300
    private var hertz: Double = 2

    public private(set) var state: LinkState = .disconnected

    /// Where to connect. An endpoint is used by tests and by anonymous
    /// listeners; the Mach service name is the real path.
    public enum Target: Sendable {
        case machService(String)
        case endpoint(NSXPCListenerEndpoint)
    }

    private let target: Target
    private let daemonRequirement: String?

    public init(target: Target = .machService(nmDaemonMachServiceName),
                daemonRequirement: String? = nil) {
        self.target = target
        self.daemonRequirement = daemonRequirement
    }

    // MARK: - Connection

    private func makeConnection() -> NSXPCConnection {
        let connection: NSXPCConnection
        switch target {
        case .machService(let name):
            // privileged: the daemon runs in the system domain, not the user's.
            connection = NSXPCConnection(machServiceName: name, options: .privileged)
        case .endpoint(let endpoint):
            connection = NSXPCConnection(listenerEndpoint: endpoint)
        }

        if let daemonRequirement {
            // Symmetric to the daemon's check: this is what stops another
            // process impersonating the monitoring service and feeding the UI
            // fabricated data.
            connection.setCodeSigningRequirement(daemonRequirement)
        }

        connection.remoteObjectInterface = NMInterface.daemon()
        connection.exportedInterface = NMInterface.client()

        let receiver = SnapshotReceiver { [weak self] snapshot in
            Task { await self?.deliver(snapshot) }
        }
        self.receiver = receiver
        connection.exportedObject = receiver

        connection.invalidationHandler = { [weak self] in
            Task { await self?.handleDrop(invalidated: true) }
        }
        connection.interruptionHandler = { [weak self] in
            Task { await self?.handleDrop(invalidated: false) }
        }
        connection.resume()
        return connection
    }

    private func proxy() -> NMDaemonProtocol? {
        if connection == nil { connection = makeConnection() }
        return connection?.remoteObjectProxyWithErrorHandler { _ in
            // Errors surface through the invalidation handler; swallowing here
            // keeps every call site from having to duplicate that path.
        } as? NMDaemonProtocol
    }

    private func handleDrop(invalidated: Bool) async {
        connection = nil
        subscribed = false
        guard wantsSubscription else {
            state = .disconnected
            return
        }

        reconnectAttempt += 1
        state = .reconnecting(attempt: reconnectAttempt)

        // Backoff, capped. An immediate retry loop against a daemon that is
        // down is a busy-wait that makes the machine worse.
        let delay = min(pow(2.0, Double(min(reconnectAttempt, 5))), 30)
        try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
        guard wantsSubscription else { return }
        await subscribe(backfillSeconds: backfillSeconds, hertz: hertz)
    }

    private func deliver(_ snapshot: LiveSnapshot) {
        guard snapshot.wireVersion == nmWireVersion else {
            state = .versionMismatch
            return
        }
        reconnectAttempt = 0
        state = .connected
        continuation?.yield(snapshot)
    }

    // MARK: - Live stream

    /// The stream of snapshots. Finishes when `stop()` is called.
    public func snapshots() -> AsyncStream<LiveSnapshot> {
        AsyncStream { continuation in
            self.continuation = continuation
        }
    }

    public func subscribe(backfillSeconds: Int = 300, hertz: Double = 2) async {
        self.wantsSubscription = true
        self.backfillSeconds = backfillSeconds
        self.hertz = hertz
        guard let proxy = proxy() else { return }
        proxy.subscribe(backfillSeconds: backfillSeconds, hertz: hertz)
        subscribed = true
    }

    /// Called when the window is occluded or closed. The daemon stops producing
    /// snapshots the moment nobody is listening.
    public func pause() async {
        wantsSubscription = false
        guard subscribed, let proxy = proxy() else { return }
        proxy.unsubscribe()
        subscribed = false
    }

    public func stop() async {
        wantsSubscription = false
        continuation?.finish()
        continuation = nil
        connection?.invalidate()
        connection = nil
        state = .disconnected
    }

    // MARK: - Requests

    public func status() async throws -> DaemonStatus {
        try await request(DaemonStatus.self) { proxy, reply in
            proxy.status(reply: reply)
        }
    }

    public func configuration() async throws -> SystemConfig {
        try await request(SystemConfig.self) { proxy, reply in
            proxy.configuration(reply: reply)
        }
    }

    public func permissions() async throws -> ConfigPermissions {
        try await request(ConfigPermissions.self) { proxy, reply in
            proxy.permissions(reply: reply)
        }
    }

    /// Changing collection policy affects everyone on the machine, so this
    /// raises the standard administrator prompt before the daemon is even
    /// asked -- and the daemon re-checks the result regardless.
    public func setConfiguration(_ config: SystemConfig,
                                 authorization: Data) async throws -> Bool {
        try await request(Bool.self) { proxy, reply in
            proxy.setConfiguration(WireCoder.encode(config),
                                   authorization: authorization, reply: reply)
        }
    }

    public func setCaptureEnabled(_ enabled: Bool, authorization: Data) async throws -> Bool {
        try await request(Bool.self) { proxy, reply in
            proxy.setCaptureEnabled(enabled, authorization: authorization, reply: reply)
        }
    }

    public func runRetention(authorization: Data) async throws -> Bool {
        try await request(Bool.self) { proxy, reply in
            proxy.runRetention(authorization: authorization, reply: reply)
        }
    }

    public func rotateNow(authorization: Data) async throws -> Bool {
        try await request(Bool.self) { proxy, reply in
            proxy.rotateNow(authorization: authorization, reply: reply)
        }
    }

    private func request<T: Codable & Sendable>(
        _ type: T.Type,
        _ send: (NMDaemonProtocol, @escaping (Data) -> Void) -> Void
    ) async throws -> T {
        guard let proxy = proxy() else { throw DaemonError.internalFailure }
        let data: Data = await withCheckedContinuation { continuation in
            send(proxy) { continuation.resume(returning: $0) }
        }
        guard let reply = WireCoder.decode(DaemonReply<T>.self, from: data) else {
            throw DaemonError.internalFailure
        }
        return try reply.get()
    }
}

/// The object the daemon calls back into.
private final class SnapshotReceiver: NSObject, NMClientProtocol {
    private let onSnapshot: (LiveSnapshot) -> Void

    init(onSnapshot: @escaping (LiveSnapshot) -> Void) {
        self.onSnapshot = onSnapshot
        super.init()
    }

    func receiveSnapshot(_ payload: Data) {
        guard let snapshot = WireCoder.decode(LiveSnapshot.self, from: payload) else { return }
        onSnapshot(snapshot)
    }

    func daemonStateChanged(_ payload: Data) {}
}
