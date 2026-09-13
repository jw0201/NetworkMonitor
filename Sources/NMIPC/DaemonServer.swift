//
//  DaemonServer.swift
//
//  The daemon's side of the connection.
//
//  Three things this is responsible for that are easy to leave out:
//
//    1. Deciding authorization here rather than trusting the client. The client
//       is a separate binary a user can replace.
//    2. Never using the peer's pid for identity. Pids are recycled, so a check
//       against one is a check against whoever holds it now.
//    3. Stopping work when nobody is listening. A subscriber that closed its
//       window should cost nothing.
//

import Foundation
import NMCore

/// What the server needs from the rest of the daemon, so this file has no
/// opinion about capture or storage and can be tested without either.
public protocol DaemonBackend: AnyObject {
    func currentStatus(callerUID: uid_t) -> DaemonStatus
    func currentConfiguration() -> SystemConfig
    func snapshot(backfillSeconds: Int) -> LiveSnapshot
    func applyConfiguration(_ config: SystemConfig) -> DaemonError?
    func setCaptureEnabled(_ enabled: Bool) -> DaemonError?
    func runRetentionNow() -> DaemonError?
    func rotateNow() -> DaemonError?
}

public final class DaemonServer: NSObject, NSXPCListenerDelegate {

    private let listener: NSXPCListener
    private weak var backend: DaemonBackend?

    /// Code-signing requirement each peer must satisfy, when one is available.
    /// Unsigned development builds have none, and the server says so loudly
    /// rather than pretending the check happened.
    private let peerRequirement: String?

    /// Development fallback: accept a group-membership check for writes when
    /// the custom authorization right is not installed.
    public var allowGroupMembershipFallback = false

    private let lock = NSLock()
    private var subscribers: [ObjectIdentifier: Subscriber] = [:]
    private var timer: DispatchSourceTimer?
    private let queue = DispatchQueue(label: "com.narusec.networkmonitor.xpc")

    private struct Subscriber {
        weak var connection: NSXPCConnection?
        var proxy: NMClientProtocol
        var hertz: Double
        var lastSentAt: Timestamp
        var uid: uid_t
    }

    public private(set) var stats = Stats()

    public struct Stats: Sendable, Equatable {
        public var connectionsAccepted: Int64 = 0
        public var connectionsRejected: Int64 = 0
        public var snapshotsPushed: Int64 = 0
        public var authorizationsDenied: Int64 = 0
        public var pushFailures: Int64 = 0
    }

    public init(listener: NSXPCListener, backend: DaemonBackend,
                peerRequirement: String? = nil) {
        self.listener = listener
        self.backend = backend
        self.peerRequirement = peerRequirement
        super.init()
        listener.delegate = self
    }

    /// A server bound to the Mach service declared in the LaunchDaemon plist.
    public static func machService(backend: DaemonBackend,
                                   peerRequirement: String? = nil) -> DaemonServer {
        DaemonServer(listener: NSXPCListener(machServiceName: nmDaemonMachServiceName),
                     backend: backend, peerRequirement: peerRequirement)
    }

    public func start() {
        listener.resume()
    }

    public func stop() {
        stopTimer()
        lock.lock()
        let connections = subscribers.values.compactMap(\.connection)
        subscribers.removeAll()
        lock.unlock()
        for connection in connections { connection.invalidate() }
        listener.invalidate()
    }

    // MARK: - Accepting

    public func listener(_ listener: NSXPCListener,
                         shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        if let peerRequirement {
            // Verifies the peer is the binary we expect, by code signature
            // rather than by path or pid -- both of which an attacker controls.
            connection.setCodeSigningRequirement(peerRequirement)
        }

        connection.exportedInterface = NMInterface.daemon()
        connection.remoteObjectInterface = NMInterface.client()

        let handler = ConnectionHandler(server: self, connection: connection)
        connection.exportedObject = handler

        connection.invalidationHandler = { [weak self] in
            self?.removeSubscriber(for: connection)
        }
        connection.interruptionHandler = { [weak self] in
            self?.removeSubscriber(for: connection)
        }

        connection.resume()
        stats.connectionsAccepted += 1
        return true
    }

    // MARK: - Subscriptions

    fileprivate func subscribe(connection: NSXPCConnection, backfillSeconds: Int,
                               hertz: Double) {
        guard let proxy = connection.remoteObjectProxy as? NMClientProtocol else { return }
        // Clamped: a client asking for a thousand updates a second would make
        // the daemon spend its time serialising instead of capturing.
        let rate = min(max(hertz, 0.1), 10)

        lock.lock()
        subscribers[ObjectIdentifier(connection)] = Subscriber(
            connection: connection, proxy: proxy, hertz: rate,
            lastSentAt: 0, uid: connection.effectiveUserIdentifier)
        lock.unlock()

        // The first snapshot carries history so the client's chart is populated
        // immediately rather than filling in over the next ten minutes.
        if let snapshot = backend?.snapshot(backfillSeconds: backfillSeconds) {
            proxy.receiveSnapshot(WireCoder.encode(snapshot))
            stats.snapshotsPushed += 1
        }
        startTimerIfNeeded()
    }

    fileprivate func unsubscribe(connection: NSXPCConnection) {
        removeSubscriber(for: connection)
    }

    private func removeSubscriber(for connection: NSXPCConnection) {
        lock.lock()
        subscribers.removeValue(forKey: ObjectIdentifier(connection))
        let remaining = subscribers.count
        lock.unlock()
        if remaining == 0 { stopTimer() }
    }

    public var subscriberCount: Int {
        lock.lock(); defer { lock.unlock() }
        return subscribers.count
    }

    // MARK: - Pushing

    private func startTimerIfNeeded() {
        lock.lock()
        let alreadyRunning = timer != nil
        lock.unlock()
        guard !alreadyRunning else { return }

        let source = DispatchSource.makeTimerSource(queue: queue)
        // Ticks at the finest rate any subscriber could want; each subscriber
        // is then rate-limited individually, so one fast client does not force
        // the pace for everyone.
        source.schedule(deadline: .now() + 0.1, repeating: 0.1)
        source.setEventHandler { [weak self] in self?.tick() }
        source.resume()

        lock.lock(); timer = source; lock.unlock()
    }

    private func stopTimer() {
        lock.lock()
        let source = timer
        timer = nil
        lock.unlock()
        source?.cancel()
    }

    private func tick() {
        let now = Timestamp(Date().timeIntervalSince1970 * 1_000_000)

        lock.lock()
        let due = subscribers.filter { _, subscriber in
            let interval = Int64(1_000_000 / subscriber.hertz)
            return now - subscriber.lastSentAt >= interval
        }
        lock.unlock()
        guard !due.isEmpty else { return }

        // Subsequent snapshots carry only a few seconds of history: the client
        // already has the rest, and a full window several times a second would
        // be most of the payload.
        guard let snapshot = backend?.snapshot(backfillSeconds: 5) else { return }
        let payload = WireCoder.encode(snapshot)

        for (key, subscriber) in due {
            guard subscriber.connection != nil else {
                lock.lock(); subscribers.removeValue(forKey: key); lock.unlock()
                continue
            }
            subscriber.proxy.receiveSnapshot(payload)
            stats.snapshotsPushed += 1
            lock.lock()
            subscribers[key]?.lastSentAt = now
            lock.unlock()
        }
    }

    // MARK: - Authorization

    fileprivate func authorize(_ blob: Data, connection: NSXPCConnection) -> Bool {
        if NMAuthorization.verifyAdminRights(blob) { return true }

        if allowGroupMembershipFallback {
            // Weaker, and only for unsigned development builds where the
            // custom right has not been installed: this proves who the caller
            // is, not that a human just approved the action.
            let uid = connection.effectiveUserIdentifier
            if NMAuthorization.isAdministrator(uid: uid) { return true }
        }

        stats.authorizationsDenied += 1
        return false
    }

    fileprivate var currentBackend: DaemonBackend? { backend }
}

/// One connection's exported object.
///
/// A separate instance per connection so the caller's identity is captured once
/// and cannot be confused between concurrent clients.
private final class ConnectionHandler: NSObject, NMDaemonProtocol {

    private weak var server: DaemonServer?
    private weak var connection: NSXPCConnection?
    private let callerUID: uid_t

    init(server: DaemonServer, connection: NSXPCConnection) {
        self.server = server
        self.connection = connection
        // Captured at accept time. The pid is deliberately NOT recorded:
        // pids are recycled, so identity based on one is identity based on
        // whoever holds it now.
        self.callerUID = connection.effectiveUserIdentifier
        super.init()
    }

    // MARK: Reads

    func status(reply: @escaping (Data) -> Void) {
        guard let backend = server?.currentBackend else {
            return reply(WireCoder.encode(DaemonReply<DaemonStatus>(error: .internalFailure)))
        }
        reply(WireCoder.encode(DaemonReply(value: backend.currentStatus(callerUID: callerUID))))
    }

    func configuration(reply: @escaping (Data) -> Void) {
        guard let backend = server?.currentBackend else {
            return reply(WireCoder.encode(DaemonReply<SystemConfig>(error: .internalFailure)))
        }
        reply(WireCoder.encode(DaemonReply(value: backend.currentConfiguration())))
    }

    func permissions(reply: @escaping (Data) -> Void) {
        // Lets the UI render locks up front instead of discovering the answer
        // by being refused. It is a convenience, never the enforcement.
        let isAdmin = NMAuthorization.isAdministrator(uid: callerUID)
        let locked = isAdmin ? [] : ["captureEnabled", "interfaces", "snaplen",
                                     "retention", "payloadCaptureEnabled",
                                     "pcapRingEnabled", "reverseDNSEnabled"]
        reply(WireCoder.encode(DaemonReply(value: ConfigPermissions(callerIsAdmin: isAdmin,
                                                                    lockedFields: locked))))
    }

    func subscribe(backfillSeconds: Int, hertz: Double) {
        guard let server, let connection else { return }
        server.subscribe(connection: connection,
                         backfillSeconds: min(max(backfillSeconds, 1), 900),
                         hertz: hertz)
    }

    func unsubscribe() {
        guard let server, let connection else { return }
        server.unsubscribe(connection: connection)
    }

    // MARK: Writes

    func setConfiguration(_ payload: Data, authorization: Data,
                          reply: @escaping (Data) -> Void) {
        perform(authorization, reply: reply) { backend in
            guard let config = WireCoder.decode(SystemConfig.self, from: payload) else {
                return .invalidRequest
            }
            guard config.wireVersion == nmWireVersion else { return .wireVersionMismatch }
            return backend.applyConfiguration(config)
        }
    }

    func setCaptureEnabled(_ enabled: Bool, authorization: Data,
                           reply: @escaping (Data) -> Void) {
        perform(authorization, reply: reply) { $0.setCaptureEnabled(enabled) }
    }

    func runRetention(authorization: Data, reply: @escaping (Data) -> Void) {
        perform(authorization, reply: reply) { $0.runRetentionNow() }
    }

    func rotateNow(authorization: Data, reply: @escaping (Data) -> Void) {
        perform(authorization, reply: reply) { $0.rotateNow() }
    }

    private func perform(_ authorization: Data, reply: @escaping (Data) -> Void,
                         _ action: (DaemonBackend) -> DaemonError?) {
        guard let server, let connection, let backend = server.currentBackend else {
            return reply(WireCoder.encode(DaemonReply<Bool>(error: .internalFailure)))
        }
        guard server.authorize(authorization, connection: connection) else {
            return reply(WireCoder.encode(DaemonReply<Bool>(error: .notAuthorized)))
        }
        if let error = action(backend) {
            reply(WireCoder.encode(DaemonReply<Bool>(error: error)))
        } else {
            reply(WireCoder.encode(DaemonReply(value: true)))
        }
    }
}
