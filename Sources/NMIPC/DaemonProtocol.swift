//
//  DaemonProtocol.swift
//
//  The XPC interface.
//
//  Payloads cross as `Data` holding JSON rather than as @objc types. That
//  keeps the Objective-C protocol -- which is awkward to version -- stable
//  while the actual wire format evolves independently, and it means adding a
//  field does not require both binaries to be rebuilt together.
//
//  Every mutating method takes an authorization blob. That is not a
//  convenience: it is how a request that changes what is collected for every
//  user of the machine proves a human approved it.
//

import Foundation

/// The Mach service name the daemon publishes under.
public let nmDaemonMachServiceName = "com.narusec.networkmonitor.nmcapd"

/// What the daemon exposes.
@objc public protocol NMDaemonProtocol {

    // Unprivileged reads.

    func status(reply: @escaping (Data) -> Void)
    func configuration(reply: @escaping (Data) -> Void)
    func permissions(reply: @escaping (Data) -> Void)

    /// Starts the live push. `backfillSeconds` controls how much history the
    /// first snapshot carries, so a chart is populated on connect instead of
    /// drawing itself in over the following minutes.
    func subscribe(backfillSeconds: Int, hertz: Double)

    /// Stops the push. Clients call this when their window is occluded: a
    /// background monitor that keeps working when nobody is looking is a
    /// monitor people uninstall.
    func unsubscribe()

    // Privileged writes. Each re-verifies the authorization on this side.

    func setConfiguration(_ payload: Data, authorization: Data,
                          reply: @escaping (Data) -> Void)
    func setCaptureEnabled(_ enabled: Bool, authorization: Data,
                           reply: @escaping (Data) -> Void)
    func runRetention(authorization: Data, reply: @escaping (Data) -> Void)
    func rotateNow(authorization: Data, reply: @escaping (Data) -> Void)
}

/// What a subscribed client exposes back to the daemon.
@objc public protocol NMClientProtocol {
    /// One-way: the daemon does not wait for the client to finish drawing.
    func receiveSnapshot(_ payload: Data)
    func daemonStateChanged(_ payload: Data)
}

public enum NMInterface {
    public static func daemon() -> NSXPCInterface {
        NSXPCInterface(with: NMDaemonProtocol.self)
    }

    public static func client() -> NSXPCInterface {
        NSXPCInterface(with: NMClientProtocol.self)
    }
}
