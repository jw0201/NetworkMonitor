//
//  Wire.swift
//
//  What crosses the process boundary.
//
//  These types are versioned and Codable rather than being the domain types
//  themselves. The daemon and the app are separate binaries that can be
//  updated independently -- a user can replace the app while the daemon keeps
//  running -- so the wire format has to be able to change without either side
//  mis-reading the other. Encoding the domain types directly would couple the
//  protocol to every internal refactor.
//
//  They are also deliberately SMALL. The live snapshot is sent several times a
//  second to a client that may be showing it on a menu bar; anything that grows
//  with the number of flows belongs in a paged query, not here.
//

import Foundation
import NMCore

/// Bumped when a field's meaning changes incompatibly. Both sides check it.
public let nmWireVersion = 1

// MARK: - Live

/// One second of aggregate traffic.
public struct ThroughputSample: Codable, Sendable, Equatable {
    public var second: Int64
    public var bytesIn: Int64
    public var bytesOut: Int64
    public var packetsIn: Int64
    public var packetsOut: Int64
    public var activeFlows: Int32
    public var newFlows: Int32

    public init(second: Int64, bytesIn: Int64 = 0, bytesOut: Int64 = 0,
                packetsIn: Int64 = 0, packetsOut: Int64 = 0,
                activeFlows: Int32 = 0, newFlows: Int32 = 0) {
        self.second = second
        self.bytesIn = bytesIn
        self.bytesOut = bytesOut
        self.packetsIn = packetsIn
        self.packetsOut = packetsOut
        self.activeFlows = activeFlows
        self.newFlows = newFlows
    }

    public var totalBytes: Int64 { bytesIn + bytesOut }
}

/// Per-process traffic over the snapshot's window.
public struct ProcessTraffic: Codable, Sendable, Equatable {
    public var execID: Int64
    public var name: String
    public var bytesIn: Int64
    public var bytesOut: Int64
    public var flows: Int32
    /// The traffic was carried by a proxy on this process's behalf.
    public var viaProxy: String?

    public init(execID: Int64, name: String, bytesIn: Int64, bytesOut: Int64,
                flows: Int32, viaProxy: String? = nil) {
        self.execID = execID
        self.name = name
        self.bytesIn = bytesIn
        self.bytesOut = bytesOut
        self.flows = flows
        self.viaProxy = viaProxy
    }

    public var totalBytes: Int64 { bytesIn + bytesOut }
}

/// A connection currently open.
///
/// Open flows exist ONLY here: they are written to the database when they
/// close, so there is nothing to query for them. That is the structural reason
/// the live channel cannot be replaced by polling the store.
public struct LiveFlow: Codable, Sendable, Equatable {
    public var uid: UInt64
    public var startedAt: Timestamp
    public var proto: UInt8
    public var localAddress: String
    public var localPort: UInt16
    public var remoteAddress: String
    public var remotePort: UInt16
    public var hostname: String?
    public var hostnameSource: Int
    public var service: String?
    public var processName: String?
    public var proxyName: String?
    public var bytesOut: Int64
    public var bytesIn: Int64
    public var state: String

    public init(uid: UInt64, startedAt: Timestamp, proto: UInt8,
                localAddress: String, localPort: UInt16,
                remoteAddress: String, remotePort: UInt16,
                hostname: String? = nil, hostnameSource: Int = 0,
                service: String? = nil, processName: String? = nil,
                proxyName: String? = nil,
                bytesOut: Int64 = 0, bytesIn: Int64 = 0, state: String = "S0") {
        self.uid = uid
        self.startedAt = startedAt
        self.proto = proto
        self.localAddress = localAddress
        self.localPort = localPort
        self.remoteAddress = remoteAddress
        self.remotePort = remotePort
        self.hostname = hostname
        self.hostnameSource = hostnameSource
        self.service = service
        self.processName = processName
        self.proxyName = proxyName
        self.bytesOut = bytesOut
        self.bytesIn = bytesIn
        self.state = state
    }
}

/// How healthy the capture is.
///
/// Surfaced prominently rather than buried, because a monitor that is quietly
/// dropping packets is worse than one that is obviously broken: the numbers
/// still look plausible.
public struct CaptureHealth: Codable, Sendable, Equatable {
    public enum Level: Int, Codable, Sendable {
        case healthy = 0
        case degraded = 1
        case failing = 2
    }

    public var level: Level
    public var packetsReceived: Int64
    public var kernelDropped: Int64
    public var ringDropped: Int64
    public var decodeFailures: Int64
    public var flowsShed: Int64
    /// Plain-language cause, so the UI does not have to infer one.
    public var explanation: String

    public init(level: Level = .healthy, packetsReceived: Int64 = 0,
                kernelDropped: Int64 = 0, ringDropped: Int64 = 0,
                decodeFailures: Int64 = 0, flowsShed: Int64 = 0,
                explanation: String = "") {
        self.level = level
        self.packetsReceived = packetsReceived
        self.kernelDropped = kernelDropped
        self.ringDropped = ringDropped
        self.decodeFailures = decodeFailures
        self.flowsShed = flowsShed
        self.explanation = explanation
    }

    public var totalDropped: Int64 { kernelDropped + ringDropped }

    public var dropRate: Double {
        let total = packetsReceived + totalDropped
        return total > 0 ? Double(totalDropped) / Double(total) : 0
    }
}

/// What the daemon pushes to subscribers.
public struct LiveSnapshot: Codable, Sendable {
    public var wireVersion: Int = nmWireVersion
    public var generatedAt: Timestamp
    /// Recent per-second history. On first connect this is backfilled so a
    /// chart is populated immediately rather than drawing itself in over the
    /// next few minutes.
    public var samples: [ThroughputSample]
    public var topProcesses: [ProcessTraffic]
    public var flows: [LiveFlow]
    public var health: CaptureHealth
    /// Incremented on any capture drop. A client that sees this change knows
    /// the counts spanning it are approximate.
    public var lossEpoch: UInt64

    public init(generatedAt: Timestamp, samples: [ThroughputSample] = [],
                topProcesses: [ProcessTraffic] = [], flows: [LiveFlow] = [],
                health: CaptureHealth = CaptureHealth(), lossEpoch: UInt64 = 0) {
        self.generatedAt = generatedAt
        self.samples = samples
        self.topProcesses = topProcesses
        self.flows = flows
        self.health = health
        self.lossEpoch = lossEpoch
    }
}

// MARK: - Status and configuration

public struct DaemonStatus: Codable, Sendable {
    public var wireVersion: Int = nmWireVersion
    public var version: String
    public var startedAt: Timestamp
    public var capturing: Bool
    public var interfaces: [String]
    public var snaplen: Int32
    public var bpfBufferBytes: Int
    public var health: CaptureHealth
    public var liveDay: String?
    public var archiveCount: Int
    public var databaseBytes: Int64
    public var freeSpaceBytes: Int64
    /// Whether the caller may read the databases directly, i.e. is in the
    /// readers group. Lets the client choose the fast path or the XPC fallback
    /// without discovering it by failing.
    public var callerCanReadStore: Bool
    public var databaseDirectory: String

    public init(version: String, startedAt: Timestamp, capturing: Bool,
                interfaces: [String] = [], snaplen: Int32 = 0,
                bpfBufferBytes: Int = 0, health: CaptureHealth = CaptureHealth(),
                liveDay: String? = nil, archiveCount: Int = 0,
                databaseBytes: Int64 = 0, freeSpaceBytes: Int64 = 0,
                callerCanReadStore: Bool = false, databaseDirectory: String = "") {
        self.version = version
        self.startedAt = startedAt
        self.capturing = capturing
        self.interfaces = interfaces
        self.snaplen = snaplen
        self.bpfBufferBytes = bpfBufferBytes
        self.health = health
        self.liveDay = liveDay
        self.archiveCount = archiveCount
        self.databaseBytes = databaseBytes
        self.freeSpaceBytes = freeSpaceBytes
        self.callerCanReadStore = callerCanReadStore
        self.databaseDirectory = databaseDirectory
    }
}

/// System-wide settings.
///
/// Every field here changes what is collected or how long it is kept, which
/// affects every user of the machine -- so all of it requires authorization.
/// Per-user display preferences deliberately do NOT live here; they belong in
/// the app's own UserDefaults and need no privilege at all.
public struct SystemConfig: Codable, Sendable, Equatable {
    public var wireVersion: Int = nmWireVersion
    public var captureEnabled: Bool = true
    public var interfaces: [String] = []
    public var snaplen: Int32 = 2048
    public var retention = RetentionSettings()
    /// Off by default. Payload bytes are the most sensitive thing the product
    /// can hold: for non-TLS protocols they are plaintext credentials.
    public var payloadCaptureEnabled: Bool = false
    public var payloadBytesPerDirection: Int = 512
    public var pcapRingEnabled: Bool = false
    public var reverseDNSEnabled: Bool = false

    public init() {}

    public struct RetentionSettings: Codable, Sendable, Equatable {
        public var connDays: Int = 30
        public var dnsDays: Int = 14
        public var sslDays: Int = 30
        public var payloadDays: Int = 7
        public var pcapBudgetBytes: Int64 = 20 * 1024 * 1024 * 1024
        public init() {}
    }
}

/// Which settings the caller is allowed to change, so the UI can render locks
/// rather than discovering the answer by being refused.
public struct ConfigPermissions: Codable, Sendable {
    public var callerIsAdmin: Bool
    public var lockedFields: [String]
    public init(callerIsAdmin: Bool, lockedFields: [String] = []) {
        self.callerIsAdmin = callerIsAdmin
        self.lockedFields = lockedFields
    }
}

// MARK: - Errors

public enum DaemonError: Int, Codable, Sendable {
    case notAuthorized = 1
    case invalidRequest = 2
    case wireVersionMismatch = 3
    case notCapturing = 4
    case storeUnavailable = 5
    case internalFailure = 6

    public var message: String {
        switch self {
        case .notAuthorized:
            return "This change affects every user of this Mac and needs administrator approval."
        case .invalidRequest: return "The request was malformed."
        case .wireVersionMismatch:
            return "The app and the monitoring service are different versions."
        case .notCapturing: return "Capture is not running."
        case .storeUnavailable: return "The database is not available."
        case .internalFailure: return "The monitoring service failed to handle the request."
        }
    }
}

/// A reply carries either a payload or a structured error.
///
/// XPC gives you NSError across the boundary; this keeps the failure modes
/// enumerable and gives each one a sentence a person can act on.
public struct DaemonReply<T: Codable & Sendable>: Codable, Sendable {
    public var value: T?
    public var error: DaemonError?

    public init(value: T) { self.value = value; self.error = nil }
    public init(error: DaemonError) { self.value = nil; self.error = error }

    public func get() throws -> T {
        if let error { throw error }
        guard let value else { throw DaemonError.internalFailure }
        return value
    }
}

extension DaemonError: Error {}

// MARK: - Coding

public enum WireCoder {
    public static func encode<T: Encodable>(_ value: T) -> Data {
        (try? JSONEncoder().encode(value)) ?? Data()
    }

    public static func decode<T: Decodable>(_ type: T.Type, from data: Data) -> T? {
        try? JSONDecoder().decode(type, from: data)
    }
}
