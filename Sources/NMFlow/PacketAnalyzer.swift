//
//  PacketAnalyzer.swift
//
//  The seam application-layer analyzers plug into.
//
//  The protocol lives here rather than in NMAnalyzers because the flow engine
//  has to call it, and NMAnalyzers already depends on NMFlow for the L3/L4
//  types. Putting it the other way round would be circular.
//
//  Analyzers are SINGLETONS, not per-flow objects. Allocating an analyzer per
//  flow would put a heap allocation on flow creation, which is exactly the path
//  a SYN flood hammers. Per-flow state instead lives either in the flow entry
//  or in a bounded table the analyzer owns and keys itself.
//

import NMCore

/// What an analyzer wants to happen next.
public enum AnalyzerVerdict: Sendable {
    /// Keep feeding this flow's payloads to me.
    case wantMore
    /// I have what I need; stop calling me for this flow.
    case satisfied
    /// Misidentified -- this is not my protocol. Detach and let another try.
    case notMine
    /// Malformed. Detach and record why.
    case failed(String)
}

/// What an analyzer produces.
public enum AnalyzerOutput: Sendable {
    case dns(DNSRecord)
    case ssl(SSLRecord)
    /// The application protocol this flow turned out to be carrying, which ends
    /// up in the conn record's `service` column.
    case service(String)
    /// A hostname learned for an address, offered to the enrichment cache.
    case resolvedName(address: IPAddress, name: String, ttl: UInt32, requestingPID: Int32)
    /// A name learned for THIS flow specifically, with its provenance. Applied
    /// to the flow directly, and only when it outranks what is already there.
    case hostname(String, HostnameSource)
}

/// How a flow is routed to an analyzer.
public enum AnalyzerTrigger: Sendable {
    case port(proto: UInt8, port: UInt16)
    case portRange(proto: UInt8, ClosedRange<UInt16>)
}

/// Everything an analyzer is given about one payload.
public struct AnalyzerContext {
    public let flowUID: FlowID
    public let key: FlowKey
    public let packet: PacketContext
    public let fromOriginator: Bool
    public let sourceAddress: IPAddress
    public let sourcePort: UInt16
    public let destinationAddress: IPAddress
    public let destinationPort: UInt16
    public let proto: UInt8

    /// True when the payload is the cumulative in-order stream rather than a
    /// single datagram. A stream analyzer will be called repeatedly with a
    /// growing prefix and must be restartable.
    public let isStream: Bool
    /// The stream lost in-order continuity before this point. Anything parsed
    /// past a gap is guesswork, so analyzers stop rather than splice.
    public let streamHasGap: Bool

    public init(flowUID: FlowID, key: FlowKey, packet: PacketContext,
                fromOriginator: Bool,
                sourceAddress: IPAddress, sourcePort: UInt16,
                destinationAddress: IPAddress, destinationPort: UInt16,
                proto: UInt8,
                isStream: Bool = false,
                streamHasGap: Bool = false) {
        self.flowUID = flowUID
        self.key = key
        self.packet = packet
        self.fromOriginator = fromOriginator
        self.sourceAddress = sourceAddress
        self.sourcePort = sourcePort
        self.destinationAddress = destinationAddress
        self.destinationPort = destinationPort
        self.proto = proto
        self.isStream = isStream
        self.streamHasGap = streamHasGap
    }
}

public protocol PacketAnalyzer: AnyObject {
    var identifier: String { get }
    var triggers: [AnalyzerTrigger] { get }

    /// One datagram, or one TCP payload. `payload` is scoped to exactly the
    /// application bytes and borrows memory valid only for this call.
    func analyze(_ context: AnalyzerContext,
                 payload: ByteReader,
                 emit: (AnalyzerOutput) -> Void) -> AnalyzerVerdict

    /// Called when the flow ends, so an analyzer can flush anything it was
    /// holding (an unanswered query, a half-seen handshake).
    func flowClosed(_ uid: FlowID, emit: (AnalyzerOutput) -> Void)

    /// Periodic maintenance: expire pending state. Called about once a second.
    func tick(now: Timestamp, emit: (AnalyzerOutput) -> Void)
}

public extension PacketAnalyzer {
    func flowClosed(_ uid: FlowID, emit: (AnalyzerOutput) -> Void) {}
    func tick(now: Timestamp, emit: (AnalyzerOutput) -> Void) {}
}

/// Routes payloads to analyzers by protocol and port.
///
/// Dispatch is a flat 65,536-entry table per protocol: one array index, no
/// hashing, no iteration over registered analyzers. 128 KB of memory to take
/// the per-packet cost of analyzer lookup to approximately nothing.
public final class AnalyzerRegistry {
    private var analyzers: [PacketAnalyzer] = []
    /// Index+1 into `analyzers`, or 0 for "no analyzer". Avoids an optional.
    private var tcpPorts = [UInt16](repeating: 0, count: 65536)
    private var udpPorts = [UInt16](repeating: 0, count: 65536)

    public init() {}

    public var count: Int { analyzers.count }

    public func register(_ analyzer: PacketAnalyzer) {
        analyzers.append(analyzer)
        let slot = UInt16(analyzers.count)

        for trigger in analyzer.triggers {
            switch trigger {
            case .port(let proto, let port):
                setSlot(proto: proto, port: port, slot: slot)
            case .portRange(let proto, let range):
                for port in range { setSlot(proto: proto, port: port, slot: slot) }
            }
        }
    }

    private func setSlot(proto: UInt8, port: UInt16, slot: UInt16) {
        switch proto {
        case TransportParser.tcp: tcpPorts[Int(port)] = slot
        case TransportParser.udp: udpPorts[Int(port)] = slot
        default: break
        }
    }

    /// Finds the analyzer for a flow. Both ports are consulted because either
    /// end may be the well-known one, and a flow picked up mid-stream gives no
    /// other clue which is the server.
    public func analyzer(proto: UInt8, sourcePort: UInt16,
                         destinationPort: UInt16) -> PacketAnalyzer? {
        let table: [UInt16]
        switch proto {
        case TransportParser.tcp: table = tcpPorts
        case TransportParser.udp: table = udpPorts
        default: return nil
        }
        let slot = table[Int(destinationPort)] != 0
            ? table[Int(destinationPort)] : table[Int(sourcePort)]
        guard slot > 0 else { return nil }
        return analyzers[Int(slot) - 1]
    }

    public func forEach(_ body: (PacketAnalyzer) -> Void) {
        for analyzer in analyzers { body(analyzer) }
    }
}
