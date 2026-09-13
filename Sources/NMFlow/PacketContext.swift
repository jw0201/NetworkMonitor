//
//  PacketContext.swift
//
//  What the flow engine needs to know about a packet, independent of where it
//  came from.
//
//  This type exists to keep NMFlow from importing NMCapture. The capture module
//  holds the root-privileged pcap handle and must stay free of the parsing and
//  flow-tracking code, so that splitting the daemon into a small root capturer
//  and an unprivileged analyzer stays a main.swift change. A shared neutral
//  struct is what makes that boundary cost nothing.
//
//  It is also what lets the whole flow layer be driven from a pcap replay, a
//  synthetic generator, or a test fixture with no capture code present at all.
//

import NMCore

public struct PacketContext: Sendable {
    public var timestamp: Timestamp
    public var interfaceName: String
    /// IFT_* value. IFT_LOOP matters: the kernel taps loopback packets twice,
    /// once per endpoint, so counting both doubles every localhost byte.
    public var interfaceType: UInt16
    public var direction: PacketDirection

    /// Socket-owning pid, or nil when the kernel had no attribution. Observed
    /// live as -1 for forwarded traffic and for inbound packets arriving before
    /// a socket is associated.
    public var pid: Int32?
    public var processName: String
    /// The application the traffic is really for, when a proxy process carried
    /// it. Nil in the common case -- delegation is an exception, not the rule.
    public var effectivePID: Int32?
    public var effectiveProcessName: String
    public var uuidHi: UInt64
    public var uuidLo: UInt64

    /// From the kernel's own retransmission flag, which is both cheaper and
    /// more accurate than inferring it from sequence numbers.
    public var isRetransmit: Bool
    public var isDelegated: Bool

    /// Monotonic counter incremented on any capture drop. A flow whose start
    /// and end epochs differ had packets dropped during its lifetime and its
    /// byte counts are approximate.
    public var lossEpoch: UInt64

    /// pcap ring segment this packet was written to, if the ring is running.
    public var pcapSegment: UInt32?

    public init(timestamp: Timestamp,
                interfaceName: String,
                interfaceType: UInt16 = 0,
                direction: PacketDirection = .unknown,
                pid: Int32? = nil,
                processName: String = "",
                effectivePID: Int32? = nil,
                effectiveProcessName: String = "",
                uuidHi: UInt64 = 0,
                uuidLo: UInt64 = 0,
                isRetransmit: Bool = false,
                isDelegated: Bool = false,
                lossEpoch: UInt64 = 0,
                pcapSegment: UInt32? = nil) {
        self.timestamp = timestamp
        self.interfaceName = interfaceName
        self.interfaceType = interfaceType
        self.direction = direction
        self.pid = pid
        self.processName = processName
        self.effectivePID = effectivePID
        self.effectiveProcessName = effectiveProcessName
        self.uuidHi = uuidHi
        self.uuidLo = uuidLo
        self.isRetransmit = isRetransmit
        self.isDelegated = isDelegated
        self.lossEpoch = lossEpoch
        self.pcapSegment = pcapSegment
    }

    /// IFT_LOOP. Loopback packets are tapped twice by the kernel.
    public static let interfaceTypeLoopback: UInt16 = 0x18
    public var isLoopback: Bool { interfaceType == Self.interfaceTypeLoopback }
}
