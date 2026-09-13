//
//  PacketDirection.swift
//

/// Direction of travel relative to this host.
///
/// Verified against live kernel output on macOS 26.6.2: the PKTAP flag word's
/// low two bits are 0x1 for inbound and 0x2 for outbound. That was established
/// empirically by correlating 20 live packets against this host's own interface
/// addresses, because XNU's comments on those two macros are transposed
/// relative to their names.
public enum PacketDirection: UInt8, Sendable {
    case inbound
    case outbound
    /// Neither bit set, or both. Callers must not guess: byte accounting keeps
    /// unknown-direction packets separate so they can be audited rather than
    /// silently attributed to the wrong side.
    case unknown
}
