//
//  IPParser.swift
//
//  IPv4 and IPv6 header parsing.
//
//  Two things make this different from the textbook version, and both come from
//  capturing at the HOST STACK rather than on the wire:
//
//    1. TSO/LRO offload. The kernel hands the NIC one enormous segment and lets
//       hardware split it, so a captured packet can be 64 KB rather than MTU
//       sized, and its IP total-length field is frequently 0 because the value
//       is filled in by the hardware afterwards. A parser that trusts
//       total_length blindly will compute negative payload lengths on a normal
//       machine, not just under attack.
//
//    2. We are parsing bytes an attacker controls, inside a root process. Every
//       length is clamped against what was actually captured, every loop has a
//       hard cap, and nothing is read except through ByteReader.
//

import NMCore

public struct L3Info: Sendable {
    public var source: IPAddress
    public var destination: IPAddress
    /// The upper-layer protocol: IPPROTO_TCP, _UDP, _ICMP, _ICMPV6.
    public var proto: UInt8
    /// Offset of the L4 header, relative to the start of the L3 reader.
    public var payloadOffset: Int
    /// Bytes of L4 header + payload actually available.
    public var payloadLength: Int
    /// On-wire IP bytes, used for throughput accounting. Falls back to the
    /// captured length when the header's own field is unusable.
    public var ipBytes: Int
    public var hopLimit: UInt8
    /// A fragment other than the first. Its L4 header is absent, so it can be
    /// counted toward a flow's bytes but cannot start one.
    public var isNonInitialFragment: Bool
    public var isFragment: Bool
    /// Some length or option was inconsistent and had to be clamped. Surfaced
    /// so counts derived from it can be marked approximate rather than wrong.
    public var clamped: Bool
}

public enum IPParser {

    public static let ipv4: UInt8 = 4
    public static let ipv6: UInt8 = 6

    /// Parses an IP header starting at the reader's current position.
    ///
    /// `reader` must be scoped to exactly the captured L3 bytes. The pktap
    /// header already told us where L3 starts, so no link-layer dissection
    /// happens here.
    public static func parse(_ r: inout ByteReader) throws -> L3Info {
        let first = try r.peek(0)
        switch first >> 4 {
        case ipv4: return try parseV4(&r)
        case ipv6: return try parseV6(&r)
        default:
            throw ParseError.malformed("IP version \(first >> 4)")
        }
    }

    // MARK: - IPv4

    private static func parseV4(_ r: inout ByteReader) throws -> L3Info {
        let available = r.remaining
        let start = r.offset

        let versionIHL = try r.u8()
        let ihl = Int(versionIHL & 0x0F)
        // IHL counts 32-bit words and must cover at least the fixed 20 bytes.
        guard ihl >= 5 else { throw ParseError.malformed("IPv4 IHL \(ihl) < 5") }
        let headerLength = ihl * 4
        guard headerLength <= available else {
            throw ParseError.truncated(needed: headerLength, available: available)
        }

        try r.skip(1)                                  // DSCP/ECN
        let totalLength = Int(try r.u16be())
        try r.skip(2)                                  // identification
        let flagsAndFragment = try r.u16be()
        let hopLimit = try r.u8()
        let proto = try r.u8()
        try r.skip(2)                                  // header checksum, not verified
        let source = IPAddress(v4NetworkOrder: try r.u32le())
        let destination = IPAddress(v4NetworkOrder: try r.u32le())

        // Skip options without interpreting them. They are rare, and a parser
        // for them is attack surface with no payoff for flow tracking.
        let consumed = r.offset - start
        if headerLength > consumed { try r.skip(headerLength - consumed) }

        let moreFragments = flagsAndFragment & 0x2000 != 0
        let fragmentOffset = Int(flagsAndFragment & 0x1FFF) * 8

        // total_length is 0 under TSO, and can exceed what was captured under
        // snaplen truncation. Neither is an error.
        var clamped = false
        var ipBytes = totalLength
        if totalLength == 0 || totalLength > available {
            ipBytes = available
            clamped = totalLength != 0
        }

        var payloadLength = ipBytes - headerLength
        if payloadLength < 0 || payloadLength > available - headerLength {
            payloadLength = max(0, available - headerLength)
            clamped = true
        }

        return L3Info(source: source,
                      destination: destination,
                      proto: proto,
                      payloadOffset: start + headerLength,
                      payloadLength: payloadLength,
                      ipBytes: ipBytes,
                      hopLimit: hopLimit,
                      isNonInitialFragment: fragmentOffset > 0,
                      isFragment: moreFragments || fragmentOffset > 0,
                      clamped: clamped)
    }

    // MARK: - IPv6

    /// Extension header types that carry the standard 8-bit next-header plus
    /// 8-bit length-in-8-octet-units layout.
    private static let hopByHop: UInt8 = 0
    private static let routing: UInt8 = 43
    private static let fragment: UInt8 = 44
    private static let encapsulatingSecurity: UInt8 = 50
    private static let authentication: UInt8 = 51
    private static let noNextHeader: UInt8 = 59
    private static let destinationOptions: UInt8 = 60

    private static func parseV6(_ r: inout ByteReader) throws -> L3Info {
        let available = r.remaining
        let start = r.offset

        try r.skip(4)                                  // version, traffic class, flow label
        let payloadLengthField = Int(try r.u16be())
        var next = try r.u8()
        let hopLimit = try r.u8()

        let srcBytes = try r.bytes(16)
        guard let source = IPAddress(v6: srcBytes) else {
            throw ParseError.malformed("IPv6 source")
        }
        let dstBytes = try r.bytes(16)
        guard let destination = IPAddress(v6: dstBytes) else {
            throw ParseError.malformed("IPv6 destination")
        }

        var clamped = false
        var nonInitialFragment = false
        var isFragment = false

        // Walk the extension header chain. The cap is not a nicety: a crafted
        // chain of self-referential headers is a cheap way to spin a parser
        // forever, and a repeated hop-by-hop header is illegal by RFC 8200.
        var headers = 0
        var sawHopByHop = false
        while headers < Limits.maxIPv6ExtensionHeaders {
            switch next {
            case hopByHop:
                if sawHopByHop && headers > 0 {
                    throw ParseError.malformed("repeated IPv6 hop-by-hop header")
                }
                sawHopByHop = true
                fallthrough
            case routing, destinationOptions, authentication:
                guard r.remaining >= 2 else { clamped = true; next = noNextHeader; break }
                let nextHeader = try r.u8()
                let lengthUnits = Int(try r.u8())
                // Authentication headers count in 4-octet units and exclude two
                // of them; every other type counts 8-octet units excluding one.
                let extensionLength = next == authentication
                    ? (lengthUnits + 2) * 4 - 2
                    : (lengthUnits + 1) * 8 - 2
                guard extensionLength >= 0, extensionLength <= r.remaining else {
                    clamped = true
                    next = noNextHeader
                    break
                }
                try r.skip(extensionLength)
                next = nextHeader
                headers += 1
                continue

            case fragment:
                guard r.remaining >= 8 else { clamped = true; next = noNextHeader; break }
                let nextHeader = try r.u8()
                try r.skip(1)                          // reserved
                let offsetAndFlags = try r.u16be()
                try r.skip(4)                          // identification
                isFragment = true
                nonInitialFragment = (offsetAndFlags & 0xFFF8) != 0
                next = nextHeader
                headers += 1
                continue

            case encapsulatingSecurity:
                // ESP payload is encrypted; there is nothing above it to parse.
                next = encapsulatingSecurity

            default:
                break
            }
            break
        }

        if headers >= Limits.maxIPv6ExtensionHeaders { clamped = true }

        let headerLength = r.offset - start
        var ipBytes = payloadLengthField == 0 ? available : 40 + payloadLengthField
        if ipBytes > available { ipBytes = available; clamped = true }

        var payloadLength = ipBytes - headerLength
        if payloadLength < 0 || payloadLength > available - headerLength {
            payloadLength = max(0, available - headerLength)
            clamped = true
        }

        return L3Info(source: source,
                      destination: destination,
                      proto: next,
                      payloadOffset: start + headerLength,
                      payloadLength: payloadLength,
                      ipBytes: ipBytes,
                      hopLimit: hopLimit,
                      isNonInitialFragment: nonInitialFragment,
                      isFragment: isFragment,
                      clamped: clamped)
    }
}
