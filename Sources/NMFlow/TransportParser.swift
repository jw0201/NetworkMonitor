//
//  TransportParser.swift
//
//  TCP and UDP header parsing -- enough to key a flow and drive the connection
//  state machine, and nothing more.
//

import NMCore

public struct TCPFlags: OptionSet, Sendable, Hashable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }

    public static let fin = TCPFlags(rawValue: 0x01)
    public static let syn = TCPFlags(rawValue: 0x02)
    public static let rst = TCPFlags(rawValue: 0x04)
    public static let psh = TCPFlags(rawValue: 0x08)
    public static let ack = TCPFlags(rawValue: 0x10)
    public static let urg = TCPFlags(rawValue: 0x20)
    public static let ece = TCPFlags(rawValue: 0x40)
    public static let cwr = TCPFlags(rawValue: 0x80)

    /// A bare SYN: connection initiation.
    public var isSynOnly: Bool { contains(.syn) && !contains(.ack) }
    /// SYN-ACK: the responder accepting.
    public var isSynAck: Bool { contains(.syn) && contains(.ack) }

    /// Flag combinations no legitimate stack emits. Zeek records these as `I`
    /// (inconsistent) and they are a reliable scanner signature -- nmap's more
    /// exotic scan types are built out of exactly these.
    public var isInconsistent: Bool {
        if contains(.syn) && contains(.fin) { return true }
        if contains(.syn) && contains(.rst) { return true }
        if contains(.fin) && contains(.rst) { return true }
        if rawValue == 0 { return true }                    // NULL scan
        if !contains(.ack) && (contains(.fin) || contains(.urg) || contains(.psh))
            && !contains(.syn) && !contains(.rst) { return true }   // FIN/XMAS scan
        return false
    }

    public var description: String {
        var s = ""
        if contains(.cwr) { s += "C" }
        if contains(.ece) { s += "E" }
        if contains(.urg) { s += "U" }
        if contains(.ack) { s += "A" }
        if contains(.psh) { s += "P" }
        if contains(.rst) { s += "R" }
        if contains(.syn) { s += "S" }
        if contains(.fin) { s += "F" }
        return s.isEmpty ? "." : s
    }
}

public struct L4Info: Sendable {
    public var sourcePort: UInt16
    public var destinationPort: UInt16
    /// Offset of the application payload, relative to the L3 reader start.
    public var payloadOffset: Int
    public var payloadLength: Int

    // TCP only.
    public var flags: TCPFlags = []
    public var sequence: UInt32 = 0
    public var acknowledgement: UInt32 = 0
    public var window: UInt16 = 0
    public var windowScale: UInt8?
    public var maximumSegmentSize: UInt16?

    public var clamped: Bool = false
}

public enum TransportParser {

    public static let icmp: UInt8 = 1
    public static let tcp: UInt8 = 6
    public static let udp: UInt8 = 17
    public static let icmpv6: UInt8 = 58

    /// Parses the L4 header for a protocol that has ports. Returns nil for
    /// protocols we do not key by port (ICMP and anything else), which are
    /// still tracked as flows but keyed on addresses alone.
    public static func parse(proto: UInt8, _ r: inout ByteReader,
                             availableLength: Int) throws -> L4Info? {
        switch proto {
        case tcp: return try parseTCP(&r, availableLength: availableLength)
        case udp: return try parseUDP(&r, availableLength: availableLength)
        default: return nil
        }
    }

    private static func parseTCP(_ r: inout ByteReader, availableLength: Int) throws -> L4Info {
        let start = r.offset
        let available = min(availableLength, r.remaining)
        guard available >= 20 else {
            throw ParseError.truncated(needed: 20, available: available)
        }

        let sourcePort = try r.u16be()
        let destinationPort = try r.u16be()
        let sequence = try r.u32be()
        let acknowledgement = try r.u32be()
        let dataOffsetAndReserved = try r.u8()
        let flags = TCPFlags(rawValue: try r.u8())
        let window = try r.u16be()
        try r.skip(2)                                   // checksum, not verified
        try r.skip(2)                                   // urgent pointer

        let dataOffsetWords = Int(dataOffsetAndReserved >> 4)
        var headerLength = dataOffsetWords * 4
        var clamped = false
        // A data offset below 5 is structurally impossible; above what was
        // captured means truncation, not malice. Clamp rather than reject:
        // the ports and flags are already read, and they are what the flow
        // needs most.
        if headerLength < 20 || headerLength > available {
            headerLength = min(20, available)
            clamped = true
        }

        var windowScale: UInt8?
        var mss: UInt16?
        let optionBytes = headerLength - 20
        if optionBytes > 0, var options = try? r.sub(optionBytes) {
            (mss, windowScale) = parseTCPOptions(&options)
        }

        let consumed = r.offset - start
        if consumed < headerLength, r.remaining >= headerLength - consumed {
            try r.skip(headerLength - consumed)
        }

        let payloadLength = max(0, available - headerLength)
        return L4Info(sourcePort: sourcePort,
                      destinationPort: destinationPort,
                      payloadOffset: start + headerLength,
                      payloadLength: payloadLength,
                      flags: flags,
                      sequence: sequence,
                      acknowledgement: acknowledgement,
                      window: window,
                      windowScale: windowScale,
                      maximumSegmentSize: mss,
                      clamped: clamped)
    }

    /// Reads the two options that matter for interpreting a connection, and
    /// skips the rest.
    ///
    /// The iteration cap is load-bearing: a 40-byte option area filled with
    /// zero-length options would otherwise loop forever.
    private static func parseTCPOptions(_ r: inout ByteReader) -> (UInt16?, UInt8?) {
        var mss: UInt16?
        var windowScale: UInt8?
        var iterations = 0
        let maxIterations = 40

        while r.remaining > 0 && iterations < maxIterations {
            iterations += 1
            guard let kind = try? r.u8() else { break }
            if kind == 0 { break }                      // end of option list
            if kind == 1 { continue }                   // no-op padding
            guard let length = try? r.u8() else { break }
            // Length includes the kind and length bytes themselves, so anything
            // below 2 would not advance the cursor.
            guard length >= 2 else { break }
            let bodyLength = Int(length) - 2
            guard bodyLength <= r.remaining else { break }

            switch kind {
            case 2 where bodyLength == 2:
                mss = try? r.u16be()
            case 3 where bodyLength == 1:
                windowScale = try? r.u8()
            default:
                if (try? r.skip(bodyLength)) == nil { return (mss, windowScale) }
            }
        }
        return (mss, windowScale)
    }

    private static func parseUDP(_ r: inout ByteReader, availableLength: Int) throws -> L4Info {
        let start = r.offset
        let available = min(availableLength, r.remaining)
        guard available >= 8 else {
            throw ParseError.truncated(needed: 8, available: available)
        }

        let sourcePort = try r.u16be()
        let destinationPort = try r.u16be()
        let lengthField = Int(try r.u16be())
        try r.skip(2)                                   // checksum

        var clamped = false
        // The UDP length field covers header plus payload. Under offload it can
        // be 0, and under snaplen truncation it can exceed what was captured.
        var payloadLength = lengthField - 8
        if lengthField == 0 || payloadLength < 0 || payloadLength > available - 8 {
            payloadLength = max(0, available - 8)
            clamped = lengthField != 0
        }

        return L4Info(sourcePort: sourcePort,
                      destinationPort: destinationPort,
                      payloadOffset: start + 8,
                      payloadLength: payloadLength,
                      clamped: clamped)
    }
}
