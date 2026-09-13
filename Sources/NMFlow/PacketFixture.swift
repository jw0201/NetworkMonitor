//
//  PacketFixture.swift
//
//  Builds IPv4/IPv6 + TCP/UDP packets.
//
//  In the library rather than the test target for the same reason as
//  PktapFixture: the flow layer needs to be drivable with no capture code and
//  no privileges, for tests, benchmarks and crash reproduction alike.
//

import NMCore

public struct PacketFixture {

    public struct TCPSegment {
        public var source: IPAddress
        public var sourcePort: UInt16
        public var destination: IPAddress
        public var destinationPort: UInt16
        public var flags: TCPFlags
        public var sequence: UInt32
        public var acknowledgement: UInt32
        public var window: UInt16
        public var payload: [UInt8]

        public init(source: IPAddress, sourcePort: UInt16,
                    destination: IPAddress, destinationPort: UInt16,
                    flags: TCPFlags, sequence: UInt32 = 1,
                    acknowledgement: UInt32 = 0, window: UInt16 = 65535,
                    payload: [UInt8] = []) {
            self.source = source
            self.sourcePort = sourcePort
            self.destination = destination
            self.destinationPort = destinationPort
            self.flags = flags
            self.sequence = sequence
            self.acknowledgement = acknowledgement
            self.window = window
            self.payload = payload
        }
    }

    /// Builds an IPv4 packet carrying a TCP segment.
    public static func ipv4TCP(_ s: TCPSegment,
                               totalLengthOverride: UInt16? = nil,
                               fragmentOffset: UInt16 = 0,
                               moreFragments: Bool = false) -> [UInt8] {
        let tcp = tcpHeader(s)
        let total = 20 + tcp.count
        var p = [UInt8]()
        p.reserveCapacity(total)

        p.append(0x45)                                  // IPv4, IHL 5
        p.append(0)                                     // DSCP/ECN
        let length = totalLengthOverride ?? UInt16(total)
        p.append(UInt8(length >> 8)); p.append(UInt8(length & 0xFF))
        p.append(0); p.append(0)                        // identification
        var flagsField = fragmentOffset / 8
        if moreFragments { flagsField |= 0x2000 }
        p.append(UInt8(flagsField >> 8)); p.append(UInt8(flagsField & 0xFF))
        p.append(64)                                    // TTL
        p.append(6)                                     // TCP
        p.append(0); p.append(0)                        // checksum, not computed
        p.append(contentsOf: addressBytes(s.source))
        p.append(contentsOf: addressBytes(s.destination))
        p.append(contentsOf: tcp)
        return p
    }

    public static func ipv4UDP(source: IPAddress, sourcePort: UInt16,
                               destination: IPAddress, destinationPort: UInt16,
                               payload: [UInt8] = [],
                               lengthOverride: UInt16? = nil) -> [UInt8] {
        var udp = [UInt8]()
        udp.append(UInt8(sourcePort >> 8)); udp.append(UInt8(sourcePort & 0xFF))
        udp.append(UInt8(destinationPort >> 8)); udp.append(UInt8(destinationPort & 0xFF))
        let udpLength = lengthOverride ?? UInt16(8 + payload.count)
        udp.append(UInt8(udpLength >> 8)); udp.append(UInt8(udpLength & 0xFF))
        udp.append(0); udp.append(0)                    // checksum
        udp.append(contentsOf: payload)

        var p = [UInt8]()
        p.append(0x45); p.append(0)
        let total = UInt16(20 + udp.count)
        p.append(UInt8(total >> 8)); p.append(UInt8(total & 0xFF))
        p.append(0); p.append(0)
        p.append(0); p.append(0)
        p.append(64)
        p.append(17)                                    // UDP
        p.append(0); p.append(0)
        p.append(contentsOf: addressBytes(source))
        p.append(contentsOf: addressBytes(destination))
        p.append(contentsOf: udp)
        return p
    }

    /// Builds an IPv6 packet carrying a TCP segment, optionally behind a chain
    /// of extension headers.
    public static func ipv6TCP(_ s: TCPSegment,
                               extensionHeaders: [UInt8] = []) -> [UInt8] {
        let tcp = tcpHeader(s)
        var chain = [UInt8]()
        var nextHeader: UInt8 = 6                       // TCP
        // Build the chain backwards so each header points at the one after it.
        for type in extensionHeaders.reversed() {
            var header = [UInt8]()
            header.append(nextHeader)
            header.append(0)                            // length: one 8-octet unit
            header.append(contentsOf: [UInt8](repeating: 0, count: 6))
            chain = header + chain
            nextHeader = type
        }

        var p = [UInt8]()
        p.append(0x60); p.append(0); p.append(0); p.append(0)
        let payloadLength = UInt16(chain.count + tcp.count)
        p.append(UInt8(payloadLength >> 8)); p.append(UInt8(payloadLength & 0xFF))
        p.append(nextHeader)
        p.append(64)                                    // hop limit
        p.append(contentsOf: s.source.storageBytes)
        p.append(contentsOf: s.destination.storageBytes)
        p.append(contentsOf: chain)
        p.append(contentsOf: tcp)
        return p
    }

    private static func tcpHeader(_ s: TCPSegment) -> [UInt8] {
        var t = [UInt8]()
        t.append(UInt8(s.sourcePort >> 8)); t.append(UInt8(s.sourcePort & 0xFF))
        t.append(UInt8(s.destinationPort >> 8)); t.append(UInt8(s.destinationPort & 0xFF))
        for shift in [24, 16, 8, 0] { t.append(UInt8((s.sequence >> UInt32(shift)) & 0xFF)) }
        for shift in [24, 16, 8, 0] { t.append(UInt8((s.acknowledgement >> UInt32(shift)) & 0xFF)) }
        t.append(0x50)                                  // data offset 5 words
        t.append(s.flags.rawValue)
        t.append(UInt8(s.window >> 8)); t.append(UInt8(s.window & 0xFF))
        t.append(0); t.append(0)                        // checksum
        t.append(0); t.append(0)                        // urgent pointer
        t.append(contentsOf: s.payload)
        return t
    }

    private static func addressBytes(_ a: IPAddress) -> [UInt8] {
        let bytes = a.storageBytes
        return bytes.count == 4 ? bytes : Array(bytes.suffix(4))
    }
}
