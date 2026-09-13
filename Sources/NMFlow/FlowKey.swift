//
//  FlowKey.swift
//
//  The key a flow is looked up by, once per packet.
//
//  Three decisions here are not obvious:
//
//    1. The endpoints are SORTED, so both directions of a conversation hash to
//       the same bucket. Orientation is recovered from a separate flag on the
//       entry. Without this you get two half-flows and every byte count is
//       wrong by half.
//
//    2. The interface is part of the key. The same 5-tuple legitimately appears
//       on utun0 and en0 at once (a VPN carries the inner packet and the outer
//       one is its own conversation), and on lo0 it appears twice per packet.
//
//    3. The hash is seeded per process. That is a SECURITY requirement, not a
//       micro-optimisation: with a fixed, publicly known hash an attacker can
//       craft 5-tuples that all collide into one bucket, turning the flow table
//       into a linked list. That is a denial of service costing the attacker
//       almost nothing.
//

import NMCore

public struct FlowKey: Hashable, Sendable {
    // Endpoints, ordered so the pair is direction-independent.
    public let lowAddressHi: UInt64
    public let lowAddressLo: UInt64
    public let highAddressHi: UInt64
    public let highAddressLo: UInt64
    public let lowPort: UInt16
    public let highPort: UInt16
    public let proto: UInt8
    /// Interned interface index, not a string: the key is compared and hashed
    /// once per packet and a String there would allocate and chase pointers.
    public let interfaceIndex: UInt8
    public let vlan: UInt16

    /// Precomputed, because Hashable's synthesized version calls SipHash once
    /// per stored property and that is measurable at hundreds of thousands of
    /// packets per second.
    private let precomputedHash: Int

    public init(addressA: IPAddress, portA: UInt16,
                addressB: IPAddress, portB: UInt16,
                proto: UInt8, interfaceIndex: UInt8, vlan: UInt16 = 0) {
        // Order by address, then by port. Deterministic and direction-free.
        let aFirst: Bool
        if addressA == addressB {
            aFirst = portA <= portB
        } else {
            aFirst = addressA < addressB
        }

        let low = aFirst ? addressA : addressB
        let high = aFirst ? addressB : addressA
        self.lowAddressHi = low.hi
        self.lowAddressLo = low.lo
        self.highAddressHi = high.hi
        self.highAddressLo = high.lo
        self.lowPort = aFirst ? portA : portB
        self.highPort = aFirst ? portB : portA
        self.proto = proto
        self.interfaceIndex = interfaceIndex
        self.vlan = vlan

        self.precomputedHash = Int(bitPattern: UInt(truncatingIfNeeded: seededHash(
            low.hi &+ high.hi,
            low.lo &+ high.lo,
            UInt64(self.lowPort) | (UInt64(self.highPort) << 16)
                | (UInt64(proto) << 32) | (UInt64(interfaceIndex) << 40)
                | (UInt64(vlan) << 48)
        )))
    }

    /// True when the given endpoint is the one stored as "low", which is how
    /// orientation is recovered after the sort.
    public func isLowEndpoint(address: IPAddress, port: UInt16) -> Bool {
        address.hi == lowAddressHi && address.lo == lowAddressLo && port == lowPort
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(precomputedHash)
    }

    public static func == (a: FlowKey, b: FlowKey) -> Bool {
        a.precomputedHash == b.precomputedHash
            && a.lowAddressHi == b.lowAddressHi && a.lowAddressLo == b.lowAddressLo
            && a.highAddressHi == b.highAddressHi && a.highAddressLo == b.highAddressLo
            && a.lowPort == b.lowPort && a.highPort == b.highPort
            && a.proto == b.proto && a.interfaceIndex == b.interfaceIndex
            && a.vlan == b.vlan
    }

    public var lowAddress: IPAddress { IPAddress(hi: lowAddressHi, lo: lowAddressLo) }
    public var highAddress: IPAddress { IPAddress(hi: highAddressHi, lo: highAddressLo) }
}

/// Interns interface names into small integers.
///
/// Bounded at 255 entries because the index is a UInt8 in the key. A machine
/// with more than 255 simultaneously-active interfaces does not exist; if one
/// did, the overflow entries share index 255 and are merged, which is wrong but
/// bounded -- far better than growing the key.
public struct InterfaceTable: Sendable {
    private var indices: [String: UInt8] = [:]
    private var names: [String] = []

    public init() {}

    public mutating func index(of name: String) -> UInt8 {
        if let i = indices[name] { return i }
        guard names.count < 255 else { return 255 }
        let i = UInt8(names.count)
        indices[name] = i
        names.append(name)
        return i
    }

    public func name(at index: UInt8) -> String {
        Int(index) < names.count ? names[Int(index)] : "?"
    }

    public var count: Int { names.count }
}
