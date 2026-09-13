//
//  IPAddress.swift
//
//  One address type covering v4 and v6.
//
//  IN MEMORY every address is 16 bytes, with IPv4 stored v4-mapped
//  (::ffff:a.b.c.d). A single layout means the flow table has one key shape,
//  one hash, and no v4/v6 branch on the packet path.
//
//  ON DISK addresses are written in their NATIVE width -- 4 bytes for v4,
//  16 for v6 -- as a BLOB. Two reasons, and the first one is load-bearing:
//
//    1. SQLite compares BLOBs with memcmp, so a CIDR filter compiles to
//       `addr BETWEEN :lo AND :hi`, which is an INDEX RANGE SCAN. Stored as
//       TEXT, the same filter is a full table scan. On 72M rows/day that is
//       the difference between a query and a coffee break.
//    2. 4 bytes instead of 16 for the common case, twice per conn row.
//
//  The conversion happens at the storage boundary and nowhere else.
//

/// An IPv4 or IPv6 address.
///
/// Storage is the 16 address bytes in network order, packed big-endian:
/// byte 0 is the most significant byte of `hi`, byte 15 the least significant
/// byte of `lo`. That ordering is deliberate -- it makes `(hi, lo)` compare
/// lexicographically in the same order as the raw bytes, so range comparisons
/// for CIDR work on the in-memory form too.
public struct IPAddress: Hashable, Sendable, Comparable {
    public var hi: UInt64
    public var lo: UInt64

    @inlinable
    public init(hi: UInt64, lo: UInt64) {
        self.hi = hi
        self.lo = lo
    }

    /// The IPv4-mapped prefix: 80 zero bits followed by 16 one bits.
    @usableFromInline static let v4MappedPrefix: UInt64 = 0x0000_FFFF_0000_0000

    /// From a host-order 32-bit IPv4 address (i.e. 1.2.3.4 == 0x01020304).
    @inlinable
    public init(v4HostOrder value: UInt32) {
        self.hi = 0
        self.lo = Self.v4MappedPrefix | UInt64(value)
    }

    /// From a network-order 32-bit IPv4 address, which is what `sockaddr_in`
    /// and the IP header both hand you.
    @inlinable
    public init(v4NetworkOrder value: UInt32) {
        self.init(v4HostOrder: UInt32(bigEndian: value))
    }

    /// From 16 address bytes in network order.
    @inlinable
    public init?(v6 bytes: UnsafeRawBufferPointer) {
        guard bytes.count >= 16, let base = bytes.baseAddress else { return nil }
        self.hi = UInt64(bigEndian: base.loadUnaligned(as: UInt64.self))
        self.lo = UInt64(bigEndian: base.loadUnaligned(fromByteOffset: 8, as: UInt64.self))
    }

    @inlinable
    public init(v6 bytes: [UInt8]) {
        precondition(bytes.count == 16, "IPv6 address must be 16 bytes")
        var h: UInt64 = 0, l: UInt64 = 0
        for i in 0..<8 { h = (h << 8) | UInt64(bytes[i]) }
        for i in 8..<16 { l = (l << 8) | UInt64(bytes[i]) }
        self.hi = h
        self.lo = l
    }

    // MARK: - Classification

    /// True when this is a v4-mapped address. Note that `::` and `::1` are NOT
    /// v4-mapped -- the mapping requires the 0xFFFF marker.
    @inlinable
    public var isIPv4: Bool {
        hi == 0 && (lo & 0xFFFF_FFFF_0000_0000) == Self.v4MappedPrefix
    }

    /// The IPv4 address in host order, or nil for a genuine v6 address.
    @inlinable
    public var v4HostOrder: UInt32? {
        isIPv4 ? UInt32(truncatingIfNeeded: lo) : nil
    }

    /// Address family, in the `AF_*` vocabulary the pktap header uses.
    @inlinable
    public var addressFamily: Int32 { isIPv4 ? 2 : 30 }   // AF_INET / AF_INET6

    public var isLoopback: Bool {
        if let v4 = v4HostOrder { return (v4 >> 24) == 127 }
        return hi == 0 && lo == 1
    }

    /// RFC 1918 / RFC 4193 / CGNAT. Used for Zeek's `local_orig` / `local_resp`.
    public var isPrivate: Bool {
        if let v4 = v4HostOrder {
            let a = UInt8(truncatingIfNeeded: v4 >> 24)
            let b = UInt8(truncatingIfNeeded: v4 >> 16)
            if a == 10 { return true }
            if a == 172 && (b & 0xF0) == 16 { return true }
            if a == 192 && b == 168 { return true }
            if a == 100 && (b & 0xC0) == 64 { return true }   // 100.64/10 CGNAT
            return false
        }
        return (hi >> 57) == 0b1111110                        // fc00::/7 unique local
    }

    public var isLinkLocal: Bool {
        if let v4 = v4HostOrder { return (v4 >> 16) == 0xA9FE }   // 169.254/16
        return (hi >> 54) == 0b1111111010                         // fe80::/10
    }

    public var isMulticast: Bool {
        if let v4 = v4HostOrder { return (v4 >> 28) == 0xE }      // 224/4
        return (hi >> 56) == 0xFF
    }

    /// Whether this address belongs to this machine's own networks, in the
    /// sense Zeek's conn.log means by "local".
    public var isLocalScope: Bool { isLoopback || isPrivate || isLinkLocal }

    // MARK: - Comparable, for CIDR range scans

    @inlinable
    public static func < (a: IPAddress, b: IPAddress) -> Bool {
        a.hi == b.hi ? a.lo < b.lo : a.hi < b.hi
    }

    // MARK: - Storage form

    /// The native-width bytes to persist: 4 for v4, 16 for v6.
    public var storageBytes: [UInt8] {
        if let v4 = v4HostOrder {
            return [UInt8(truncatingIfNeeded: v4 >> 24),
                    UInt8(truncatingIfNeeded: v4 >> 16),
                    UInt8(truncatingIfNeeded: v4 >> 8),
                    UInt8(truncatingIfNeeded: v4)]
        }
        var out = [UInt8](repeating: 0, count: 16)
        for i in 0..<8 { out[i] = UInt8(truncatingIfNeeded: hi >> (56 - 8 * UInt64(i))) }
        for i in 0..<8 { out[8 + i] = UInt8(truncatingIfNeeded: lo >> (56 - 8 * UInt64(i))) }
        return out
    }

    /// Reconstructs from the persisted form. Width decides the family, which is
    /// why the two are never mixed in one column's semantics.
    public init?(storageBytes bytes: [UInt8]) {
        switch bytes.count {
        case 4:
            let v = (UInt32(bytes[0]) << 24) | (UInt32(bytes[1]) << 16)
                  | (UInt32(bytes[2]) << 8) | UInt32(bytes[3])
            self.init(v4HostOrder: v)
        case 16:
            self.init(v6: bytes)
        default:
            return nil
        }
    }
}

// MARK: - Text

extension IPAddress: CustomStringConvertible {
    public var description: String {
        if let v4 = v4HostOrder {
            return "\(v4 >> 24).\((v4 >> 16) & 0xFF).\((v4 >> 8) & 0xFF).\(v4 & 0xFF)"
        }
        // RFC 5952: lowercase hex, no leading zeros, longest run of zero groups
        // collapsed to "::" (leftmost wins on a tie, and a single zero group is
        // never collapsed).
        var groups = [UInt16](repeating: 0, count: 8)
        for i in 0..<4 { groups[i] = UInt16(truncatingIfNeeded: hi >> (48 - 16 * UInt64(i))) }
        for i in 0..<4 { groups[4 + i] = UInt16(truncatingIfNeeded: lo >> (48 - 16 * UInt64(i))) }

        var bestStart = -1, bestLen = 0
        var runStart = -1, runLen = 0
        for i in 0..<8 {
            if groups[i] == 0 {
                if runStart < 0 { runStart = i; runLen = 1 } else { runLen += 1 }
                if runLen > bestLen { bestLen = runLen; bestStart = runStart }
            } else {
                runStart = -1; runLen = 0
            }
        }
        if bestLen < 2 { bestStart = -1 }

        var parts: [String] = []
        var i = 0
        while i < 8 {
            if i == bestStart {
                parts.append("")
                if i == 0 { parts.append("") }
                i += bestLen
                if i >= 8 { parts.append("") }
                continue
            }
            parts.append(String(groups[i], radix: 16))
            i += 1
        }
        return parts.joined(separator: ":")
    }
}

// MARK: - Parsing

extension IPAddress {
    /// Parses dotted-quad IPv4 or colon-hex IPv6. Returns nil for anything
    /// malformed -- this feeds the filter DSL, so it must reject rather than
    /// guess.
    public init?(_ text: String) {
        if text.contains(".") && !text.contains(":") {
            let parts = text.split(separator: ".", omittingEmptySubsequences: false)
            guard parts.count == 4 else { return nil }
            var v: UInt32 = 0
            for p in parts {
                guard !p.isEmpty, p.count <= 3, let n = UInt16(p), n <= 255 else { return nil }
                v = (v << 8) | UInt32(n)
            }
            self.init(v4HostOrder: v)
            return
        }
        guard text.contains(":") else { return nil }

        // Locate "::" by hand rather than via Foundation's components(separatedBy:).
        // NMCore is on the packet path and stays Foundation-free.
        let chars = Array(text)
        var doubleColonAt: Int? = nil
        var doubleColonCount = 0
        var scan = 0
        while scan + 1 < chars.count {
            if chars[scan] == ":" && chars[scan + 1] == ":" {
                doubleColonCount += 1
                if doubleColonAt == nil { doubleColonAt = scan }
                scan += 2
            } else {
                scan += 1
            }
        }
        guard doubleColonCount <= 1 else { return nil }

        func groups(_ s: ArraySlice<Character>) -> [UInt16]? {
            guard !s.isEmpty else { return [] }
            var out: [UInt16] = []
            var current = ""
            for ch in s {
                if ch == ":" {
                    guard !current.isEmpty, current.count <= 4,
                          let n = UInt16(current, radix: 16) else { return nil }
                    out.append(n)
                    current = ""
                } else {
                    current.append(ch)
                }
            }
            guard !current.isEmpty, current.count <= 4,
                  let n = UInt16(current, radix: 16) else { return nil }
            out.append(n)
            return out
        }

        var all: [UInt16]
        if let dc = doubleColonAt {
            guard let head = groups(chars[0..<dc]),
                  let tail = groups(chars[(dc + 2)...]),
                  head.count + tail.count <= 7 else { return nil }
            all = head + [UInt16](repeating: 0, count: 8 - head.count - tail.count) + tail
        } else {
            guard let g = groups(chars[0...]), g.count == 8 else { return nil }
            all = g
        }
        guard all.count == 8 else { return nil }

        var h: UInt64 = 0, l: UInt64 = 0
        for i in 0..<4 { h = (h << 16) | UInt64(all[i]) }
        for i in 4..<8 { l = (l << 16) | UInt64(all[i]) }
        self.init(hi: h, lo: l)
    }
}

// MARK: - CIDR

/// An address range, stored as inclusive bounds so it compiles directly to a
/// SQL `BETWEEN` against the BLOB column.
public struct IPPrefix: Sendable, Hashable {
    public let lower: IPAddress
    public let upper: IPAddress
    public let isIPv4: Bool

    /// Parses "10.0.0.0/8", "192.168.1.0/24", "2001:db8::/32".
    public init?(_ text: String) {
        let parts = text.split(separator: "/", maxSplits: 1)
        guard parts.count == 2,
              let base = IPAddress(String(parts[0])),
              let bits = Int(parts[1]) else { return nil }

        let v4 = base.isIPv4
        let width = v4 ? 32 : 128
        guard bits >= 0, bits <= width else { return nil }

        if v4 {
            guard let host = base.v4HostOrder else { return nil }
            let mask: UInt32 = bits == 0 ? 0 : ~UInt32(0) << (32 - bits)
            self.lower = IPAddress(v4HostOrder: host & mask)
            self.upper = IPAddress(v4HostOrder: (host & mask) | ~mask)
        } else {
            let hiBits = min(bits, 64)
            let loBits = max(0, bits - 64)
            let hiMask: UInt64 = hiBits == 0 ? 0 : ~UInt64(0) << (64 - hiBits)
            let loMask: UInt64 = loBits == 0 ? 0 : ~UInt64(0) << (64 - loBits)
            let lh = base.hi & hiMask, ll = base.lo & loMask
            self.lower = IPAddress(hi: lh, lo: ll)
            self.upper = IPAddress(hi: lh | ~hiMask, lo: ll | ~loMask)
        }
        self.isIPv4 = v4
    }

    public func contains(_ a: IPAddress) -> Bool {
        a.isIPv4 == isIPv4 && a >= lower && a <= upper
    }
}
