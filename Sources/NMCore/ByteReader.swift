//
//  ByteReader.swift
//
//  The only sanctioned way to read packet bytes anywhere in this project.
//
//  WHY THIS TYPE EXISTS
//  --------------------
//  nmcapd runs as root and parses attacker-controlled bytes. The obvious Swift
//  reflex -- "UnsafeRawBufferPointer is bounds-checked, so I'm safe" -- is
//  WRONG in exactly the configuration we ship. UnsafeRawBufferPointer's
//  subscript bounds check is a _debugPrecondition, which is compiled out under
//  -O. A release build gets NO automatic protection on the packet path.
//
//  So every read goes through this type, which performs its own explicit,
//  always-on bounds check. No parser in this codebase is permitted to touch a
//  raw pointer directly. That is a lint rule, not a style preference.
//
//  LIFETIME
//  --------
//  A ByteReader borrows memory it does not own. For packets that memory is a
//  slot in the capture ring, valid only until both consumers advance past it.
//  NEVER store a ByteReader (or a slice obtained from one) beyond the call that
//  received it. Anything an analyzer needs to keep across packets must be
//  copied into flow-owned storage.
//

/// A parse failure. Always recoverable: the caller drops the packet, bumps a
/// counter, and moves on. A malformed packet must never take down the daemon.
public enum ParseError: Error, Sendable, Equatable {
    /// Fewer bytes remain than the read requires.
    case truncated(needed: Int, available: Int)
    /// Structurally invalid content (a reserved bit pattern, an impossible tag).
    case malformed(String)
    /// A hard iteration/size cap was hit. Distinct from `malformed` because it
    /// usually means "hostile", not "buggy sender", and is counted separately.
    case limitExceeded(String)
}

/// A bounds-checked cursor over a region of raw memory.
///
/// Reads are little- or big-endian explicit; there is no host-order accessor,
/// because "host order" in a packet parser is almost always a bug. The two
/// exceptions (DLT_NULL's address family word, which really is host order) call
/// `u32le`/`u32be` explicitly and comment why.
public struct ByteReader {
    @usableFromInline let base: UnsafeRawPointer
    /// Total bytes readable from `base`. Never mutated after init.
    @usableFromInline let limit: Int
    /// Bytes consumed so far. Invariant: 0 <= _offset <= limit. The setter is
    /// deliberately not public -- a caller able to set a negative _offset would
    /// defeat `need()`'s bounds check and produce an out-of-bounds read.
    @usableFromInline var _offset: Int

    /// Bytes consumed so far.
    @inlinable public var offset: Int { _offset }

    @inlinable
    public init(_ base: UnsafeRawPointer, count: Int) {
        precondition(count >= 0, "ByteReader count must be non-negative")
        self.base = base
        self.limit = count
        self._offset = 0
    }

    /// Fails only for a buffer with a nil base address, which `UnsafeRawBufferPointer`
    /// permits when empty.
    @inlinable
    public init?(_ buffer: UnsafeRawBufferPointer) {
        guard let p = buffer.baseAddress else { return nil }
        self.init(p, count: buffer.count)
    }

    @inlinable public var remaining: Int { limit - _offset }
    @inlinable public var isAtEnd: Bool { _offset >= limit }
    @inlinable public var count: Int { limit }

    /// The single bounds check every read funnels through.
    ///
    /// Written as `limit - _offset >= n` rather than the more natural
    /// `_offset + n <= limit` deliberately: the latter can overflow when `n`
    /// comes from a wire length field, and an overflowed check passes.
    /// `_offset` is an invariant 0...limit, so `limit - _offset` cannot overflow.
    @inline(__always)
    @usableFromInline
    func need(_ n: Int) throws {
        guard n >= 0 else { throw ParseError.malformed("negative read length \(n)") }
        guard limit - _offset >= n else {
            throw ParseError.truncated(needed: n, available: limit - _offset)
        }
    }

    // MARK: - Fixed-width reads

    @inlinable
    public mutating func u8() throws -> UInt8 {
        try need(1)
        defer { _offset += 1 }
        return base.loadUnaligned(fromByteOffset: _offset, as: UInt8.self)
    }

    @inlinable
    public mutating func u16be() throws -> UInt16 {
        try need(2)
        defer { _offset += 2 }
        return UInt16(bigEndian: base.loadUnaligned(fromByteOffset: _offset, as: UInt16.self))
    }

    @inlinable
    public mutating func u16le() throws -> UInt16 {
        try need(2)
        defer { _offset += 2 }
        return UInt16(littleEndian: base.loadUnaligned(fromByteOffset: _offset, as: UInt16.self))
    }

    /// 24-bit big-endian. TLS handshake message lengths use this.
    @inlinable
    public mutating func u24be() throws -> UInt32 {
        try need(3)
        let a = UInt32(base.loadUnaligned(fromByteOffset: _offset, as: UInt8.self))
        let b = UInt32(base.loadUnaligned(fromByteOffset: _offset + 1, as: UInt8.self))
        let c = UInt32(base.loadUnaligned(fromByteOffset: _offset + 2, as: UInt8.self))
        _offset += 3
        return (a << 16) | (b << 8) | c
    }

    @inlinable
    public mutating func u32be() throws -> UInt32 {
        try need(4)
        defer { _offset += 4 }
        return UInt32(bigEndian: base.loadUnaligned(fromByteOffset: _offset, as: UInt32.self))
    }

    @inlinable
    public mutating func u32le() throws -> UInt32 {
        try need(4)
        defer { _offset += 4 }
        return UInt32(littleEndian: base.loadUnaligned(fromByteOffset: _offset, as: UInt32.self))
    }

    @inlinable
    public mutating func u64be() throws -> UInt64 {
        try need(8)
        defer { _offset += 8 }
        return UInt64(bigEndian: base.loadUnaligned(fromByteOffset: _offset, as: UInt64.self))
    }

    // MARK: - Cursor movement

    @inlinable
    public mutating func skip(_ n: Int) throws {
        try need(n)
        _offset += n
    }

    /// Absolute seek within this reader's window. Used by DNS name
    /// decompression, which is the only parser that legitimately moves
    /// backwards -- and which enforces its own strictly-decreasing jump rule
    /// on top of this.
    @inlinable
    public mutating func seek(to newOffset: Int) throws {
        guard newOffset >= 0, newOffset <= limit else {
            throw ParseError.malformed("seek to \(newOffset) outside 0...\(limit)")
        }
        _offset = newOffset
    }

    // MARK: - Sub-regions

    /// Consumes `n` bytes and returns a reader scoped to exactly those bytes.
    ///
    /// This is how a length-delimited field is parsed: the sub-reader cannot
    /// read past the field even if the inner parser is buggy, so a bad nested
    /// length can never reach beyond its own extent.
    @inlinable
    public mutating func sub(_ n: Int) throws -> ByteReader {
        try need(n)
        let r = ByteReader(base + _offset, count: n)
        _offset += n
        return r
    }

    /// A reader over an absolute window, without moving this cursor.
    /// Needed for DNS compression pointers, which address the whole message.
    @inlinable
    public func reader(at start: Int, count n: Int) throws -> ByteReader {
        guard start >= 0, n >= 0, start <= limit, limit - start >= n else {
            throw ParseError.truncated(needed: n, available: max(0, limit - max(0, start)))
        }
        return ByteReader(base + start, count: n)
    }

    /// The remaining bytes as a raw buffer, without consuming them.
    /// Valid only for the lifetime of the underlying memory -- see the header note.
    @inlinable
    public var rest: UnsafeRawBufferPointer {
        UnsafeRawBufferPointer(start: base + _offset, count: limit - _offset)
    }

    /// Consumes and returns `n` bytes as a raw buffer.
    @inlinable
    public mutating func bytes(_ n: Int) throws -> UnsafeRawBufferPointer {
        try need(n)
        defer { _offset += n }
        return UnsafeRawBufferPointer(start: base + _offset, count: n)
    }

    // MARK: - Non-consuming inspection

    /// Reads a byte at an _offset relative to the current cursor without moving it.
    @inlinable
    public func peek(_ ahead: Int = 0) throws -> UInt8 {
        guard ahead >= 0, limit - _offset > ahead else {
            throw ParseError.truncated(needed: ahead + 1, available: limit - _offset)
        }
        return base.loadUnaligned(fromByteOffset: _offset + ahead, as: UInt8.self)
    }

    // MARK: - Copies out

    /// Copies up to `max` remaining bytes into caller-owned storage and returns
    /// how many were copied. This is the sanctioned escape from the borrow:
    /// anything that must outlive the packet goes through here.
    @inlinable
    @discardableResult
    public mutating func copyOut(into dest: UnsafeMutableRawBufferPointer, max n: Int) -> Int {
        let avail = min(n, remaining, dest.count)
        guard avail > 0, let d = dest.baseAddress else { return 0 }
        d.copyMemory(from: base + _offset, byteCount: avail)
        _offset += avail
        return avail
    }

    /// Reads `n` bytes as a NUL-terminated ASCII string, stopping at the first
    /// NUL. Non-ASCII bytes are replaced rather than rejected: this is used for
    /// kernel-supplied names (`pth_comm`, `pth_ifname`), where a weird byte is
    /// not worth dropping the packet over.
    @inlinable
    public mutating func cString(_ n: Int) throws -> String {
        let buf = try bytes(n)
        var s = ""
        s.reserveCapacity(n)
        for byte in buf {
            if byte == 0 { break }
            s.append(byte >= 0x20 && byte < 0x7f ? Character(UnicodeScalar(byte)) : "?")
        }
        return s
    }
}
