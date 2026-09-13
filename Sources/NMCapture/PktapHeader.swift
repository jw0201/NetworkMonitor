//
//  PktapHeader.swift
//
//  Decoding of the macOS PKTAP metadata header that precedes every packet
//  captured from the `pktap` pseudo-interface.
//
//  IMPORTANT: these fields are a kernel struct copied out verbatim, NOT wire
//  data. They are in HOST byte order. Reading them big-endian is a classic and
//  silent mistake -- pth_pid would come out as a huge number and process
//  attribution would quietly produce nothing.
//

import CPktap
import NMCore

/// What the kernel is telling us this record contains.
public enum PktapRecordKind: Sendable {
    case packet
    /// The kernel is reporting that it dropped packets. There is no frame to
    /// parse; feed this straight into the drop counters.
    case drop
    case none
}

/// Decoded PKTAP metadata. Strings are copied out, so this is safe to keep;
/// the frame it describes is not.
public struct PktapMetadata: Sendable {
    public var headerLength: Int
    public var kind: PktapRecordKind
    public var dlt: UInt32
    public var ifname: String
    public var rawFlags: UInt32
    public var protocolFamily: UInt32
    public var framePreLength: Int
    public var framePostLength: Int
    public var pid: Int32
    public var comm: String
    public var svc: UInt32
    public var ifType: UInt16
    public var ifUnit: UInt16
    public var epid: Int32
    public var ecomm: String

    /// Present only when the header is long enough (>= 124 bytes).
    public var flowID: UInt32?
    public var ipProto: UInt32?
    /// Mach-O UUID of the binary behind `pid`. This is what makes pid reuse
    /// detectable: same pid + different uuid means the pid was recycled.
    public var uuid: UUIDBytes?
    public var euuid: UUIDBytes?

    /// The socket-owning pid, or nil when the kernel had no attribution.
    ///
    /// Observed live: `pth_pid` is -1 for packets the kernel cannot attribute
    /// (forwarded traffic, some inbound packets arriving before a socket is
    /// associated). Callers must treat that as "unknown" rather than as a pid.
    public var attributedPID: Int32? { pid > 0 ? pid : nil }

    /// The effective pid, or nil when there is no delegation.
    ///
    /// Observed live: `pth_epid` is -1 on the majority of packets -- the kernel
    /// only populates it when the traffic really is being carried on another
    /// process's behalf. Apple's tcpdump correspondingly prints `eproc` only
    /// when it differs from `proc`.
    public var effectivePID: Int32? { epid > 0 && epid != pid ? epid : nil }

    /// Whether the kernel says this packet's real owner is `epid`, not `pid`.
    /// True for traffic proxied by nsurlsessiond / mDNSResponder / trustd on
    /// behalf of an application. Preserving this is the single biggest
    /// advantage pktap gives us over every other capture method.
    public var isProcessDelegated: Bool {
        rawFlags & UInt32(NM_PTH_FLAG_PROC_DELEGATED) != 0
    }

    /// The kernel flagged this as a TCP retransmission. Free and more accurate
    /// than inferring it from sequence numbers.
    public var isRetransmit: Bool {
        rawFlags & UInt32(NM_PTH_FLAG_REXMIT) != 0
    }

    /// True when this packet was seen on the loopback interface, where the
    /// kernel taps the same packet twice (once per endpoint). Byte accounting
    /// must count only one of the two copies or every localhost byte doubles.
    public var isLoopback: Bool { ifType == UInt16(IFT_LOOP) }

    /// Direction according to the flag bits.
    ///
    /// The flag VALUES are unverified on this system -- see the warning in
    /// CPktap.h. `DirectionCalibration` resolves the ambiguity empirically at
    /// startup; prefer its result over this property for anything that affects
    /// stored byte counts.
    public var flaggedDirection: PacketDirection {
        let inBit = rawFlags & UInt32(NM_PTH_FLAG_DIR_IN) != 0
        let outBit = rawFlags & UInt32(NM_PTH_FLAG_DIR_OUT) != 0
        // Exactly one bit must be set. Both or neither means our constants are
        // wrong, and saying "unknown" is far better than picking one.
        switch (inBit, outBit) {
        case (true, false): return .inbound
        case (false, true): return .outbound
        default: return .unknown
        }
    }

    /// Byte offset from the start of the pktap record to the first byte of the
    /// IP header.
    ///
    /// This is the fast path and the reason pktap beats raw BPF: the kernel
    /// already tells us how many link-layer bytes precede L3, so we never have
    /// to dissect Ethernet/NULL/RAW framing just to find the IP header.
    public var l3Offset: Int { headerLength + framePreLength }
}

public struct UUIDBytes: Sendable, Hashable {
    public var bytes: (UInt64, UInt64)
    public var isZero: Bool { bytes.0 == 0 && bytes.1 == 0 }
    public static func == (a: UUIDBytes, b: UUIDBytes) -> Bool { a.bytes == b.bytes }
    public func hash(into h: inout Hasher) { h.combine(bytes.0); h.combine(bytes.1) }
}

public enum PktapDecodeError: Error, Sendable {
    case tooShort(Int)
    case implausibleHeaderLength(UInt32, caplen: Int)
    case unrecognizedVersion
    /// A PKTAP v2 header was seen. We never opt into v2, so this means the OS
    /// changed its default. Handled, but loudly.
    case version2(PktapMetadata)
}

public enum PktapDecoder {

    /// Field offsets within the v1 header. Mirrored by _Static_asserts in shim.c.
    private enum Off {
        static let length = 0, typeNext = 4, dlt = 8, ifname = 12
        static let flags = 36, protoFamily = 40, framePre = 44, framePost = 48
        static let pid = 52, comm = 56, svc = 76, ifType = 80, ifUnit = 82
        static let epid = 84, ecomm = 88, flowID = 108, ipProto = 112
        static let tstamp = 116, uuid = 124, euuid = 140
    }

    /// Decodes the metadata header at the start of a captured pktap record.
    ///
    /// `reader` must be positioned at byte 0 of the record and scoped to
    /// exactly `caplen` bytes.
    public static func decode(_ r: inout ByteReader) throws -> PktapMetadata {
        guard r.count >= 24 else { throw PktapDecodeError.tooShort(r.count) }

        // -- version discrimination ------------------------------------------
        //
        // In v1, bytes 0..3 are pth_length and bytes 4..7 are pth_type_next,
        // which is 0, 1 or 2. In v2, byte 0 is a one-byte length and bytes 4..7
        // are two offset bytes plus the low/high halves of a 16-bit DLT, which
        // cannot form a little-endian value <= 2 for any real packet. So
        // pth_type_next is a strong discriminator.
        var probe = try r.reader(at: 0, count: min(8, r.count))
        let lengthWord = try probe.u32le()
        let typeWord = try probe.u32le()

        let looksV1 = lengthWord >= UInt32(NM_PKTAP_MIN_HDR_LEN)
            && lengthWord <= UInt32(r.count)
            && typeWord <= 2

        guard looksV1 else {
            if r.count >= 28 {
                let firstByte = try r.peek(0)
                if firstByte >= 28 && Int(firstByte) <= r.count {
                    throw PktapDecodeError.unrecognizedVersion  // v2 shape; see decodeV2
                }
            }
            throw PktapDecodeError.implausibleHeaderLength(lengthWord, caplen: r.count)
        }

        let hdrLen = Int(lengthWord)

        // Everything below reads a field ONLY if the wire-reported header length
        // actually covers it. Never sizeof(). Older macOS shipped shorter
        // headers and future ones may append fields.
        func has(_ offset: Int, _ size: Int) -> Bool { hdrLen >= offset + size }

        var h = try r.reader(at: 0, count: hdrLen)

        let kind: PktapRecordKind
        switch typeWord {
        case UInt32(NM_PTH_TYPE_PACKET): kind = .packet
        case UInt32(NM_PTH_TYPE_DROP): kind = .drop
        default: kind = .none
        }

        try h.seek(to: Off.dlt)
        let dlt = try h.u32le()

        try h.seek(to: Off.ifname)
        let ifname = try h.cString(Int(NM_PKTAP_IFXNAMESIZE))

        try h.seek(to: Off.flags)
        let flags = try h.u32le()
        let protoFamily = try h.u32le()
        let framePre = Int(try h.u32le())
        let framePost = Int(try h.u32le())
        let pid = Int32(bitPattern: try h.u32le())

        try h.seek(to: Off.comm)
        let comm = try h.cString(Int(MAXCOMLEN) + 1)

        try h.seek(to: Off.svc)
        let svc = try h.u32le()
        let ifType = try h.u16le()
        let ifUnit = try h.u16le()
        let epid = Int32(bitPattern: try h.u32le())

        try h.seek(to: Off.ecomm)
        let ecomm = try h.cString(Int(MAXCOMLEN) + 1)

        var flowID: UInt32?
        var ipProto: UInt32?
        if has(Off.flowID, 4) {
            try h.seek(to: Off.flowID)
            flowID = try h.u32le()
        }
        if has(Off.ipProto, 4) {
            try h.seek(to: Off.ipProto)
            ipProto = try h.u32le()
        }

        var uuid: UUIDBytes?
        var euuid: UUIDBytes?
        if has(Off.uuid, 16) {
            try h.seek(to: Off.uuid)
            uuid = UUIDBytes(bytes: (try h.u64be(), try h.u64be()))
        }
        if has(Off.euuid, 16) {
            try h.seek(to: Off.euuid)
            euuid = UUIDBytes(bytes: (try h.u64be(), try h.u64be()))
        }

        // Sanity-clamp the frame offsets against what was actually captured.
        // A bogus framePreLength must never push the L3 offset past the buffer.
        let safePre = (framePre >= 0 && hdrLen + framePre <= r.count) ? framePre : 0
        let safePost = (framePost >= 0 && framePost <= r.count) ? framePost : 0

        return PktapMetadata(
            headerLength: hdrLen,
            kind: kind,
            dlt: dlt,
            ifname: ifname,
            rawFlags: flags,
            protocolFamily: protoFamily,
            framePreLength: safePre,
            framePostLength: safePost,
            pid: pid,
            comm: comm,
            svc: svc,
            ifType: ifType,
            ifUnit: ifUnit,
            epid: epid,
            ecomm: ecomm,
            flowID: flowID,
            ipProto: ipProto,
            uuid: uuid,
            euuid: euuid
        )
    }
}
