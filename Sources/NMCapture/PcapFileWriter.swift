//
//  PcapFileWriter.swift
//
//  Writes libpcap savefiles ourselves rather than going through pcap_dump.
//
//  The format is 24 bytes of file header and 16 bytes per packet, so this is
//  about 120 lines -- and writing it ourselves buys three things that matter:
//
//    1. CONTROL OVER THE LINK TYPE, which turns out to be a real fork -- see
//       PcapLinkType below. The two viewers disagree about which value a pktap
//       savefile should carry, and we have to pick per destination.
//    2. Direct control over rotation, fsync policy and segment indexing.
//    3. No dependency on Apple's 280-byte pcap_pkthdr for output.
//
//  pcapng was considered and rejected: it would let us carry Apple's Process
//  Information Blocks, but the pktap header ALREADY carries the pid and process
//  name inline, so the extra format complexity buys nothing.
//

import Darwin
import Foundation

public enum PcapWriteError: Error, CustomStringConvertible {
    case cannotCreate(String, errno: Int32)
    case writeFailed(errno: Int32)

    public var description: String {
        switch self {
        case .cannotCreate(let p, let e): return "cannot create \(p): \(String(cString: strerror(e)))"
        case .writeFailed(let e): return "write failed: \(String(cString: strerror(e)))"
        }
    }
}

/// Which link-type value to record in a pktap savefile.
///
/// These are NOT interchangeable, and the choice was settled by experiment on
/// this machine rather than by reading the header comments:
///
///   sudo tcpdump -r file.pcap -k -n
///     link type 149 -> "(en0, proc Safari:842, eproc Mail:904, svc BE, out)"
///     link type 258 -> "UNSUPPORTED", followed by a raw hex dump
///
/// libpcap's own dlt.h argues that a savefile should carry 258 so pktap files
/// read identically on every OS, and Wireshark's pktap dissector is keyed on
/// 258. But Apple's tcpdump -- version 4.99.1 (Apple 158), the only pcap viewer
/// present on a stock Mac -- still only understands 149, exactly as dlt.h
/// predicted back in the Mavericks era.
///
/// So: the ring writes 149, because a capture nobody on the machine can open is
/// worthless, and export for Wireshark rewrites the four header bytes. The
/// packet records themselves are byte-identical either way.
public enum PcapLinkType: UInt32, Sendable {
    /// 149. Apple aliases DLT_PKTAP to DLT_USER2. Apple's tcpdump dissects this
    /// fully, including process names and direction.
    case appleLive = 149
    /// 258. LINKTYPE_PKTAP, what Wireshark expects. Apple's tcpdump reports
    /// UNSUPPORTED for it.
    case wiresharkFile = 258
}

public final class PcapFileWriter {

    /// Retained for the file-format tests and for callers that want the raw value.
    public static let linkTypePKTAP: UInt32 = PcapLinkType.wiresharkFile.rawValue

    /// Little-endian magic with microsecond timestamps. The byte order of the
    /// magic tells a reader how to interpret every other field, so writing it
    /// in host order and letting the reader adapt is correct and standard.
    private static let magicMicroseconds: UInt32 = 0xA1B2_C3D4

    private var fd: Int32 = -1
    public let path: String
    public let linkType: UInt32
    public let snaplen: UInt32

    public private(set) var bytesWritten: Int = 0
    public private(set) var packetsWritten: Int = 0
    public private(set) var firstTimestamp: Double?
    public private(set) var lastTimestamp: Double?

    /// Userspace buffering, flushed at 1 MB. The kernel is perfectly capable of
    /// buffering too, but batching here keeps the write() syscall count off the
    /// capture thread's critical path.
    private var buffer: [UInt8] = []
    private static let flushThreshold = 1 << 20

    public convenience init(path: String,
                            linkType: PcapLinkType,
                            snaplen: UInt32 = 2048) throws {
        try self.init(path: path, rawLinkType: linkType.rawValue, snaplen: snaplen)
    }

    /// Defaults to 149 so the resulting file opens in the tcpdump that ships
    /// with every Mac. Pass `.wiresharkFile` when exporting for Wireshark.
    public init(path: String,
                rawLinkType: UInt32 = PcapLinkType.appleLive.rawValue,
                snaplen: UInt32 = 2048) throws {
        self.path = path
        self.linkType = rawLinkType
        self.snaplen = snaplen

        // 0600: capture files contain every user's traffic metadata and, with
        // payload capture on, plaintext bytes.
        fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0o600)
        guard fd >= 0 else { throw PcapWriteError.cannotCreate(path, errno: errno) }

        buffer.reserveCapacity(Self.flushThreshold + 4096)
        writeFileHeader()
    }

    deinit { try? close() }

    private func writeFileHeader() {
        appendU32(Self.magicMicroseconds)
        appendU16(2)              // version major
        appendU16(4)              // version minor
        appendU32(0)              // thiszone: timestamps are UTC, so always 0
        appendU32(0)              // sigfigs: unused in practice
        appendU32(snaplen)
        appendU32(linkType)
    }

    /// Appends one packet. `originalLength` is the on-wire length before
    /// truncation to snaplen -- keeping it distinct from the captured length is
    /// what lets a reader know data was cut rather than silently short.
    public func write(timestamp: Double,
                      originalLength: Int,
                      bytes: UnsafeRawBufferPointer) throws {
        let seconds = Int64(timestamp.rounded(.down))
        let micros = Int64(((timestamp - Double(seconds)) * 1_000_000).rounded())

        appendU32(UInt32(truncatingIfNeeded: seconds))
        appendU32(UInt32(truncatingIfNeeded: micros))
        appendU32(UInt32(bytes.count))
        appendU32(UInt32(originalLength))
        buffer.append(contentsOf: bytes)

        packetsWritten += 1
        if firstTimestamp == nil { firstTimestamp = timestamp }
        lastTimestamp = timestamp

        if buffer.count >= Self.flushThreshold { try flush() }
    }

    /// Byte offset the next packet will be written at. This is what the segment
    /// index records per flow -- a byte RANGE per (flow, file), never a row per
    /// packet.
    public var currentOffset: Int { bytesWritten + buffer.count }

    public func flush() throws {
        guard !buffer.isEmpty, fd >= 0 else { return }
        try buffer.withUnsafeBytes { raw in
            var offset = 0
            while offset < raw.count {
                let n = Darwin.write(fd, raw.baseAddress! + offset, raw.count - offset)
                if n < 0 {
                    if errno == EINTR { continue }
                    throw PcapWriteError.writeFailed(errno: errno)
                }
                offset += n
            }
        }
        bytesWritten += buffer.count
        buffer.removeAll(keepingCapacity: true)
    }

    /// fsync happens here and nowhere else. Per-packet durability would cost
    /// more than the capture itself, and a segment lost to a crash is a far
    /// smaller problem than a capture that cannot keep up.
    public func close() throws {
        guard fd >= 0 else { return }
        try flush()
        fsync(fd)
        Darwin.close(fd)
        fd = -1
    }

    /// Rewrites an existing savefile's link-type field in place.
    ///
    /// The packet records are identical between 149 and 258, so converting a
    /// capture for a different viewer is a four-byte edit rather than a rewrite.
    public static func rewriteLinkType(path: String, to linkType: PcapLinkType) throws {
        let fd = open(path, O_WRONLY)
        guard fd >= 0 else { throw PcapWriteError.cannotCreate(path, errno: errno) }
        defer { Darwin.close(fd) }
        var value = linkType.rawValue.littleEndian
        // The `network` field sits at byte offset 20 of the 24-byte file header.
        let written = withUnsafeBytes(of: &value) { pwrite(fd, $0.baseAddress, 4, 20) }
        guard written == 4 else { throw PcapWriteError.writeFailed(errno: errno) }
    }

    // MARK: - Little-endian append

    private func appendU16(_ v: UInt16) {
        buffer.append(UInt8(truncatingIfNeeded: v))
        buffer.append(UInt8(truncatingIfNeeded: v >> 8))
    }

    private func appendU32(_ v: UInt32) {
        buffer.append(UInt8(truncatingIfNeeded: v))
        buffer.append(UInt8(truncatingIfNeeded: v >> 8))
        buffer.append(UInt8(truncatingIfNeeded: v >> 16))
        buffer.append(UInt8(truncatingIfNeeded: v >> 24))
    }
}
