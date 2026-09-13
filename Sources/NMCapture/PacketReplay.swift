//
//  PacketReplay.swift
//
//  Feeds a saved capture through the exact same decode path as a live one.
//
//  This exists for three reasons, in ascending order of importance:
//
//    1. Verifying the PKTAP decoder needs root exactly ONCE -- to produce a
//       sample file. Everything after that is repeatable without privileges.
//    2. Every crash becomes a regression test: keep the file, replay it.
//    3. Benchmarking the analyzer is only meaningful against identical input,
//       which a live capture can never provide.
//
//  The decode path is shared with CaptureSession deliberately. A replay that
//  used a parallel implementation would verify the wrong thing.
//

import CPktap
import Darwin
import NMCore

public enum ReplayError: Error, CustomStringConvertible {
    case openFailed(String)
    case unsupportedLinkType(Int32)

    public var description: String {
        switch self {
        case .openFailed(let m): return "cannot open capture file: \(m)"
        case .unsupportedLinkType(let dlt):
            return """
                capture file has link type \(dlt); expected \(DLT_PKTAP) (live DLT_PKTAP) \
                or 258 (LINKTYPE_PKTAP in a savefile).
                Capture with: sudo tcpdump -i pktap,all -w file.pcap
                """
        }
    }
}

public final class PacketReplay {

    /// LINKTYPE_PKTAP as recorded in a savefile. Deliberately different from
    /// the live DLT value (149) so that pktap files read identically on every
    /// OS -- see the long comment in the SDK's pcap/dlt.h.
    public static let fileLinkType: Int32 = 258

    private var handle: OpaquePointer?
    public private(set) var linkType: Int32 = -1
    public let path: String

    public init(path: String) throws {
        self.path = path
        var errbuf = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
        guard let h = pcap_open_offline(path, &errbuf) else {
            throw ReplayError.openFailed(String(cString: errbuf))
        }
        let dlt = pcap_datalink(h)
        guard dlt == DLT_PKTAP || dlt == Self.fileLinkType else {
            pcap_close(h)
            throw ReplayError.unsupportedLinkType(dlt)
        }
        self.handle = h
        self.linkType = dlt
    }

    deinit { close() }

    public func close() {
        if let h = handle { pcap_close(h) }
        handle = nil
    }

    private final class Context {
        let handler: (PktapMetadata, ByteReader, Double) -> Void
        var decoded: Int = 0
        var decodeFailures: Int = 0
        var dropRecords: Int = 0
        init(_ h: @escaping (PktapMetadata, ByteReader, Double) -> Void) { handler = h }
    }

    public struct Result: Sendable {
        public var delivered: Int
        public var decoded: Int
        public var decodeFailures: Int
        public var dropRecords: Int
    }

    /// Replays the whole file. The handler sees exactly what a live capture
    /// would, including the same borrowed-memory lifetime rule: the reader is
    /// valid only for the duration of the call.
    @discardableResult
    public func replayAll(handler: @escaping (PktapMetadata, ByteReader, Double) -> Void) -> Result {
        guard let h = handle else { return Result(delivered: 0, decoded: 0, decodeFailures: 0, dropRecords: 0) }
        let ctx = Context(handler)
        let boxed = Unmanaged.passUnretained(ctx).toOpaque()
        // pcap_loop, not pcap_dispatch: on a savefile, dispatch's return value
        // is the count for ONE buffer's worth and comes back as 0 at EOF, which
        // reads as "empty file" when the file was in fact fully processed.
        // pcap_loop with a negative count reads to EOF and returns 0 on success.
        _ = pcap_loop(h, -1, replayTrampoline, boxed.assumingMemoryBound(to: UInt8.self))
        return Result(delivered: ctx.decoded + ctx.decodeFailures + ctx.dropRecords,
                      decoded: ctx.decoded,
                      decodeFailures: ctx.decodeFailures,
                      dropRecords: ctx.dropRecords)
    }

    fileprivate static func handle(_ user: UnsafeMutablePointer<UInt8>?,
                                   _ hdr: UnsafePointer<pcap_pkthdr>?,
                                   _ bytes: UnsafePointer<UInt8>?) {
        guard let user, let hdr, let bytes else { return }
        let ctx = Unmanaged<Context>.fromOpaque(UnsafeRawPointer(user)).takeUnretainedValue()

        let caplen = Int(hdr.pointee.caplen)
        guard caplen > 0 else { return }
        let ts = Double(hdr.pointee.ts.tv_sec) + Double(hdr.pointee.ts.tv_usec) / 1_000_000

        var reader = ByteReader(UnsafeRawPointer(bytes), count: caplen)
        do {
            let meta = try PktapDecoder.decode(&reader)
            if case .drop = meta.kind {
                ctx.dropRecords += 1
                return
            }
            ctx.decoded += 1
            ctx.handler(meta, reader, ts)
        } catch {
            ctx.decodeFailures += 1
        }
    }
}

private let replayTrampoline: @convention(c) (UnsafeMutablePointer<UInt8>?,
                                              UnsafePointer<pcap_pkthdr>?,
                                              UnsafePointer<UInt8>?) -> Void = { user, hdr, bytes in
    PacketReplay.handle(user, hdr, bytes)
}
