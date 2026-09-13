//
//  CaptureSession.swift
//
//  Opening and draining a live PKTAP capture.
//
//  Two decisions here dominate the daemon's drop rate:
//
//  1. debug.bpf_maxbufsize defaults to 512 KB on macOS. That holds roughly 310
//     full-size pktap packets -- about 4 ms of gigabit traffic. We raise it at
//     startup (we are root) because no amount of userspace cleverness recovers
//     from a kernel ring that small.
//
//  2. The pcap callback does the absolute minimum. While it runs, pcap_dispatch
//     is iterating the kernel buffer in place, so every microsecond spent in
//     the callback is a microsecond the kernel cannot refill. Parsing belongs
//     on the analyzer thread, never here.
//

import CPktap
import Darwin
import NMCore

public struct CaptureConfig: Sendable {
    /// Device string. "pktap,all" asks Apple's libpcap to clone a pktap
    /// interface tapping every interface, including loopback and tunnels.
    public var device: String = "pktap,all"

    /// Snaplen counts the 156-byte pktap header too.
    ///  - 320   lightweight: headers only, no TLS visibility
    ///  - 2048  balanced (default): fits a typical ClientHello segment
    ///  - 65535 full fidelity, ~40x the buffer pressure
    public var snaplen: Int32 = 2048

    /// Requested kernel buffer. The BPF ceiling is raised to match; if the
    /// kernel still refuses, libpcap halves until BIOCSBLEN succeeds.
    public var bufferSize: Int32 = 16 * 1024 * 1024

    /// Read timeout in milliseconds.
    ///
    /// Not the conventional 1000. With a 16 MB buffer a gigabit link fills in
    /// ~150 ms; with the 512 KB fallback it fills in ~4 ms. 20 ms keeps the
    /// fallback path from overflowing on timeout alone while still batching
    /// (one wakeup per batch instead of per packet).
    public var timeoutMs: Int32 = 20

    /// Immediate mode wakes the reader per packet. At 80 kpps that is 80,000
    /// syscall returns per second, which pins a core and thermally throttles a
    /// laptop. Off by design.
    public var immediateMode: Bool = false

    public init() {}
}

public enum CaptureError: Error, CustomStringConvertible {
    case createFailed(String)
    case activateFailed(code: Int32, message: String)
    case unexpectedLinkType(got: Int32, available: [Int32])
    case notRoot

    public var description: String {
        switch self {
        case .createFailed(let m): return "pcap_create failed: \(m)"
        case .activateFailed(let c, let m): return "pcap_activate failed (\(c)): \(m)"
        case .unexpectedLinkType(let got, let available):
            let list = available.map { "\($0)\($0 == DLT_PKTAP ? " (PKTAP)" : "")" }
                                .joined(separator: ", ")
            return """
                capture device returned DLT \(got), expected \(DLT_PKTAP) (DLT_PKTAP/DLT_USER2).
                Link types this device offers: \(list.isEmpty ? "(none reported)" : list)
                Without PKTAP framing there is no per-packet process attribution.
                """
        case .notRoot:
            return "packet capture requires root: /dev/bpf* is mode 0600 root:wheel"
        }
    }
}

/// Cumulative capture counters. `pcap_stats` values are cumulative since
/// activate on macOS, so callers diff successive samples rather than reading
/// them as rates.
public struct CaptureStats: Sendable, Equatable {
    /// Packets delivered to us.
    public var received: UInt32 = 0
    /// Dropped by the kernel because the BPF ring was full. The number that matters.
    public var kernelDropped: UInt32 = 0
    /// Dropped by the NIC/driver before BPF. Nearly always 0 on pktap.
    public var interfaceDropped: UInt32 = 0
    /// Records where the kernel explicitly told us it dropped packets.
    public var kernelDropRecords: UInt64 = 0
    /// Records we could not decode. Ours to fix.
    public var decodeFailures: UInt64 = 0

    public init() {}
}

public final class CaptureSession {

    private var handle: OpaquePointer?
    public let config: CaptureConfig
    public private(set) var linkType: Int32 = -1
    public private(set) var bpfCeiling = BPFCeiling(before: 0, after: 0, requested: 0)
    /// Every link type the activated device offers. Diagnostic: if PKTAP is
    /// missing from this list, the problem is the device, not our request.
    public private(set) var availableLinkTypes: [Int32] = []
    /// Non-zero if pcap_set_want_pktap was refused.
    public private(set) var pktapRequestRC: Int32 = 0

    public init(config: CaptureConfig = CaptureConfig()) {
        self.config = config
    }

    deinit {
        if let h = handle { pcap_close(h) }
    }

    // MARK: - BPF ceiling

    /// The outcome of trying to raise the kernel's BPF buffer ceiling.
    ///
    /// Reported explicitly rather than swallowed, because it is the single
    /// biggest determinant of the drop rate and because it MAY NOT BE
    /// PERMITTED: `debug.*` sysctls are candidates for SIP protection, in which
    /// case even root cannot change this and 512 KB -- roughly 4 ms of gigabit
    /// traffic -- is a hard ceiling we have to design around.
    public struct BPFCeiling: Sendable {
        public var before: Int
        public var after: Int
        public var requested: Int
        /// True when the write was refused. Not fatal, but it changes the
        /// tuning: the read timeout has to drop and the snaplen has to shrink.
        public var refused: Bool { after < requested && after == before }
        public var alreadySufficient: Bool { before >= requested }

        public var explanation: String {
            if alreadySufficient { return "already \(before) bytes, no change needed" }
            if refused {
                return """
                    REFUSED -- still \(after) bytes. Even as root this sysctl could not be
                    raised, most likely because SIP protects debug.* Compensating: shorter
                    read timeout and a smaller snaplen. Expect drops under heavy traffic,
                    and trust the drop counters rather than the byte totals.
                    """
            }
            return "raised \(before) -> \(after) bytes"
        }
    }

    /// Raises debug.bpf_maxbufsize so pcap_set_buffer_size is not silently
    /// clamped to the 512 KB default.
    @discardableResult
    public static func raiseBPFBufferCeiling(to wanted: Int) -> BPFCeiling {
        var current: Int32 = 0
        var size = MemoryLayout<Int32>.size
        guard sysctlbyname("debug.bpf_maxbufsize", &current, &size, nil, 0) == 0 else {
            return BPFCeiling(before: 0, after: 0, requested: wanted)
        }
        if Int(current) >= wanted {
            return BPFCeiling(before: Int(current), after: Int(current), requested: wanted)
        }

        var target = Int32(wanted)
        _ = sysctlbyname("debug.bpf_maxbufsize", nil, nil, &target, MemoryLayout<Int32>.size)

        var after: Int32 = current
        size = MemoryLayout<Int32>.size
        _ = sysctlbyname("debug.bpf_maxbufsize", &after, &size, nil, 0)
        return BPFCeiling(before: Int(current), after: Int(after), requested: wanted)
    }

    // MARK: - Open

    public func open() throws {
        guard geteuid() == 0 else { throw CaptureError.notRoot }

        bpfCeiling = Self.raiseBPFBufferCeiling(to: Int(config.bufferSize))

        // If the kernel would not give us a bigger ring, stop asking it to
        // batch: a smaller buffer overflows on the timeout alone.
        let effectiveTimeout = bpfCeiling.refused ? min(config.timeoutMs, 2) : config.timeoutMs

        var errbuf = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))

        guard let h = config.device.withCString({ dev in
            pcap_create(dev, &errbuf)
        }) else {
            throw CaptureError.createFailed(String(cString: errbuf))
        }

        // PKTAP framing is OPT-IN, and this is the call that asks for it.
        //
        // Without it, `pcap_create("pktap,all")` succeeds, activates cleanly and
        // hands back DLT_RAW (12) -- bare IP packets with no metadata at all.
        // Everything appears to work while silently discarding the process
        // attribution that is the entire reason for capturing this way.
        //
        // pcap_set_want_pktap is exported from Apple's libpcap but is absent
        // from the public headers, so it is declared in CPktap.h. Its absence
        // from a future libpcap would be a link error, not a silent failure.
        let wantRC = pcap_set_want_pktap(h, 1)
        if wantRC != 0 {
            // Not fatal on its own: pcap_set_datalink after activate is the
            // fallback. Recorded so the failure is visible if that also fails.
            pktapRequestRC = wantRC
        }

        // Granular setup. pcap_open_live cannot express any of this: it forces
        // promiscuous mode on and offers no control over buffer size,
        // immediate mode, or timestamp precision.
        pcap_set_snaplen(h, config.snaplen)
        pcap_set_promisc(h, 0)          // pktap taps the host stack; promisc is meaningless
        pcap_set_timeout(h, effectiveTimeout)
        pcap_set_immediate_mode(h, config.immediateMode ? 1 : 0)
        pcap_set_buffer_size(h, config.bufferSize)
        // BPF has no nanosecond mode; asking for it would just fail.
        pcap_set_tstamp_precision(h, PCAP_TSTAMP_PRECISION_MICRO)

        let rc = pcap_activate(h)
        if rc < 0 {
            let msg = String(cString: pcap_geterr(h))
            pcap_close(h)
            throw CaptureError.activateFailed(code: rc, message: msg)
        }
        // rc > 0 is a warning (e.g. promisc not supported); the handle is usable.

        var dlt = pcap_datalink(h)
        availableLinkTypes = Self.linkTypes(of: h)

        // Fallback: ask for PKTAP explicitly, but only if the device actually
        // offers it. Calling pcap_set_datalink for a value absent from the
        // device's list returns PCAP_ERROR, so checking first avoids aborting a
        // capture that might still be usable.
        if dlt != DLT_PKTAP && availableLinkTypes.contains(DLT_PKTAP) {
            if pcap_set_datalink(h, DLT_PKTAP) == 0 {
                dlt = pcap_datalink(h)
            }
        }

        guard dlt == DLT_PKTAP else {
            let available = availableLinkTypes
            pcap_close(h)
            throw CaptureError.unexpectedLinkType(got: dlt, available: available)
        }

        self.handle = h
        self.linkType = dlt
    }

    public func close() {
        if let h = handle { pcap_close(h) }
        handle = nil
    }

    /// The DLT values a handle offers. libpcap allocates the list, so it must
    /// be freed with pcap_free_datalinks.
    private static func linkTypes(of handle: OpaquePointer) -> [Int32] {
        var list: UnsafeMutablePointer<Int32>?
        let n = pcap_list_datalinks(handle, &list)
        guard n > 0, let list else { return [] }
        defer { pcap_free_datalinks(list) }
        return Array(UnsafeBufferPointer(start: list, count: Int(n)))
    }

    public func stats() -> CaptureStats? {
        guard let h = handle else { return nil }
        var ps = pcap_stat()
        guard pcap_stats(h, &ps) == 0 else { return nil }
        var s = CaptureStats()
        s.received = ps.ps_recv
        s.kernelDropped = ps.ps_drop
        s.interfaceDropped = ps.ps_ifdrop
        return s
    }

    // MARK: - Draining

    /// Context handed to the C callback. Passed unretained: the session
    /// outlives every dispatch call by construction.
    private final class DispatchContext {
        var handler: (PktapMetadata, ByteReader, Double) -> Void
        var decodeFailures: UInt64 = 0
        var dropRecords: UInt64 = 0
        init(_ h: @escaping (PktapMetadata, ByteReader, Double) -> Void) { handler = h }
    }

    /// Drains up to `count` packets (or until `pcap_breakloop`) on the calling
    /// thread. Returns the number of packets libpcap delivered.
    ///
    /// The handler receives a reader scoped to exactly the captured bytes. That
    /// memory belongs to the kernel buffer and is valid ONLY for the duration
    /// of the call -- copy anything that must outlive it.
    @discardableResult
    public func drain(count: Int32,
                      handler: @escaping (PktapMetadata, ByteReader, Double) -> Void)
        -> (delivered: Int32, decodeFailures: UInt64, dropRecords: UInt64)
    {
        guard let h = handle else { return (0, 0, 0) }
        let ctx = DispatchContext(handler)
        let boxed = Unmanaged.passUnretained(ctx).toOpaque()
        let n = pcap_dispatch(h, count, pktapTrampoline,
                              boxed.assumingMemoryBound(to: UInt8.self))
        return (n, ctx.decodeFailures, ctx.dropRecords)
    }

    /// The one place in this project where a raw pointer is dereferenced
    /// outside ByteReader, and it is confined to constructing the reader.
    fileprivate static func handle(_ user: UnsafeMutablePointer<UInt8>?,
                                   _ hdr: UnsafePointer<pcap_pkthdr>?,
                                   _ bytes: UnsafePointer<UInt8>?) {
        guard let user, let hdr, let bytes else { return }
        let ctx = Unmanaged<DispatchContext>
            .fromOpaque(UnsafeRawPointer(user)).takeUnretainedValue()

        let caplen = Int(hdr.pointee.caplen)
        guard caplen > 0 else { return }

        // hdr.pointee.ts is a timeval; Apple's pcap_pkthdr also carries a
        // trailing comment[256], which is exactly why this struct is imported
        // from the real header rather than redeclared in Swift.
        let ts = Double(hdr.pointee.ts.tv_sec) + Double(hdr.pointee.ts.tv_usec) / 1_000_000

        var reader = ByteReader(UnsafeRawPointer(bytes), count: caplen)
        do {
            let meta = try PktapDecoder.decode(&reader)
            if case .drop = meta.kind {
                ctx.dropRecords += 1
                return
            }
            ctx.handler(meta, reader, ts)
        } catch {
            ctx.decodeFailures += 1
        }
    }
}

/// Top-level @convention(c) trampoline. Swift closures cannot be
/// @convention(c) if they capture, so the context travels through the
/// user pointer instead.
private let pktapTrampoline: @convention(c) (UnsafeMutablePointer<UInt8>?,
                                             UnsafePointer<pcap_pkthdr>?,
                                             UnsafePointer<UInt8>?) -> Void = { user, hdr, bytes in
    CaptureSession.handle(user, hdr, bytes)
}
