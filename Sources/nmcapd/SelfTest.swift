//
//  SelfTest.swift
//
//  `nmcapd --self-test` -- the gate that everything else in the capture layer
//  depends on.
//
//  net/pktap.h is not in the SDK, so struct nm_pktap_header is a
//  reconstruction. Static asserts prove it is self-consistent with the SDK's
//  types; only a live capture can prove it matches what the kernel emits.
//  This mode prints the decoded fields so they can be diffed against:
//
//      sudo tcpdump -i pktap,all -k -n -c 20
//
//  It also calibrates the direction flag empirically, because the PTH_FLAG_DIR_*
//  values are the least certain constants in the whole project and XNU's own
//  comments about them are known to be transposed.
//

import CPktap
import Darwin
import Foundation
import NMCapture
import NMCore

// MARK: - Local address set, for direction calibration

/// Every address assigned to a local interface. A packet whose source is in
/// this set originated here -- which is ground truth for "outbound",
/// independent of whatever the flag bits claim.
struct LocalAddresses {
    private var v4 = Set<UInt32>()
    private var v6 = Set<[UInt8]>()

    init() {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let start = head else { return }
        defer { freeifaddrs(start) }

        var cur: UnsafeMutablePointer<ifaddrs>? = start
        while let ifa = cur {
            defer { cur = ifa.pointee.ifa_next }
            guard let sa = ifa.pointee.ifa_addr else { continue }
            switch Int32(sa.pointee.sa_family) {
            case AF_INET:
                sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                    v4.insert($0.pointee.sin_addr.s_addr)
                }
            case AF_INET6:
                sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) {
                    var a = $0.pointee.sin6_addr
                    let bytes = withUnsafeBytes(of: &a) { Array($0) }
                    v6.insert(bytes)
                }
            default: break
            }
        }
    }

    var count: Int { v4.count + v6.count }

    func containsV4(_ networkOrder: UInt32) -> Bool { v4.contains(networkOrder) }
    func containsV6(_ bytes: [UInt8]) -> Bool { v6.contains(bytes) }
}

/// Minimal source/destination extraction, for diagnostics only. The real
/// IPParser lives in NMAnalyzers; this exists so the self-test can establish
/// direction ground truth without depending on the analyzer layer.
struct ProbeAddresses {
    var src: String
    var dst: String
    var srcIsLocal: Bool
}

func probeAddresses(_ meta: PktapMetadata, _ record: ByteReader,
                    _ local: LocalAddresses) -> ProbeAddresses? {
    guard var r = try? record.reader(at: meta.l3Offset,
                                     count: record.count - meta.l3Offset) else { return nil }
    guard let first = try? r.peek(0) else { return nil }
    let version = first >> 4

    if version == 4 {
        guard (try? r.skip(12)) != nil else { return nil }
        guard let s = try? r.u32le(), let d = try? r.u32le() else { return nil }
        return ProbeAddresses(src: ipv4String(s), dst: ipv4String(d),
                              srcIsLocal: local.containsV4(s))
    } else if version == 6 {
        guard (try? r.skip(8)) != nil else { return nil }
        guard let sb = try? r.bytes(16) else { return nil }
        let s = Array(sb)
        guard let db = try? r.bytes(16) else { return nil }
        let d = Array(db)
        return ProbeAddresses(src: ipv6String(s), dst: ipv6String(d),
                              srcIsLocal: local.containsV6(s))
    }
    return nil
}

private func ipv4String(_ networkOrder: UInt32) -> String {
    let b = withUnsafeBytes(of: networkOrder) { Array($0) }
    return "\(b[0]).\(b[1]).\(b[2]).\(b[3])"
}

private func ipv6String(_ bytes: [UInt8]) -> String {
    guard bytes.count == 16 else { return "?" }
    var groups: [String] = []
    for i in stride(from: 0, to: 16, by: 2) {
        groups.append(String(format: "%x", (UInt16(bytes[i]) << 8) | UInt16(bytes[i + 1])))
    }
    return groups.joined(separator: ":")
}

// MARK: - Self test

/// Accumulates decoded packets and reports on them.
///
/// Shared by live capture and file replay on purpose: a replay that used a
/// separate analysis path would verify the wrong thing.
final class PktapInspection {
    private let local = LocalAddresses()
    private var seen = 0
    private var noDirectionBits = 0
    private var flagVsLocalSource: [UInt32: (local: Int, remote: Int)] = [:]
    private var interfaces: [String: Int] = [:]
    private var delegatedCount = 0
    private var unattributed = 0
    private let printRows: Int

    init(printRows: Int = 20) { self.printRows = printRows }

    var count: Int { seen }
    var localAddressCount: Int { local.count }

    func printHeader() {
        print(pad("#", 5) + pad("iface", 8) + pad("dir", 5) + pad("pid", 7) + pad("comm", 18)
              + pad("epid", 7) + pad("ecomm", 18) + pad("dlt", 5) + "src -> dst")
        print(String(repeating: "-", count: 108))
    }

    func observe(_ meta: PktapMetadata, _ record: ByteReader) {
        seen += 1
        interfaces[meta.ifname, default: 0] += 1
        if meta.isProcessDelegated { delegatedCount += 1 }
        if meta.attributedPID == nil { unattributed += 1 }

        let addrs = probeAddresses(meta, record, local)
        let dirBits = meta.rawFlags & 0x0003
        if dirBits == 0 { noDirectionBits += 1 }
        if let a = addrs {
            var e = flagVsLocalSource[dirBits] ?? (0, 0)
            if a.srcIsLocal { e.local += 1 } else { e.remote += 1 }
            flagVsLocalSource[dirBits] = e
        }

        guard seen <= printRows else { return }

        let dirLabel: String
        switch meta.flaggedDirection {
        case .inbound: dirLabel = "in"
        case .outbound: dirLabel = "out"
        case .unknown: dirLabel = "?"
        }
        // The kernel writes -1 for "no attribution", which is not a pid and
        // must not be rendered as one.
        let pidText = meta.attributedPID.map(String.init) ?? "-"
        let epidText = meta.effectivePID.map(String.init) ?? "-"
        let ecommText = meta.effectivePID == nil ? "-" : meta.ecomm

        print(pad("\(seen)", 5) + pad(meta.ifname, 8) + pad(dirLabel, 5)
              + pad(pidText, 7) + pad(meta.comm.isEmpty ? "-" : meta.comm, 18)
              + pad(epidText, 7) + pad(ecommText, 18)
              + pad("\(meta.dlt)", 5)
              + (addrs.map { "\($0.src) -> \($0.dst)" } ?? "(not IP)"))
    }

    /// Reports what the flag bits actually mean, established empirically.
    ///
    /// The PTH_FLAG_DIR_* values are the least certain constants in the project
    /// -- net/pktap.h is not in the SDK and XNU's own comments on these two
    /// macros are known to be transposed relative to their names. Rather than
    /// trust the reconstruction, correlate against ground truth: a packet whose
    /// SOURCE address belongs to this host went out.
    func report() {
        print("\nInterfaces seen")
        print(String(repeating: "-", count: 108))
        for (name, n) in interfaces.sorted(by: { $0.value > $1.value }) {
            print("  \(pad(name, 12)) \(n) packet(s)")
        }
        if unattributed > 0 {
            print("\n  \(unattributed) packet(s) had no process attribution (pth_pid == -1).")
            print("  Expected for forwarded traffic and for inbound packets that arrive")
            print("  before the kernel has associated a socket. Flow attribution latches")
            print("  on the first packet that carries a real pid rather than recording -1.")
        }
        if delegatedCount > 0 {
            print("\n  \(delegatedCount) packet(s) carried PTH_FLAG_PROC_DELEGATED "
                  + "(traffic proxied on another process's behalf).")
            print("  That flag is the reason this app can say \"Safari used 2 GB\" "
                  + "rather than \"nsurlsessiond used 2 GB\".")
        }

        print("\nDirection flag calibration")
        print(String(repeating: "-", count: 108))
        print("A packet whose SOURCE is one of this host's own addresses is outbound.")
        print("That is ground truth, independent of what the flag bits mean.\n")

        // The method only works if BOTH kinds of packet were observed. If no
        // packet had a locally-sourced address, every bit pattern trivially
        // reads as "inbound" -- a confident answer resting on no evidence. Say
        // so instead.
        let totalLocal = flagVsLocalSource.values.reduce(0) { $0 + $1.local }
        let totalRemote = flagVsLocalSource.values.reduce(0) { $0 + $1.remote }
        guard totalLocal > 0 && totalRemote > 0 else {
            print("  CANNOT CALIBRATE: \(totalLocal) packet(s) had a local source address "
                  + "and \(totalRemote) had a remote one.")
            print("  Both are needed. Capture live traffic on a real interface "
                  + "(browsing, or `ping -c 20 1.1.1.1`) rather than a synthetic fixture.")
            return
        }

        var resolved = false
        for (bits, counts) in flagVsLocalSource.sorted(by: { $0.key < $1.key }) {
            let total = counts.local + counts.remote
            guard total > 0 else { continue }
            let pct = 100.0 * Double(counts.local) / Double(total)
            let verdict: String
            if pct > 90 { verdict = "=> this bit pattern means OUTBOUND"; resolved = true }
            else if pct < 10 { verdict = "=> this bit pattern means INBOUND"; resolved = true }
            else { verdict = "=> INCONCLUSIVE (needs more traffic)" }
            print("  flags & 0x3 = 0x\(String(bits, radix: 16)) : "
                  + "\(counts.local) local-source, \(counts.remote) remote-source "
                  + "(\(String(Int(pct.rounded())))%)  \(verdict)")
        }
        if !resolved && seen > 0 {
            print("\n  Not enough varied traffic to decide. Capture again while "
                  + "browsing or running `ping -c 20 1.1.1.1`.")
        }
        if noDirectionBits > 0 {
            print("\n  WARNING: \(noDirectionBits) packet(s) had neither direction bit set.")
            print("  The NM_PTH_FLAG_DIR_* constants in CPktap.h are probably wrong.")
        }
    }
}

func printLayoutBanner() {
    let layout = nm_pktap_layout()
    print("""
    pktap_header       \(layout.header_size) bytes  (static asserts passed at build time)
    pcap_pkthdr        \(layout.pcap_pkthdr_size) bytes  (portable libpcap is 24 -- never redeclare this)
    DLT_PKTAP (live)   \(layout.dlt_pktap_live)
    LINKTYPE (file)    \(layout.linktype_pktap_file)
    """)
}

// MARK: - Replay (no root required)

func runReplay(path: String, printRows: Int) -> Int32 {
    print("""
    NetworkMonitor capture replay
    =============================
    file  \(path)
    """)
    printLayoutBanner()

    let replay: PacketReplay
    do {
        replay = try PacketReplay(path: path)
    } catch {
        print("\n\(error)")
        return 1
    }
    defer { replay.close() }

    print("file link type     \(replay.linkType)"
          + (replay.linkType == 258 ? "  (LINKTYPE_PKTAP -- Wireshark will show process names)"
                                    : "  (live DLT_PKTAP)"))

    let inspector = PktapInspection(printRows: printRows)
    print("local addresses    \(inspector.localAddressCount) across all interfaces\n")
    inspector.printHeader()

    let result = replay.replayAll { meta, record, _ in
        inspector.observe(meta, record)
    }

    inspector.report()

    print("""

    Decode summary
    \(String(repeating: "-", count: 108))
      packets in file   \(result.delivered)
      decoded           \(result.decoded)
      decode failures   \(result.decodeFailures)
      kernel drop recs  \(result.dropRecords)
    """)

    if result.decodeFailures > 0 {
        print("""

          \(result.decodeFailures) packet(s) failed to decode. If this is more than a
          handful, the pktap header reconstruction in CPktap.h is wrong for this
          macOS version and nothing downstream can be trusted.
        """)
        return 1
    }

    print("""

    Now diff the table above against Apple's own decoder:
        tcpdump -r \(path) -k -n -c \(printRows)
    Interface, direction, pid, process name and effective pid must all agree.
    """)
    return result.decoded > 0 ? 0 : 1
}

func runSelfTest(packetCount: Int32, waitSeconds: Double = 15) -> Int32 {
    print("""
    NetworkMonitor capture self-test
    ================================
    """)
    printLayoutBanner()

    let session = CaptureSession()
    do {
        try session.open()
    } catch {
        print("\nopen failed: \(error)")
        if case CaptureError.unexpectedLinkType(let got, _) = error, got == 12 {
            print("""

            DLT 12 is DLT_RAW: the pktap pseudo-interface exists but is handing back
            bare IP with no metadata. PKTAP framing is opt-in; CaptureSession.open()
            requests it with pcap_set_want_pktap before activating, and falls back to
            pcap_set_datalink afterwards. Both failing means this device genuinely
            cannot produce PKTAP framing.
            """)
        }
        if case CaptureError.notRoot = error {
            print("""

            Packet capture needs root. Claude Code's `!` prefix has no TTY, so sudo
            cannot prompt there -- run this in a normal Terminal window instead:

                cd \(FileManager.default.currentDirectoryPath)
                sudo Tools/verify-pktap.sh 20

            Or capture once and replay without root afterwards:

                sudo tcpdump -i pktap,all -c 200 -w /tmp/pktap.pcap
                sudo chown $USER /tmp/pktap.pcap
                .build/debug/nmcapd --replay /tmp/pktap.pcap
            """)
        }
        return 1
    }
    defer { session.close() }

    print("""
    BPF ceiling        \(session.bpfCeiling.explanation)
    device             pktap,all   snaplen \(session.config.snaplen)
    link types offered \(session.availableLinkTypes.map(String.init).joined(separator: ", "))
    """)
    if session.pktapRequestRC != 0 {
        print("    NOTE: pcap_set_want_pktap returned \(session.pktapRequestRC); "
              + "fell back to pcap_set_datalink.")
    }

    let inspector = PktapInspection(printRows: Int(packetCount))
    print("local addresses    \(inspector.localAddressCount) across all interfaces\n")
    inspector.printHeader()

    var failures: UInt64 = 0
    var drops: UInt64 = 0

    // pcap_dispatch returns 0 whenever the read timeout expires with nothing
    // buffered, which with a 20 ms timeout happens constantly on an idle link.
    // Treating that as "no traffic" gave up after twenty MILLISECONDS. Poll
    // until either enough packets arrive or a real deadline passes.
    let deadline = Date().addingTimeInterval(waitSeconds)
    var timedOut = false
    while inspector.count < Int(packetCount) {
        if Date() >= deadline {
            timedOut = true
            break
        }
        let r = session.drain(count: packetCount - Int32(inspector.count)) { meta, record, _ in
            inspector.observe(meta, record)
        }
        failures += r.decodeFailures
        drops += r.dropRecords
        if r.delivered < 0 { break }   // pcap_breakloop or a handle error
    }

    if inspector.count == 0 {
        print("(no packets in \(Int(waitSeconds))s -- generate traffic, e.g. `ping -c 30 1.1.1.1`)")
    } else if timedOut {
        print("\n(stopped after \(Int(waitSeconds))s with \(inspector.count) of \(packetCount) packets)")
    }

    inspector.report()

    if let s = session.stats() {
        print("""

        Capture stats
        \(String(repeating: "-", count: 108))
          received          \(s.received)
          kernel dropped    \(s.kernelDropped)   (BPF ring overflow)
          interface dropped \(s.interfaceDropped)
          decode failures   \(failures)
          kernel drop recs  \(drops)
        """)
    }

    print("""

    Next: diff the table above against
        sudo tcpdump -i pktap,all -k -n -c \(packetCount)
    Fields must agree packet for packet before building on this decoder.
    """)

    return inspector.count > 0 ? 0 : 1
}

/// Left-justified column padding. Avoids String(format:) so this file needs no
/// Foundation import -- the capture path stays free of it.
private func pad(_ s: String, _ width: Int) -> String {
    s.count >= width ? String(s.prefix(width - 1)) + " "
                     : s + String(repeating: " ", count: width - s.count)
}

