//
//  FlowMode.swift
//
//  `nmcapd --flows` -- capture or replay, run the flow engine, print conn.log.
//
//  This is the first point where the project produces the thing it exists to
//  produce: one row per conversation, with the process that owned it.
//

import CPktap
import Darwin
import Foundation
import NMCapture
import NMCore
import NMFlow

/// Bridges the capture layer's PKTAP metadata to the flow layer's neutral
/// input type. This function is the entire coupling between the two modules --
/// keeping it this small is what lets the daemon later split into a root
/// capturer and an unprivileged analyzer.
func makeContext(_ meta: PktapMetadata, timestamp: Double, lossEpoch: UInt64) -> PacketContext {
    PacketContext(
        timestamp: Timestamp(timestamp * 1_000_000),
        interfaceName: meta.ifname,
        interfaceType: meta.ifType,
        direction: meta.flaggedDirection,
        pid: meta.attributedPID,
        processName: meta.comm,
        effectivePID: meta.effectivePID,
        effectiveProcessName: meta.ecomm,
        uuidHi: meta.uuid?.bytes.0 ?? 0,
        uuidLo: meta.uuid?.bytes.1 ?? 0,
        isRetransmit: meta.isRetransmit,
        isDelegated: meta.isProcessDelegated,
        lossEpoch: lossEpoch
    )
}

private struct FlowPrinter {
    var rows: [ConnRecord] = []
    var reasons: [FlowEndReason] = []

    mutating func add(_ r: ConnRecord, _ reason: FlowEndReason) {
        rows.append(r)
        reasons.append(reason)
    }

    func printTable(limit: Int) {
        print("")
        print(col("ts", 13) + col("proto", 6) + col("originator", 24)
              + col("responder", 24) + col("state", 7) + col("hist", 10)
              + col("orig B", 10) + col("resp B", 10) + "process")
        print(String(repeating: "-", count: 124))

        // Biggest conversations first: that is what a person actually looks for.
        let ordered = rows.enumerated()
            .sorted { $0.element.totalBytes > $1.element.totalBytes }
            .prefix(limit)

        for (_, r) in ordered {
            let proto: String
            switch r.proto {
            case 6: proto = "tcp"
            case 17: proto = "udp"
            case 1: proto = "icmp"
            case 58: proto = "icmp6"
            default: proto = String(r.proto)
            }
            var process = r.exec?.name ?? "-"
            if let proxy = r.proxyExec?.name { process += " (via \(proxy))" }
            if r.captureLossSuspected { process += "  ~approx" }

            print(col(shortTime(r.ts), 13)
                  + col(proto, 6)
                  + col("\(r.origAddr):\(r.origPort)", 24)
                  + col("\(r.respAddr):\(r.respPort)", 24)
                  + col(r.state.rawValue, 7)
                  + col(r.history.isEmpty ? "-" : r.history, 10)
                  + col(bytes(r.origIPBytes), 10)
                  + col(bytes(r.respIPBytes), 10)
                  + process)
        }
        if rows.count > limit {
            print("  ... \(rows.count - limit) more")
        }
    }

    func printSummary(_ engine: FlowEngine) {
        let totalBytes = rows.reduce(Int64(0)) { $0 + $1.totalBytes }

        var byProcess: [String: (bytes: Int64, flows: Int)] = [:]
        for r in rows {
            let name = r.exec?.name ?? "(unattributed)"
            var e = byProcess[name] ?? (0, 0)
            e.bytes += r.totalBytes
            e.flows += 1
            byProcess[name] = e
        }

        print("\nPer-process traffic")
        print(String(repeating: "-", count: 124))
        for (name, e) in byProcess.sorted(by: { $0.value.bytes > $1.value.bytes }).prefix(15) {
            let share = totalBytes > 0 ? 100.0 * Double(e.bytes) / Double(totalBytes) : 0
            print("  " + col(name, 26) + col(bytes(e.bytes), 12)
                  + col("\(e.flows) flow(s)", 14)
                  + String(repeating: "#", count: max(0, Int(share / 2))))
        }

        var byState: [String: Int] = [:]
        for r in rows { byState[r.state.rawValue, default: 0] += 1 }
        print("\nConnection states")
        print(String(repeating: "-", count: 124))
        for (state, n) in byState.sorted(by: { $0.value > $1.value }) {
            print("  " + col(state, 8) + "\(n)  " + explain(state))
        }

        let s = engine.stats
        print("""

        Engine
        \(String(repeating: "-", count: 124))
          packets processed   \(s.packets)
          non-IP / unparsed   \(s.nonIPPackets)
          loopback deduped    \(s.loopbackDeduplicated)
          unknown direction   \(s.unknownDirection)
          packets w/o pid     \(s.unattributed)
          records emitted     \(s.recordsEmitted)
          flows shed (full)   \(s.droppedNoCapacity)
          peak concurrent     \(engine.table.stats.peakActive)
          evicted             \(engine.table.stats.evicted)
        """)
    }

    private func explain(_ state: String) -> String {
        switch state {
        case "SF": return "completed normally"
        case "S0": return "no response -- dead host, filtered port, or a scan"
        case "S1": return "established, still open"
        case "REJ": return "actively refused"
        case "RSTO": return "reset by the originator"
        case "RSTR": return "reset by the responder"
        case "S2": return "originator finished, responder did not"
        case "S3": return "responder finished, originator did not"
        case "SH": return "SYN then FIN, no response -- stealth-scan shape"
        case "OTH": return "picked up mid-stream, no handshake seen"
        default: return ""
        }
    }
}

private func col(_ s: String, _ width: Int) -> String {
    s.count >= width ? String(s.prefix(width - 1)) + " "
                     : s + String(repeating: " ", count: width - s.count)
}

private func bytes(_ n: Int64) -> String {
    if n < 1024 { return "\(n) B" }
    if n < 1024 * 1024 { return String(format: "%.1f KB", Double(n) / 1024) }
    if n < 1024 * 1024 * 1024 { return String(format: "%.1f MB", Double(n) / 1_048_576) }
    return String(format: "%.2f GB", Double(n) / 1_073_741_824)
}

private func shortTime(_ ts: Timestamp) -> String {
    let seconds = ts / 1_000_000
    let h = (seconds % 86400) / 3600, m = (seconds % 3600) / 60, s = seconds % 60
    let ms = (ts % 1_000_000) / 1000
    func p(_ n: Int64, _ w: Int) -> String {
        var t = String(n); while t.count < w { t = "0" + t }; return t
    }
    return "\(p(h,2)):\(p(m,2)):\(p(s,2)).\(p(ms,3))"
}

// MARK: - Replay

func runFlowsFromFile(path: String, limit: Int) -> Int32 {
    let replay: PacketReplay
    do { replay = try PacketReplay(path: path) }
    catch {
        print("\(error)")
        return 1
    }
    defer { replay.close() }

    print("""
    NetworkMonitor flow analysis
    ============================
    file       \(path)
    link type  \(replay.linkType)
    """)

    let engine = FlowEngine()
    var printer = FlowPrinter()
    engine.onConnectionRecord = { record, reason in printer.add(record, reason) }

    let result = replay.replayAll { meta, record, timestamp in
        var l3 = (try? record.reader(at: meta.l3Offset,
                                     count: record.count - meta.l3Offset))
        guard l3 != nil else { return }
        engine.process(makeContext(meta, timestamp: timestamp, lossEpoch: 0), l3: &l3!)
    }
    engine.flush()

    print("packets    \(result.decoded) decoded, \(result.decodeFailures) failed")
    printer.printTable(limit: limit)
    printer.printSummary(engine)
    return 0
}

// MARK: - Live

func runFlowsLive(seconds: Double, limit: Int) -> Int32 {
    let session = CaptureSession()
    do { try session.open() }
    catch {
        print("open failed: \(error)")
        if case CaptureError.notRoot = error {
            print("""

            Run in a Terminal window (Claude Code's `!` has no TTY for sudo):
                sudo .build/release/nmcapd --flows \(Int(seconds))

            Or capture once and analyse the file without root:
                sudo tcpdump -i pktap,all -c 2000 -w /tmp/c.pcap
                sudo chown $USER /tmp/c.pcap
                .build/release/nmcapd --flows-file /tmp/c.pcap
            """)
        }
        return 1
    }
    defer { session.close() }

    print("""
    NetworkMonitor flow analysis
    ============================
    \(session.bpfCeiling.explanation)
    capturing for \(Int(seconds))s on pktap,all ...
    """)

    let engine = FlowEngine()
    var printer = FlowPrinter()
    engine.onConnectionRecord = { record, reason in printer.add(record, reason) }

    let deadline = Date().addingTimeInterval(seconds)
    var lastStats = CaptureStats()
    while Date() < deadline {
        _ = session.drain(count: 256) { meta, record, timestamp in
            var l3 = (try? record.reader(at: meta.l3Offset,
                                         count: record.count - meta.l3Offset))
            guard l3 != nil else { return }
            engine.process(makeContext(meta, timestamp: timestamp,
                                       lossEpoch: engine.lossEpoch), l3: &l3!)
        }
        // Any kernel drop advances the loss epoch, which marks every flow
        // spanning it as approximate rather than letting its counts read exact.
        if let s = session.stats(), s.kernelDropped > lastStats.kernelDropped {
            engine.lossEpoch += 1
            lastStats = s
        }
    }
    engine.flush()

    if let s = session.stats() {
        print("packets    \(s.received) received, \(s.kernelDropped) dropped by the kernel")
    }
    printer.printTable(limit: limit)
    printer.printSummary(engine)
    return 0
}
