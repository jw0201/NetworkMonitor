//
//  FlowBenchmark.swift
//
//  `nmcapd --bench-flows` -- how fast is the flow engine, and does it stay
//  bounded under a flood?
//
//  Replaying a capture measures file I/O as much as the engine, and a fixture
//  with a handful of flows never exercises the table. This drives synthetic
//  packets across a configurable number of concurrent flows, entirely in
//  memory, so the number means something.
//
//  The target from the plan is 500 kpps sustained. Real consumer traffic on a
//  saturated gigabit link is about 81 kpps, so the headroom that matters is for
//  the adversarial case: a local port scan or SYN flood at small packet sizes.
//

import Darwin
import Foundation
import NMCore
import NMFlow

func runFlowBenchmark(flows: Int, packets: Int) -> Int32 {
    // A throughput number without the machine's load beside it is not
    // comparable to anything. Measured once at 1.02M pps and once at 819k on
    // the same build -- the second run had a load average of 17 on an 8-thread
    // machine, so the difference was contention, not a regression. Without the
    // load printed alongside, that looks like a 20% slowdown to investigate.
    let load = systemLoad()
    print("""
    NetworkMonitor flow engine benchmark
    ====================================
    concurrent flows   \(formatted(flows))
    packets            \(formatted(packets))
    cpu cores          \(ProcessInfo.processInfo.activeProcessorCount)
    load average       \(String(format: "%.2f", load))\
    \(load > Double(ProcessInfo.processInfo.activeProcessorCount) / 2
      ? "   <- machine is busy; treat the figures below as a lower bound" : "")

    """)

    let local = IPAddress("192.168.0.31")!

    // Pre-build the packets so the benchmark measures the engine, not the
    // fixture builder.
    var templates: [[UInt8]] = []
    templates.reserveCapacity(min(flows, 4096))
    for i in 0..<min(flows, 4096) {
        let remote = IPAddress(v4HostOrder: 0x08000000 | UInt32(i & 0xFFFFFF))
        templates.append(PacketFixture.ipv4TCP(.init(
            source: local, sourcePort: UInt16(10_000 &+ (i & 0x7FFF)),
            destination: remote, destinationPort: 443,
            flags: [.psh, .ack], payload: [UInt8](repeating: 0x41, count: 1400))))
    }

    func measure(_ label: String, table: FlowTable,
                 makeContext: (Int, Timestamp) -> PacketContext) -> Double {
        let engine = FlowEngine(table: table)
        var emitted = 0
        engine.onConnectionRecord = { _, _ in emitted += 1 }

        var timestamp: Timestamp = 1_757_000_000_000_000
        let start = DispatchTime.now().uptimeNanoseconds
        for i in 0..<packets {
            let template = templates[i % templates.count]
            template.withUnsafeBytes { buf in
                guard var r = ByteReader(buf) else { return }
                engine.process(makeContext(i, timestamp), l3: &r)
            }
            // Advance slowly so flows stay concurrent rather than ageing out.
            if i % 1000 == 0 { timestamp += 1000 }
        }
        let elapsed = Double(DispatchTime.now().uptimeNanoseconds - start) / 1e9
        let pps = Double(packets) / elapsed

        print("""
        \(label)
        \(String(repeating: "-", count: 66))
          elapsed            \(String(format: "%.3f", elapsed))s
          throughput         \(formatted(Int(pps))) packets/s
          per packet         \(String(format: "%.0f", 1e9 / pps)) ns
          peak concurrent    \(formatted(engine.table.stats.peakActive))
          flows created      \(formatted(Int(engine.table.stats.created)))
          records emitted    \(formatted(emitted))
          evicted            \(formatted(Int(engine.table.stats.evicted)))
          shed (table full)  \(formatted(Int(engine.stats.droppedNoCapacity)))
        """)
        return pps
    }

    let steady = measure("Steady state", table: FlowTable()) { _, ts in
        PacketContext(timestamp: ts, interfaceName: "en0", interfaceType: 0x06,
                      direction: .outbound, pid: 501, processName: "bench")
    }

    print("")

    // A flood: every packet opens a new flow, which is what a SYN scan does.
    // The question is not speed but whether memory stays bounded.
    let floodTable = FlowTable(capacity: 4096)
    let floodEngine = FlowEngine(table: floodTable)
    var floodEmitted = 0
    floodEngine.onConnectionRecord = { _, _ in floodEmitted += 1 }

    // Pre-build a large pool of DISTINCT packets. Building them inside the
    // timed loop measured array allocation, not the engine -- the first version
    // of this benchmark reported the allocator's throughput and called it the
    // flow engine's.
    let floodPoolSize = 100_000
    var floodPool: [[UInt8]] = []
    floodPool.reserveCapacity(floodPoolSize)
    for i in 0..<floodPoolSize {
        let remote = IPAddress(v4HostOrder: UInt32(truncatingIfNeeded: 0x0A000000 &+ i))
        floodPool.append(PacketFixture.ipv4TCP(.init(
            source: local, sourcePort: UInt16(truncatingIfNeeded: 1024 &+ i),
            destination: remote, destinationPort: 443, flags: [.syn])))
    }

    var timestamp: Timestamp = 1_757_000_000_000_000
    let floodStart = DispatchTime.now().uptimeNanoseconds
    for i in 0..<packets {
        floodPool[i % floodPoolSize].withUnsafeBytes { buf in
            guard var r = ByteReader(buf) else { return }
            floodEngine.process(PacketContext(timestamp: timestamp, interfaceName: "en0",
                                              interfaceType: 0x06, direction: .outbound,
                                              pid: 501, processName: "nmap"), l3: &r)
        }
        if i % 1000 == 0 { timestamp += 1000 }
    }
    floodEngine.flushEvictionAggregates()
    let floodElapsed = Double(DispatchTime.now().uptimeNanoseconds - floodStart) / 1e9

    print("""
    SYN flood  (every packet opens a new flow, table capped at 4096)
    \(String(repeating: "-", count: 66))
      elapsed            \(String(format: "%.3f", floodElapsed))s
      throughput         \(formatted(Int(Double(packets) / floodElapsed))) packets/s
      flows created      \(formatted(Int(floodTable.stats.created)))
      peak concurrent    \(formatted(floodTable.stats.peakActive))
      evicted            \(formatted(Int(floodTable.stats.evicted)))
      flood mode         \(floodTable.floodMode ? "engaged" : "not engaged")
      still resident     \(formatted(floodTable.count))
      records emitted    \(formatted(floodEmitted))  (aggregated, not one per shed flow)
    """)

    let bounded = floodTable.stats.peakActive <= 4096
    print("""

    \(bounded ? "BOUNDED" : "UNBOUNDED -- BUG")  peak concurrent flows stayed \
    \(bounded ? "within" : "ABOVE") the configured cap.
    A flood must cost the attacker more than it costs us; an unbounded table
    means they choose our memory footprint.
    """)

    let target = 500_000.0
    print("""

    Steady-state throughput is \(String(format: "%.1fx", steady / target)) the \
    500 kpps design target.
    For scale: a saturated gigabit link at 1500-byte packets is about 81 kpps.
    """)

    return bounded ? 0 : 1
}

/// One-minute load average.
private func systemLoad() -> Double {
    var averages = [Double](repeating: 0, count: 3)
    guard getloadavg(&averages, 3) > 0 else { return 0 }
    return averages[0]
}

private func formatted(_ n: Int) -> String {
    let s = String(n)
    guard s.count > 3 else { return s }
    var out = ""
    for (i, c) in s.reversed().enumerated() {
        if i > 0 && i % 3 == 0 { out.append(",") }
        out.append(c)
    }
    return String(out.reversed())
}
