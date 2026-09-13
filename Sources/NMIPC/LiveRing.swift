//
//  LiveRing.swift
//
//  The daemon's in-memory view of right now.
//
//  This exists because the live view is structurally un-queryable from the
//  database: a flow is written when it CLOSES, so every connection currently
//  open exists nowhere else. Polling the store for "what is happening now"
//  would return the recent past and miss the present entirely.
//
//  Everything here is bounded. It is fed at packet rate by a process that must
//  never block, so an unbounded structure would let traffic choose the daemon's
//  memory footprint.
//

import Foundation
import NMCore

public final class LiveRing {

    /// Seconds of per-second history kept. Ten minutes, which covers the
    /// longest window the dashboard offers and backfills a newly-connected
    /// client's chart instantly rather than drawing it in over ten minutes.
    public let historySeconds: Int

    /// Open flows tracked for the live view. A flood creates flows faster than
    /// anyone can look at them, so this caps well below the flow table's own
    /// limit: the live list is for reading, not for accounting.
    public let maximumFlows: Int

    /// Distinct processes tracked per window.
    public let maximumProcesses: Int

    private var samples: [ThroughputSample]
    private var writeIndex = 0
    private var filled = 0
    private var currentSecond: Int64 = 0
    private var current = ThroughputSample(second: 0)

    private var processTotals: [Int64: ProcessTraffic] = [:]
    private var flows: [UInt64: LiveFlow] = [:]
    private var health = CaptureHealth()
    private var lossEpoch: UInt64 = 0

    public private(set) var flowsDroppedForCapacity: Int64 = 0

    public init(historySeconds: Int = 600, maximumFlows: Int = 2048,
                maximumProcesses: Int = 256) {
        self.historySeconds = historySeconds
        self.maximumFlows = maximumFlows
        self.maximumProcesses = maximumProcesses
        self.samples = []
        self.samples.reserveCapacity(historySeconds)
    }

    // MARK: - Feeding

    /// Rolls the current second forward if `now` has moved past it.
    private func advance(to second: Int64) {
        guard second != currentSecond else { return }
        if currentSecond != 0 { commit(current) }

        // A gap means the daemon was idle or asleep. Fill it with zeroes rather
        // than leaving a hole: a chart that interpolates across a gap implies
        // traffic that did not happen.
        var gap = second - currentSecond - 1
        if currentSecond != 0 && gap > 0 {
            gap = min(gap, Int64(historySeconds))
            for offset in 0..<gap {
                commit(ThroughputSample(second: currentSecond + 1 + offset))
            }
        }

        currentSecond = second
        current = ThroughputSample(second: second, activeFlows: Int32(flows.count))
    }

    private func commit(_ sample: ThroughputSample) {
        if samples.count < historySeconds {
            samples.append(sample)
        } else {
            samples[writeIndex] = sample
        }
        writeIndex = (writeIndex + 1) % historySeconds
        filled = min(filled + 1, historySeconds)
    }

    public func record(now: Timestamp, bytesIn: Int64 = 0, bytesOut: Int64 = 0,
                       packetsIn: Int64 = 0, packetsOut: Int64 = 0) {
        advance(to: now / Time.microsPerSecond)
        current.bytesIn += bytesIn
        current.bytesOut += bytesOut
        current.packetsIn += packetsIn
        current.packetsOut += packetsOut
    }

    public func recordProcess(execID: Int64, name: String, bytesIn: Int64,
                              bytesOut: Int64, proxy: String? = nil) {
        if var existing = processTotals[execID] {
            existing.bytesIn += bytesIn
            existing.bytesOut += bytesOut
            processTotals[execID] = existing
            return
        }
        guard processTotals.count < maximumProcesses else { return }
        processTotals[execID] = ProcessTraffic(execID: execID, name: name,
                                               bytesIn: bytesIn, bytesOut: bytesOut,
                                               flows: 0, viaProxy: proxy)
    }

    public func openFlow(_ flow: LiveFlow) {
        guard flows[flow.uid] == nil else { return }
        guard flows.count < maximumFlows else {
            flowsDroppedForCapacity += 1
            return
        }
        flows[flow.uid] = flow
        current.newFlows += 1
        current.activeFlows = Int32(flows.count)
        if let execID = flow.processName.map({ Int64($0.hashValue & 0x7FFF_FFFF) }) {
            processTotals[execID]?.flows += 1
        }
    }

    public func updateFlow(uid: UInt64, bytesOut: Int64, bytesIn: Int64,
                           state: String, hostname: String? = nil,
                           service: String? = nil) {
        guard var flow = flows[uid] else { return }
        flow.bytesOut = bytesOut
        flow.bytesIn = bytesIn
        flow.state = state
        if let hostname { flow.hostname = hostname }
        if let service { flow.service = service }
        flows[uid] = flow
    }

    public func closeFlow(uid: UInt64) {
        flows.removeValue(forKey: uid)
        current.activeFlows = Int32(flows.count)
    }

    public func setHealth(_ health: CaptureHealth) {
        self.health = health
    }

    public func noteLoss() {
        lossEpoch &+= 1
    }

    /// Clears the per-window process totals. Called when a snapshot window
    /// rolls over so "top talkers in the last minute" means that, rather than
    /// "since the daemon started".
    public func rollProcessWindow() {
        processTotals.removeAll(keepingCapacity: true)
    }

    // MARK: - Reading

    public var activeFlowCount: Int { flows.count }

    /// Builds a snapshot.
    ///
    /// `backfillSeconds` is how much history to include. A newly connected
    /// client asks for the full window so its chart is populated at once; a
    /// client already subscribed asks for a few seconds, which keeps the
    /// per-tick payload small enough to push several times a second.
    public func snapshot(now: Timestamp, backfillSeconds: Int,
                         topProcessCount: Int = 12,
                         flowLimit: Int = 200) -> LiveSnapshot {
        advance(to: now / Time.microsPerSecond)

        var history = orderedSamples()
        // The in-progress second is included so the chart has a leading edge
        // rather than always lagging by up to a second.
        history.append(current)
        if history.count > backfillSeconds {
            history = Array(history.suffix(backfillSeconds))
        }

        let processes = processTotals.values
            .sorted { $0.totalBytes > $1.totalBytes }
            .prefix(topProcessCount)

        // Busiest first: with a cap on how many are sent, the ones worth seeing
        // should be the ones that survive truncation.
        let visibleFlows = flows.values
            .sorted { ($0.bytesIn + $0.bytesOut) > ($1.bytesIn + $1.bytesOut) }
            .prefix(flowLimit)

        return LiveSnapshot(generatedAt: now,
                            samples: history,
                            topProcesses: Array(processes),
                            flows: Array(visibleFlows),
                            health: health,
                            lossEpoch: lossEpoch)
    }

    private func orderedSamples() -> [ThroughputSample] {
        guard samples.count == historySeconds else { return samples }
        // The ring has wrapped: oldest is at writeIndex.
        return Array(samples[writeIndex...] + samples[..<writeIndex])
    }
}

/// Derives a health level from raw counters.
///
/// The thresholds are deliberately tight. A monitor dropping a tenth of a
/// percent of packets still produces numbers that look entirely reasonable,
/// which is exactly why it has to say so.
public enum CaptureHealthAssessor {
    public static func assess(packetsReceived: Int64, kernelDropped: Int64,
                              ringDropped: Int64, decodeFailures: Int64,
                              flowsShed: Int64, bpfBufferBytes: Int) -> CaptureHealth {
        var health = CaptureHealth(packetsReceived: packetsReceived,
                                   kernelDropped: kernelDropped,
                                   ringDropped: ringDropped,
                                   decodeFailures: decodeFailures,
                                   flowsShed: flowsShed)

        let rate = health.dropRate
        if health.totalDropped == 0 {
            health.level = .healthy
            health.explanation = "No packets dropped."
        } else if rate < 0.001 {
            health.level = .degraded
            health.explanation = Self.cause(kernelDropped: kernelDropped,
                                            ringDropped: ringDropped,
                                            bpfBufferBytes: bpfBufferBytes)
        } else {
            health.level = .failing
            health.explanation = Self.cause(kernelDropped: kernelDropped,
                                            ringDropped: ringDropped,
                                            bpfBufferBytes: bpfBufferBytes)
        }

        if flowsShed > 0 {
            health.explanation += " \(flowsShed) connection(s) were aggregated because the "
                + "flow table was saturated -- usually a scan or a flood."
        }
        return health
    }

    /// Which drop counter dominates decides what the user should actually do,
    /// so the two are never merged into one number.
    private static func cause(kernelDropped: Int64, ringDropped: Int64,
                              bpfBufferBytes: Int) -> String {
        if kernelDropped > ringDropped {
            let megabytes = bpfBufferBytes / (1024 * 1024)
            return "The kernel capture buffer overflowed (\(megabytes) MB): traffic arrived "
                + "faster than it could be read. Byte counts spanning the gap are approximate."
        }
        if ringDropped > 0 {
            return "Analysis fell behind the capture. Reducing the snaplen or turning off "
                + "payload capture will help."
        }
        return "Packets were dropped before reaching the capture."
    }
}
