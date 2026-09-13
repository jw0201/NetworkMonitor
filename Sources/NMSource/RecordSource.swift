//
//  RecordSource.swift
//
//  The seam that lets everything above the packet parser be built, benchmarked
//  and demonstrated with NO root privileges and NO pcap code.
//
//  This is the single most important de-risking decision in the project.
//  Storage, rollups, retention, IPC and the entire UI consume RecordSource.
//  `SyntheticSource` conforms to it today; `PcapSource` conforms to it once the
//  capture layer is verified. Whether SQLite holds up at 50k rows/minute is
//  therefore a measurement available on day two, not on day thirty.
//

import NMCore

/// Live counters maintained by a source, independent of what reaches storage.
///
/// These stay correct even when the writer is shedding raw rows under
/// backpressure, which is what keeps the Overview screen truthful under load.
public struct SourceCounters: Sendable, Equatable {
    public var packets: Int64 = 0
    public var bytesIn: Int64 = 0
    public var bytesOut: Int64 = 0
    public var flowsOpened: Int64 = 0
    public var flowsClosed: Int64 = 0
    public var activeFlows: Int = 0

    /// Dropped by the kernel's BPF ring. Not our fault, but our problem.
    public var kernelDropped: Int64 = 0
    /// Dropped because our own ring was full -- the analyzer fell behind.
    /// The only drop counter that is genuinely ours to fix.
    public var ringDropped: Int64 = 0
    /// Records we failed to decode.
    public var decodeFailures: Int64 = 0

    public init() {}

    public var totalDropped: Int64 { kernelDropped + ringDropped }

    public static func - (a: SourceCounters, b: SourceCounters) -> SourceCounters {
        var d = SourceCounters()
        d.packets = a.packets - b.packets
        d.bytesIn = a.bytesIn - b.bytesIn
        d.bytesOut = a.bytesOut - b.bytesOut
        d.flowsOpened = a.flowsOpened - b.flowsOpened
        d.flowsClosed = a.flowsClosed - b.flowsClosed
        d.activeFlows = a.activeFlows
        d.kernelDropped = a.kernelDropped - b.kernelDropped
        d.ringDropped = a.ringDropped - b.ringDropped
        d.decodeFailures = a.decodeFailures - b.decodeFailures
        return d
    }
}

/// A source of log records.
///
/// Implementations deliver batches rather than individual records: batching is
/// what keeps the storage layer at a handful of transactions per second instead
/// of thousands, and it is the difference between SQLite being irrelevant to
/// performance and SQLite being the bottleneck.
public protocol RecordSource: AnyObject {
    /// Begins producing records. The handler is called on the source's own
    /// thread and must not block -- it hands off to the storage queue.
    func start(_ handler: @escaping @Sendable (RecordBatch) -> Void) throws

    func stop()

    /// Cumulative counters. Callers diff successive samples to get rates.
    var counters: SourceCounters { get }

    /// Human-readable description for the UI's capture-health panel.
    var descriptionText: String { get }
}
