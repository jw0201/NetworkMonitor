//
//  IngestMode.swift
//
//  `nmcapd --ingest <capture> [dbdir]` -- the whole pipeline, end to end,
//  without root: pcap file -> PKTAP decode -> flow engine -> DNS analyzer ->
//  hostname enrichment -> SQLite.
//
//  This is the first mode where records actually persist, and it exists mainly
//  as a check that the layers fit together: the flow engine emits records the
//  store can accept, enrichment happens before a record is written rather than
//  after, and the row counts at the end match what the engine said it produced.
//

import Foundation
import NMAnalyzers
import NMCapture
import NMCore
import NMFlow
import NMStore

func runIngest(path: String, databaseRoot: String?) async -> Int32 {
    let root = databaseRoot ?? (NSTemporaryDirectory() + "nm-ingest-\(getpid())")
    let ephemeral = databaseRoot == nil
    defer { if ephemeral { try? FileManager.default.removeItem(atPath: root) } }

    let replay: PacketReplay
    do { replay = try PacketReplay(path: path) }
    catch {
        print("\(error)")
        return 1
    }
    defer { replay.close() }

    let writer: StoreWriter
    do { writer = try StoreWriter(paths: Paths.temporary(root)) }
    catch {
        print("cannot open store: \(error)")
        return 1
    }

    print("""
    NetworkMonitor ingest
    =====================
    capture    \(path)
    database   \(root)\(ephemeral ? "  (temporary)" : "")

    """)

    let engine = FlowEngine()
    engine.analyzers.register(DNSAnalyzer())
    engine.analyzers.register(TLSAnalyzer())

    // Records are accumulated and written in batches. Writing each record as it
    // is produced would put a transaction on the packet path, which is the one
    // place that must never wait on disk.
    let collector = RecordCollector()
    engine.onConnectionRecord = { record, _ in collector.batch.conns.append(record) }
    engine.onDNSRecord = { record in collector.batch.dns.append(record) }
    engine.onSSLRecord = { record in collector.batch.ssl.append(record) }

    let started = DispatchTime.now().uptimeNanoseconds
    var written = 0

    let result = replay.replayAll { meta, record, timestamp in
        var l3 = (try? record.reader(at: meta.l3Offset, count: record.count - meta.l3Offset))
        guard l3 != nil else { return }
        engine.process(makeContext(meta, timestamp: timestamp, lossEpoch: 0), l3: &l3!)
    }
    engine.flush()

    // Drain in chunks so a large capture does not build one enormous transaction.
    while !collector.batch.isEmpty {
        var chunk = RecordBatch()
        chunk.conns = Array(collector.batch.conns.prefix(Limits.writeBatchRows))
        chunk.dns = Array(collector.batch.dns.prefix(Limits.writeBatchRows))
        chunk.ssl = Array(collector.batch.ssl.prefix(Limits.writeBatchRows))
        collector.batch.conns.removeFirst(chunk.conns.count)
        collector.batch.dns.removeFirst(chunk.dns.count)
        collector.batch.ssl.removeFirst(chunk.ssl.count)

        do { try await writer.write(chunk) }
        catch {
            print("write failed after \(written) records: \(error)")
            return 1
        }
        written += chunk.count
    }

    do {
        try await writer.flush()
        try await writer.checkpoint()
    } catch {
        print("flush failed: \(error)")
    }

    let elapsed = Double(DispatchTime.now().uptimeNanoseconds - started) / 1e9
    let counts = (try? await writer.rowCounts()) ?? (conn: 0, dns: 0, ssl: 0, rollMin: 0)
    let bytes = await writer.databaseBytes()
    let stats = engine.stats
    await writer.close()

    print("""
    Pipeline
    \(String(repeating: "-", count: 70))
      packets decoded     \(result.decoded)  (\(result.decodeFailures) failed)
      flows tracked       \(engine.table.stats.created)
      conn records        \(stats.recordsEmitted)
      analyzer calls      \(stats.analyzerInvocations)
      names resolved      \(stats.hostnamesResolved)

    Persisted
    \(String(repeating: "-", count: 70))
      conn rows           \(counts.conn)
      dns rows            \(counts.dns)
      ssl rows            \(counts.ssl)
      rollup rows         \(counts.rollMin)
      on disk             \(humanBytes(bytes))
      elapsed             \(String(format: "%.2f", elapsed))s
    """)

    // The check that makes this mode worth running: every record the engine
    // produced should be in the database. A mismatch means records were
    // dropped between the two layers, which no amount of unit testing of
    // either layer on its own would catch.
    if counts.conn != Int64(stats.recordsEmitted) {
        print("""

          MISMATCH: the engine emitted \(stats.recordsEmitted) conn records but \
        \(counts.conn) were persisted.
        """)
        return 1
    }

    if !ephemeral {
        print("""

        Query it with:
            sqlite3 '\(root)/db/live.db' \\
              "SELECT datetime(ts/1000000,'unixepoch'), host_id, dport, state FROM conn LIMIT 10"
        """)
    }
    return 0
}

/// A box, because the engine's callbacks are escaping closures and a local
/// `var` cannot be captured mutably by one.
private final class RecordCollector {
    var batch = RecordBatch()
}

private func humanBytes(_ n: Int64) -> String {
    if n < 1024 { return "\(n) B" }
    if n < 1024 * 1024 { return String(format: "%.1f KB", Double(n) / 1024) }
    return String(format: "%.1f MB", Double(n) / 1_048_576)
}
