//
//  Benchmark.swift
//
//  `nmcapd --bench` -- the storage gate.
//
//  The plan's rule is that this runs BEFORE a line of UI is written, because it
//  either validates the SQLite decision or kills it cheaply. It answers four
//  questions with numbers rather than opinions:
//
//    1. Can the writer sustain the target row rate?
//    2. How many bytes does a row actually cost on disk, with indices?
//    3. What does that project to over the configured retention? (This is the
//       real constraint -- not the database engine.)
//    4. Do the dashboard's query shapes stay fast as rows accumulate?
//
//  It needs no root and no packets.
//

import Foundation
import NMCore
import NMSource
import NMStore

func runBenchmark(connsPerMinute: Int, seconds: Int) async -> Int32 {
    let root = NSTemporaryDirectory() + "nm-bench-\(getpid())"
    defer { try? FileManager.default.removeItem(atPath: root) }

    // Load is printed because a throughput figure without it is not comparable
    // to any other run.
    var loadAverages = [Double](repeating: 0, count: 3)
    _ = getloadavg(&loadAverages, 3)
    let cores = ProcessInfo.processInfo.activeProcessorCount

    print("""
    NetworkMonitor storage benchmark
    ================================
    target rate    \(fmt(connsPerMinute)) conn rows/minute
    duration       \(seconds)s of simulated traffic
    scratch        \(root)
    load average   \(String(format: "%.2f", loadAverages[0])) on \(cores) cores\
    \(loadAverages[0] > Double(cores) / 2 ? "   <- busy; figures are a lower bound" : "")

    """)

    let writer: StoreWriter
    do {
        writer = try StoreWriter(paths: Paths.temporary(root))
    } catch {
        print("failed to open store: \(error)")
        return 1
    }

    var config = SyntheticSource.Config()
    config.connsPerMinute = connsPerMinute
    config.realTime = false                 // free-running: compress wall clock
    let source = SyntheticSource(config: config)

    // Batch at 4 Hz, the same cadence the real pipeline uses.
    let batchesPerSecond = 4
    let connsPerBatch = max(1, connsPerMinute / 60 / batchesPerSecond)
    let totalBatches = seconds * batchesPerSecond

    print("writing \(fmt(connsPerBatch * totalBatches)) conn rows in "
          + "\(fmt(totalBatches)) transactions...")

    let started = DispatchTime.now().uptimeNanoseconds
    var written = 0
    for _ in 0..<totalBatches {
        let batch = source.generate(connCount: connsPerBatch)
        do {
            try await writer.write(batch)
            written += batch.count
        } catch {
            print("write failed after \(written) rows: \(error)")
            return 1
        }
    }
    do { try await writer.flush() } catch { print("flush failed: \(error)") }
    let elapsedNs = DispatchTime.now().uptimeNanoseconds - started
    let elapsedS = Double(elapsedNs) / 1e9

    do { try await writer.checkpoint() } catch { print("checkpoint failed: \(error)") }

    let stats = await writer.stats
    let counts = (try? await writer.rowCounts()) ?? (conn: 0, dns: 0, ssl: 0, rollMin: 0)
    let bytes = await writer.databaseBytes()

    // MARK: Throughput

    let rowsPerSecond = Double(stats.totalRows) / elapsedS
    print("""

    Write throughput
    \(rule())
      wall clock            \(String(format: "%.2f", elapsedS))s
      rows written          \(fmt(Int(stats.totalRows)))  (conn \(fmt(Int(stats.connRows))), \
    dns \(fmt(Int(stats.dnsRows))), ssl \(fmt(Int(stats.sslRows))))
      sustained rate        \(fmt(Int(rowsPerSecond))) rows/s
      transactions          \(fmt(Int(stats.batches)))
      mean transaction      \(stats.averageTransactionMicros) us
      headroom vs target    \(String(format: "%.0fx", rowsPerSecond / (Double(connsPerMinute) / 60)))
      distinct executables  \(stats.execInterned)
      rollup flushes        \(stats.rollupFlushes)
    """)

    // MARK: Footprint -- the number that actually decides the design

    let bytesPerRow = stats.totalRows > 0 ? Double(bytes) / Double(stats.totalRows) : 0
    let rowsPerDay = Double(connsPerMinute) * 60 * 24
        * (Double(stats.totalRows) / Double(max(stats.connRows, 1)))
    let bytesPerDay = rowsPerDay * bytesPerRow

    print("""

    Disk footprint  (the real constraint -- not the database engine)
    \(rule())
      on disk now           \(bytesHuman(bytes))
      per row               \(String(format: "%.1f", bytesPerRow)) bytes  (incl. indices)
      projected per day     \(bytesHuman(Int64(bytesPerDay)))
      projected 7 days      \(bytesHuman(Int64(bytesPerDay * 7)))
      projected 30 days     \(bytesHuman(Int64(bytesPerDay * 30)))
      rollup rows           \(fmt(Int(counts.rollMin)))  (what the Overview screen reads)
    """)

    if bytesPerDay * 30 > 100e9 {
        print("""

          NOTE: a 30-day raw retention at this rate needs \
        \(bytesHuman(Int64(bytesPerDay * 30))).
          Tier it -- raw conn 7 days, hourly rollups a year -- rather than \
        raising the disk budget.
        """)
    }

    // MARK: Where the bytes actually go
    //
    // DBSTAT_VTAB is compiled into the system SQLite, so this is a measurement
    // rather than an estimate. Optimising storage without it is guesswork.

    if let breakdown = try? storageBreakdown(Paths.temporary(root)) {
        print("""

        Storage breakdown  (\(rule().count > 0 ? "" : ""))
        \(rule())
        """)
        let total = breakdown.reduce(0) { $0 + $1.bytes }
        for entry in breakdown.prefix(14) {
            let share = total > 0 ? 100.0 * Double(entry.bytes) / Double(total) : 0
            let bar = String(repeating: "#", count: max(0, Int(share / 2)))
            print("  " + entry.name.padding(toLength: 22, withPad: " ", startingAt: 0)
                  + bytesHuman(entry.bytes).padding(toLength: 10, withPad: " ", startingAt: 0)
                  + String(format: "%5.1f%%  ", share) + bar)
        }
        let indexBytes = breakdown.filter { $0.isIndex }.reduce(0) { $0 + $1.bytes }
        print("""

          tables \(bytesHuman(total - indexBytes))   indices \(bytesHuman(indexBytes))         (\(total > 0 ? Int(100 * Double(indexBytes) / Double(total)) : 0)% of the file)
        """)
    }

    // MARK: Query shapes

    print("""

    Query shapes  (against \(fmt(Int(counts.conn))) conn rows)
    \(rule())
    """)

    let reader: SQLiteConnection
    do {
        reader = try SQLiteConnection(path: Paths.temporary(root).liveDatabase, readOnly: true)
        try Schema.configureReader(reader)
        let attach = try reader.prepare("ATTACH DATABASE ?1 AS roll")
        attach.bind(1, Paths.temporary(root).rollupDatabase)
        try attach.run()
        let attachMeta = try reader.prepare("ATTACH DATABASE ?1 AS meta")
        attachMeta.bind(1, Paths.temporary(root).metaDatabase)
        try attachMeta.run()
    } catch {
        print("  reader failed to open: \(error)")
        return 1
    }

    // The default browser sort is `id DESC`, which is the rowid btree and so
    // costs nothing -- deliberately, so the hot write path carries no index for it.
    time("newest page (id DESC, rowid btree)") {
        _ = try? countRows(reader, "SELECT id, ts, daddr, dport FROM conn ORDER BY id DESC LIMIT 200")
    }

    // Keyset pagination. OFFSET N makes SQLite produce and discard N rows, so
    // page 5,000 would cost a million discarded row-steps and get slower the
    // further you scroll. A keyset cursor is one index seek regardless of depth.
    let midpoint = (try? reader.scalarInt("SELECT ts FROM conn ORDER BY ts LIMIT 1 OFFSET \(max(0, Int(counts.conn) / 2))")) ?? 0
    time("keyset page deep in the table") {
        let s = try? reader.prepare("""
            SELECT id, ts FROM conn WHERE ts < ?1 ORDER BY ts DESC, id DESC LIMIT 200
            """)
        s?.bind(1, midpoint)
        while (try? s?.step()) == true {}
    }

    time("OFFSET equivalent, for contrast") {
        _ = try? countRows(reader, """
            SELECT id, ts FROM conn ORDER BY ts DESC LIMIT 200 OFFSET \(max(0, Int(counts.conn) - 400))
            """)
    }

    time("per-process drill-down (ix_conn_exec_ts)") {
        _ = try? countRows(reader, """
            SELECT id, ts, oipbytes FROM conn WHERE exec_id = 1 ORDER BY ts DESC LIMIT 200
            """)
    }

    // CIDR compiles to a BETWEEN over the BLOB column, which is an index range
    // scan. Stored as TEXT the same filter would be a full table scan.
    time("CIDR range scan (ix_conn_daddr_ts)") {
        let prefix = IPPrefix("8.0.0.0/8")!
        let s = try? reader.prepare("""
            SELECT count(*) FROM conn WHERE daddr BETWEEN ?1 AND ?2
            """)
        s?.bind(1, prefix.lower.storageBytes)
        s?.bind(2, prefix.upper.storageBytes)
        _ = try? s?.step()
    }

    time("Overview aggregate, from rollups") {
        _ = try? countRows(reader, """
            SELECT exec_id, sum(bytes) FROM roll.roll_min
            GROUP BY exec_id ORDER BY 2 DESC LIMIT 10
            """)
    }

    time("same aggregate from RAW rows (what rollups avoid)") {
        _ = try? countRows(reader, """
            SELECT exec_id, sum(oipbytes + iipbytes) FROM conn
            GROUP BY exec_id ORDER BY 2 DESC LIMIT 10
            """)
    }

    // LIKE is ASCII case-INSENSITIVE by default, and SQLite will only use an
    // index for a LIKE prefix when the collation matches. So the obvious
    // spelling silently degrades to a full scan. An explicit half-open range
    // always uses the index and does not depend on pragma state.
    time("domain suffix via LIKE (the obvious spelling)") {
        _ = try? countRows(reader, """
            SELECT count(*) FROM dns JOIN meta.name n ON n.id = dns.qname_id
             WHERE n.text_rev LIKE 'com.apple.%'
            """)
    }

    time("domain suffix via range (what we actually compile)") {
        let s = try? reader.prepare("""
            SELECT count(*) FROM dns
             WHERE qname_id IN (SELECT id FROM meta.name
                                 WHERE text_rev >= ?1 AND text_rev < ?2)
            """)
        s?.bind(1, "com.apple.")
        s?.bind(2, "com.apple/")      // '/' is the byte after '.'
        _ = try? s?.step()
    }

    print("\n  Query plans")
    print("  " + String(repeating: "-", count: 64))
    explain(reader, "LIKE   ", "SELECT count(*) FROM meta.name WHERE text_rev LIKE 'com.apple.%'")
    explain(reader, "range  ", "SELECT count(*) FROM meta.name WHERE text_rev >= 'com.apple.' AND text_rev < 'com.apple/'")
    explain(reader, "keyset ", "SELECT id FROM conn WHERE ts < 1 ORDER BY ts DESC, id DESC LIMIT 200")
    explain(reader, "OFFSET ", "SELECT id FROM conn ORDER BY ts DESC LIMIT 200 OFFSET 400000")
    explain(reader, "CIDR   ", "SELECT count(*) FROM conn WHERE daddr BETWEEN x'08000000' AND x'08ffffff'")

    reader.close()
    await writer.close()

    print("""

    Read the last two query rows together: that gap is the entire reason the
    rollup tables exist. Everything the Overview screen shows comes from the
    fast one.
    """)
    return 0
}

// MARK: - Storage breakdown

struct StorageEntry {
    var name: String
    var bytes: Int64
    var isIndex: Bool
}

/// Per-table and per-index byte usage, straight from SQLite's dbstat virtual
/// table. `pgsize` is the on-disk bytes for each b-tree page.
private func storageBreakdown(_ paths: Paths) throws -> [StorageEntry] {
    var out: [StorageEntry] = []
    for (label, path) in [("", paths.liveDatabase), ("roll.", paths.rollupDatabase),
                          ("meta.", paths.metaDatabase)] {
        let db = try SQLiteConnection(path: path, readOnly: true)
        defer { db.close() }
        let s = try db.prepare("""
            SELECT name, sum(pgsize) FROM dbstat GROUP BY name ORDER BY 2 DESC
            """)
        while try s.step() {
            let name = s.text(0) ?? "?"
            out.append(StorageEntry(name: label + name,
                                    bytes: s.int64(1),
                                    isIndex: name.hasPrefix("ix_") || name.hasPrefix("ux_")
                                             || name.hasPrefix("sqlite_autoindex")))
        }
    }
    return out.sorted { $0.bytes > $1.bytes }
}

// MARK: - Helpers

private func time(_ label: String, _ body: () -> Void) {
    let t0 = DispatchTime.now().uptimeNanoseconds
    body()
    let us = (DispatchTime.now().uptimeNanoseconds - t0) / 1_000
    let ms = Double(us) / 1000.0
    let value = ms >= 1 ? String(format: "%8.2f ms", ms) : String(format: "%8d us", us)
    print("  " + label.padding(toLength: 46, withPad: " ", startingAt: 0) + value)
}

/// Prints SQLite's chosen plan. Without Instruments this is the primary tool
/// for finding a query that silently degraded to a full scan.
private func explain(_ db: SQLiteConnection, _ label: String, _ sql: String) {
    guard let s = try? db.prepare("EXPLAIN QUERY PLAN " + sql) else { return }
    var lines: [String] = []
    while (try? s.step()) == true { lines.append(s.text(3) ?? "") }
    s.reset()
    print("  \(label) \(lines.joined(separator: " | "))")
}

private func countRows(_ db: SQLiteConnection, _ sql: String) throws -> Int {
    let s = try db.prepare(sql)
    var n = 0
    while try s.step() { n += 1 }
    s.reset()
    return n
}

private func rule() -> String { String(repeating: "-", count: 66) }

private func fmt(_ n: Int) -> String {
    let s = String(n)
    guard s.count > 3 else { return s }
    var out = ""
    for (i, c) in s.reversed().enumerated() {
        if i > 0 && i % 3 == 0 { out.append(",") }
        out.append(c)
    }
    return String(out.reversed())
}

private func bytesHuman(_ bytes: Int64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"]
    var value = Double(bytes)
    var unit = 0
    while value >= 1024 && unit < units.count - 1 { value /= 1024; unit += 1 }
    return String(format: value >= 100 ? "%.0f %@" : "%.1f %@", value, units[unit])
}
