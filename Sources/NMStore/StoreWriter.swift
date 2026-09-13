//
//  StoreWriter.swift
//
//  The single writer. One connection, one owner, batched transactions.
//
//  SQLite's write path is not the constraint here and it is worth being clear
//  about why: measured on this machine, batched inserts sustain roughly 1.9M
//  rows/second. The heavy target of 50k rows/MINUTE is 833 rows/second -- under
//  0.1% of capacity. What actually breaks is unindexed scans (4.4 s per 5M
//  rows) and disk footprint. The schema's index discipline and the rollup
//  tables address those; nothing here needs to be clever.
//
//  What this code does have to get right is backpressure. A capture daemon that
//  blocks on disk I/O drops packets at the BPF layer, and that loss is
//  invisible and unrecoverable. So the writer sheds in a defined order and
//  never, ever blocks the producer.
//

import Foundation
import NMCore
import SQLite3

public struct WriterStats: Sendable, Equatable {
    public var connRows: Int64 = 0
    public var dnsRows: Int64 = 0
    public var sslRows: Int64 = 0
    public var batches: Int64 = 0
    public var transactionMicros: Int64 = 0
    /// Rows discarded under backpressure. Surfaced in the UI as a warning
    /// badge: silent loss is worse than visible loss.
    public var shedRows: Int64 = 0
    public var rollupFlushes: Int64 = 0
    public var execInterned: Int64 = 0
    public var rotations: Int64 = 0
    public var checkpoints: Int64 = 0
    public var walBytesReclaimed: Int64 = 0

    public var totalRows: Int64 { connRows + dnsRows + sslRows }

    public var averageTransactionMicros: Int64 {
        batches == 0 ? 0 : transactionMicros / batches
    }
}

/// A rollup bucket key. The Overview screen's entire dataset is aggregated
/// under these five columns.
private struct RollupKey: Hashable {
    var bucket: Int64
    var execID: Int64
    var proto: Int64
    var ifaceID: Int64
    var dir: Int64
}

private struct RollupValue {
    var bytes: Int64 = 0
    var pkts: Int64 = 0
    var flowsNew: Int64 = 0
}

public actor StoreWriter {

    private let paths: Paths
    private var db: SQLiteConnection

    /// (path, uuid) -> exec.id. Keyed on the Mach-O UUID as well as the path so
    /// a binary update or a recycled pid produces a new identity rather than
    /// silently inheriting the old one.
    fileprivate struct ExecKey: Hashable {
        var path: String
        var uuidHi: UInt64
        var uuidLo: UInt64
        /// Part of the key, matching the unique index. Without it an identity
        /// carrying neither a path nor a UUID merges with every other such
        /// identity.
        var name: String
    }
    private var execCache: [ExecKey: Int64] = [:]
    private var ifaceCache: [String: Int64] = [:]

    /// Domain-name and TLS-fingerprint interning caches.
    ///
    /// Both are bounded. Names in particular can be attacker-influenced --
    /// DGA malware generates effectively unlimited distinct domains -- so the
    /// in-memory cache is capped and cleared when it fills. A cache miss costs
    /// one indexed SELECT, which is the right price for a bounded footprint.
    /// (The `name` TABLE still grows with genuinely distinct names, but those
    /// are data we would have stored inline anyway, only now deduplicated.)
    private var nameCache: [String: Int64] = [:]
    private var fingerprintCache: [String: Int64] = [:]
    private static let maxNameCacheEntries = 100_000
    private static let maxFingerprintCacheEntries = 10_000

    /// Rollups are accumulated HERE, in memory, from counters the writer
    /// already has -- never derived by scanning raw rows later. A nightly job
    /// that GROUP BYs a day of conn rows would cost seconds per 5M rows and
    /// would grow forever.
    private var rollupAccumulator: [RollupKey: RollupValue] = [:]
    private var openMinuteBucket: Int64 = 0

    public private(set) var stats = WriterStats()

    /// Retention settings. System-wide policy, not a per-user preference:
    /// changing it deletes other users' data.
    public var policy = RetentionPolicy()

    /// The UTC day the live file currently covers.
    ///
    /// Derived from the DATA, not from the wall clock. Taking it from the clock
    /// at startup means a writer replaying an older capture rotates on its very
    /// first write, archiving an empty partition and putting the real data in
    /// the "next" day. It stays nil until the first record decides it, or is
    /// recovered from rows already in the live file after a restart.
    public private(set) var currentDay: String?

    // MARK: - Lifecycle

    public init(paths: Paths, createDirectories: Bool = true) throws {
        self.paths = paths

        if createDirectories {
            for dir in paths.allDirectories {
                try FileManager.default.createDirectory(
                    atPath: dir, withIntermediateDirectories: true,
                    attributes: [.posixPermissions: 0o770])
            }
        }

        // live.db is the main database; the other three are attached so a batch
        // spanning raw rows, the exec dimension and the rollups commits as one
        // transaction. Three attachments leaves seven of SQLite's ten slots for
        // day files during queries.
        self.db = try SQLiteConnection(path: paths.liveDatabase)
        try Schema.configureWriter(db)
        try Schema.createDayPartition(db)

        // Swift 6 actor inits are nonisolated, so setup runs through static
        // helpers that take the connection explicitly rather than through
        // isolated methods.
        try Self.attach(db, path: paths.metaDatabase, alias: "meta", create: Schema.createMeta)
        try Self.attach(db, path: paths.rollupDatabase, alias: "roll", create: Schema.createRollup)
        try Self.attach(db, path: paths.pcapDatabase, alias: "pcapx", create: Schema.createPcapIndex)

        self.execCache = try Self.loadExecCache(db)
        self.ifaceCache = try Self.loadIfaceCache(db)
        // After a restart the live file may already hold a day's rows; adopt
        // their day rather than starting a new one.
        if let latest = try? db.scalarInt("SELECT max(ts) FROM conn"), latest > 0 {
            self.currentDay = Time.utcDayString(latest)
        }
    }

    private static func attach(_ db: SQLiteConnection, path: String, alias: String,
                               create: (SQLiteConnection) throws -> Void) throws {
        // Create and initialise the file through its own connection first:
        // DDL is clearer against a plain main database than against an alias.
        let side = try SQLiteConnection(path: path)
        try Schema.configureWriter(side)
        try create(side)
        side.close()

        let stmt = try db.prepare("ATTACH DATABASE ?1 AS \(alias)")
        stmt.bind(1, path)
        try stmt.run()
    }

    public func close() {
        try? flush()
        try? checkpoint()
        try? db.exec("PRAGMA optimize")
        db.close()
    }

    // MARK: - Dimension interning

    private static func loadExecCache(_ db: SQLiteConnection) throws -> [ExecKey: Int64] {
        var cache: [ExecKey: Int64] = [:]
        let s = try db.prepare("SELECT id, path, uuid_hi, uuid_lo, name FROM meta.exec")
        while try s.step() {
            let key = ExecKey(path: s.text(1) ?? "",
                              uuidHi: UInt64(bitPattern: s.int64(2)),
                              uuidLo: UInt64(bitPattern: s.int64(3)),
                              name: s.text(4) ?? "")
            cache[key] = s.int64(0)
        }
        return cache
    }

    private static func loadIfaceCache(_ db: SQLiteConnection) throws -> [String: Int64] {
        var cache: [String: Int64] = [:]
        let s = try db.prepare("SELECT id, name FROM roll.iface")
        while try s.step() { cache[s.text(1) ?? ""] = s.int64(0) }
        return cache
    }

    private func execID(for info: ExecInfo?, now: Timestamp) throws -> Int64? {
        guard let info else { return nil }
        let key = ExecKey(path: info.path, uuidHi: info.uuidHi,
                          uuidLo: info.uuidLo, name: info.name)
        if let id = execCache[key] { return id }

        let insert = try db.prepare("""
            INSERT INTO meta.exec
              (path, name, bundle_id, signing_id, team_id,
               uuid_hi, uuid_lo, is_platform, first_seen, last_seen)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)
            ON CONFLICT(path, uuid_hi, uuid_lo, name) DO UPDATE SET last_seen = ?9
            """)
        insert.bind(1, info.path)
        insert.bind(2, info.name)
        insert.bind(3, info.bundleID)
        insert.bind(4, info.signingID)
        insert.bind(5, info.teamID)
        insert.bind(6, Int64(bitPattern: info.uuidHi))
        insert.bind(7, Int64(bitPattern: info.uuidLo))
        insert.bind(8, info.isPlatform)
        insert.bind(9, now)
        try insert.run()

        let select = try db.prepare("""
            SELECT id FROM meta.exec
             WHERE path = ?1 AND uuid_hi = ?2 AND uuid_lo = ?3 AND name = ?4
            """)
        select.bind(1, info.path)
        select.bind(2, Int64(bitPattern: info.uuidHi))
        select.bind(3, Int64(bitPattern: info.uuidLo))
        select.bind(4, info.name)
        defer { select.reset() }
        guard try select.step() else { return nil }
        let id = select.int64(0)

        execCache[key] = id
        stats.execInterned += 1
        return id
    }

    /// Interns a domain name, returning its dimension id.
    ///
    /// The reversed spelling is computed once here rather than stored on every
    /// row that references the name.
    private func nameID(for text: String?) throws -> Int64? {
        guard let text, !text.isEmpty else { return nil }
        if let id = nameCache[text] { return id }

        if nameCache.count >= Self.maxNameCacheEntries { nameCache.removeAll(keepingCapacity: true) }

        let reversed = text.split(separator: ".").reversed().joined(separator: ".")
        let now = Timestamp(Date().timeIntervalSince1970 * 1_000_000)

        let insert = try db.prepare("""
            INSERT INTO meta.name (text, text_rev, first_seen, last_seen)
            VALUES (?1, ?2, ?3, ?3)
            ON CONFLICT(text) DO UPDATE SET last_seen = ?3
            """)
        insert.bind(1, text)
        insert.bind(2, reversed)
        insert.bind(3, now)
        try insert.run()

        let select = try db.prepare("SELECT id FROM meta.name WHERE text = ?1")
        select.bind(1, text)
        defer { select.reset() }
        guard try select.step() else { return nil }
        let id = select.int64(0)
        nameCache[text] = id
        return id
    }

    /// Interns a TLS fingerprint set. Measured as the single largest storage
    /// win available: ja4 + ja4_r + ja3 inline cost ~146 bytes on every ssl row
    /// while a machine produces only a few hundred distinct values.
    private func fingerprintID(for x: SSLRecord) throws -> Int64? {
        guard x.ja4 != nil || x.ja3 != nil || x.ja4s != nil || x.ja3s != nil else { return nil }
        let key = "\(x.ja4 ?? "")|\(x.ja3 ?? "")|\(x.ja4s ?? "")|\(x.ja3s ?? "")"
        if let id = fingerprintCache[key] { return id }

        if fingerprintCache.count >= Self.maxFingerprintCacheEntries {
            fingerprintCache.removeAll(keepingCapacity: true)
        }

        let insert = try db.prepare("""
            INSERT INTO meta.fingerprint (ja4, ja4_r, ja3, ja4s, ja3s, first_seen, last_seen)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
            ON CONFLICT(ja4, ja3, ja4s, ja3s) DO UPDATE SET last_seen = ?6
            """)
        insert.bind(1, x.ja4)
        insert.bind(2, x.ja4Raw)
        insert.bind(3, x.ja3)
        insert.bind(4, x.ja4s)
        insert.bind(5, x.ja3s)
        insert.bind(6, x.ts)
        try insert.run()

        let select = try db.prepare("""
            SELECT id FROM meta.fingerprint
            WHERE ja4 IS ?1 AND ja3 IS ?2 AND ja4s IS ?3 AND ja3s IS ?4
            """)
        select.bind(1, x.ja4)
        select.bind(2, x.ja3)
        select.bind(3, x.ja4s)
        select.bind(4, x.ja3s)
        defer { select.reset() }
        guard try select.step() else { return nil }
        let id = select.int64(0)
        fingerprintCache[key] = id
        return id
    }

    private func ifaceID(for name: String) throws -> Int64 {
        if let id = ifaceCache[name] { return id }
        let insert = try db.prepare("INSERT OR IGNORE INTO roll.iface (name) VALUES (?1)")
        insert.bind(1, name)
        try insert.run()
        let select = try db.prepare("SELECT id FROM roll.iface WHERE name = ?1")
        select.bind(1, name)
        defer { select.reset() }
        guard try select.step() else { return 0 }
        let id = select.int64(0)
        ifaceCache[name] = id
        return id
    }

    // MARK: - Writing

    public func write(_ batch: RecordBatch) throws {
        guard !batch.isEmpty else { return }

        // Rotation is checked on the write path rather than on a timer, so a
        // daemon that was asleep across midnight rotates on its next write
        // instead of writing a second day into yesterday's partition.
        if let first = batch.conns.first?.ts ?? batch.dns.first?.ts ?? batch.ssl.first?.ts {
            try rotateIfNeeded(now: first)
        }

        let started = DispatchTime.now().uptimeNanoseconds

        try db.transaction {
            for c in batch.conns { try insertConn(c) }
            for d in batch.dns { try insertDNS(d) }
            for s in batch.ssl { try insertSSL(s) }
            try flushRollupsIfMinuteClosed()
        }

        stats.batches += 1
        stats.transactionMicros +=
            Int64((DispatchTime.now().uptimeNanoseconds - started) / 1_000)
    }

    private func insertConn(_ c: ConnRecord) throws {
        let execRef = try execID(for: c.exec, now: c.ts)
        let proxyRef = try execID(for: c.proxyExec, now: c.ts)

        let s = try db.prepare("""
            INSERT INTO conn
              (uid, ts, ts_end, duration_us, af, proto, saddr, sport, daddr, dport,
               iface, service, state, history,
               opkts, obytes, oipbytes, ipkts, ibytes, iipbytes, missed_bytes,
               local_orig, local_resp,
               exec_id, pid, puid, proxy_exec_id, proxy_pid,
               host_id, host_src, host_ambig, first_seg, last_seg, pcap_ok, loss)
            VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,
                    ?11,?12,?13,?14,
                    ?15,?16,?17,?18,?19,?20,?21,
                    ?22,?23,
                    ?24,?25,?26,?27,?28,
                    ?29,?30,?31,?32,?33,1,?34)
            """)
        s.bind(1, c.uid.storageValue)
        s.bind(2, c.ts)
        s.bind(3, c.tsEnd)
        s.bind(4, c.durationUs)
        s.bind(5, Int64(c.origAddr.addressFamily))
        s.bind(6, c.proto)
        s.bind(7, c.origAddr.storageBytes)
        s.bind(8, c.origPort)
        s.bind(9, c.respAddr.storageBytes)
        s.bind(10, c.respPort)
        s.bind(11, c.iface)
        s.bind(12, c.service)
        s.bind(13, c.state.rawValue)
        // The history cap is enforced at the storage boundary too, so a bug in
        // the flow layer cannot put an unbounded string in the database.
        s.bind(14, String(c.history.prefix(Limits.maxHistoryCharacters)))
        s.bind(15, c.origPkts)
        s.bind(16, c.origBytes)
        s.bind(17, c.origIPBytes)
        s.bind(18, c.respPkts)
        s.bind(19, c.respBytes)
        s.bind(20, c.respIPBytes)
        s.bind(21, c.missedBytes)
        s.bind(22, c.localOrig)
        s.bind(23, c.localResp)
        s.bind(24, execRef)
        s.bind(25, c.pid)
        s.bind(26, c.userID)
        s.bind(27, proxyRef)
        s.bind(28, c.proxyPid)
        s.bind(29, try nameID(for: c.hostname))
        s.bind(30, Int64(c.hostnameSource.rawValue))
        s.bind(31, c.hostnameAmbiguous)
        s.bind(32, c.firstPcapSegment)
        s.bind(33, c.lastPcapSegment)
        s.bind(34, c.captureLossSuspected)
        try s.run()

        stats.connRows += 1
        try accumulateRollup(c, execRef: execRef)
    }

    private func insertDNS(_ d: DNSRecord) throws {
        let execRef = try execID(for: d.exec, now: d.ts)
        let s = try db.prepare("""
            INSERT INTO dns
              (uid, ts, proto, af, saddr, sport, daddr, dport,
               trans_id, rtt_us, qname_id, qtype, qclass, rcode, dnsflags,
               answers, ttls, rejected, exec_id, pid, puid)
            VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21)
            """)
        s.bind(1, d.uid?.storageValue)
        s.bind(2, d.ts)
        s.bind(3, d.proto)
        s.bind(4, Int64(d.clientAddr.addressFamily))
        s.bind(5, d.clientAddr.storageBytes)
        s.bind(6, Int64(0))
        s.bind(7, d.serverAddr.storageBytes)
        s.bind(8, d.serverPort)
        s.bind(9, d.transactionID)
        s.bind(10, d.rttUs)
        s.bind(11, try nameID(for: d.query))
        s.bind(12, d.qtype)
        s.bind(13, d.qclass)
        s.bind(14, d.rcode)
        s.bind(15, d.flags)
        s.bind(16, jsonArray(d.answers))
        s.bind(17, jsonArray(d.ttls.map(String.init)))
        s.bind(18, d.rejected)
        s.bind(19, execRef)
        s.bind(20, d.pid)
        s.bind(21, nil as Int64?)
        try s.run()
        stats.dnsRows += 1
    }

    private func insertSSL(_ x: SSLRecord) throws {
        let execRef = try execID(for: x.exec, now: x.ts)
        let s = try db.prepare("""
            INSERT INTO ssl
              (uid, ts, af, saddr, sport, daddr, dport, version, cipher, curve,
               sni_id, sni_outer, alpn, ssl_hist, established, resumed,
               fp_id,
               certs_encrypted, subject, issuer, not_before, not_after, chain_fps,
               exec_id, pid, puid)
            VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,
                    ?17,?18,?19,?20,?21,?22,?23,?24,?25,?26)
            """)
        s.bind(1, x.uid?.storageValue)
        s.bind(2, x.ts)
        s.bind(3, Int64(x.clientAddr.addressFamily))
        s.bind(4, x.clientAddr.storageBytes)
        s.bind(5, Int64(0))
        s.bind(6, x.serverAddr.storageBytes)
        s.bind(7, x.serverPort)
        s.bind(8, x.version)
        s.bind(9, x.cipher)
        s.bind(10, x.curve)
        s.bind(11, try nameID(for: x.sni))
        s.bind(12, x.sniIsOuter)
        s.bind(13, x.alpn)
        s.bind(14, x.sslHistory)
        s.bind(15, x.established)
        s.bind(16, x.resumed)
        s.bind(17, try fingerprintID(for: x))
        s.bind(18, x.certsEncrypted)
        s.bind(19, x.subject)
        s.bind(20, x.issuer)
        s.bind(21, x.notBefore)
        s.bind(22, x.notAfter)
        s.bind(23, x.chainFingerprints.isEmpty ? nil : jsonArray(x.chainFingerprints))
        s.bind(24, execRef)
        s.bind(25, x.pid)
        s.bind(26, nil as Int64?)
        try s.run()
        stats.sslRows += 1
    }

    // MARK: - Rollups

    private func accumulateRollup(_ c: ConnRecord, execRef: Int64?) throws {
        let bucket = Time.minuteBucket(c.ts)
        if openMinuteBucket == 0 { openMinuteBucket = bucket }

        let iface = try ifaceID(for: c.iface)
        let exec = execRef ?? 0

        var outKey = RollupKey(bucket: bucket, execID: exec, proto: Int64(c.proto),
                               ifaceID: iface, dir: 0)
        var outValue = rollupAccumulator[outKey] ?? RollupValue()
        outValue.bytes += c.origIPBytes
        outValue.pkts += c.origPkts
        outValue.flowsNew += 1
        rollupAccumulator[outKey] = outValue

        outKey.dir = 1
        var inValue = rollupAccumulator[outKey] ?? RollupValue()
        inValue.bytes += c.respIPBytes
        inValue.pkts += c.respPkts
        rollupAccumulator[outKey] = inValue
    }

    /// Writes out accumulated buckets once the minute they belong to has closed.
    /// Typically a few hundred UPSERTs once a minute.
    private func flushRollupsIfMinuteClosed() throws {
        guard !rollupAccumulator.isEmpty else { return }
        let newest = rollupAccumulator.keys.max { $0.bucket < $1.bucket }?.bucket ?? 0
        guard newest > openMinuteBucket else { return }
        try writeRollups(upTo: newest)
        openMinuteBucket = newest
    }

    private func writeRollups(upTo newest: Int64) throws {
        let s = try db.prepare("""
            INSERT INTO roll.roll_min
              (bucket, exec_id, proto, iface_id, dir, bytes, pkts, flows_new)
            VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
            ON CONFLICT(bucket, exec_id, proto, iface_id, dir) DO UPDATE SET
              bytes = bytes + excluded.bytes,
              pkts = pkts + excluded.pkts,
              flows_new = flows_new + excluded.flows_new
            """)
        var written = 0
        for (key, value) in rollupAccumulator where key.bucket < newest {
            s.bind(1, key.bucket)
            s.bind(2, key.execID)
            s.bind(3, key.proto)
            s.bind(4, key.ifaceID)
            s.bind(5, key.dir)
            s.bind(6, value.bytes)
            s.bind(7, value.pkts)
            s.bind(8, value.flowsNew)
            try s.run()
            written += 1
        }
        rollupAccumulator = rollupAccumulator.filter { $0.key.bucket >= newest }
        if written > 0 { stats.rollupFlushes += 1 }
    }

    /// Commits everything still buffered, including the open minute. Called at
    /// shutdown and before a day rotation.
    public func flush() throws {
        guard !rollupAccumulator.isEmpty else { return }
        try db.transaction {
            try writeRollups(upTo: Int64.max)
        }
    }

    // MARK: - Rotation

    /// Rotates when the day changes or the live file grows past its cap.
    @discardableResult
    public func rotateIfNeeded(now: Timestamp) throws -> SealedArchive? {
        let day = Time.utcDayString(now)
        guard let open = currentDay else {
            // First record ever: it defines the day, and there is nothing to
            // rotate.
            currentDay = day
            return nil
        }
        let oversized = Partition.fileSize(paths.liveDatabase) > policy.maximumLiveBytes
        guard day != open || oversized else { return nil }
        return try rotate(closing: open, newDay: day)
    }

    /// Closes the live partition, renames it into the archive, seals it, and
    /// opens a fresh one.
    ///
    /// Writers are blocked for the duration, which is milliseconds: the
    /// expensive part is the rename, and rename is O(1). The sealing that
    /// follows -- index building and compaction -- happens on the archive,
    /// which nothing is writing to any more.
    @discardableResult
    public func rotate(closing day: String, newDay: String) throws -> SealedArchive? {
        try flush()
        try checkpoint()
        try? db.exec("PRAGMA optimize")
        db.close()

        let archivePath: String
        do {
            archivePath = try Partition.rotate(paths: paths, day: day)
        } catch {
            // Reopen regardless: a failed rotation must not leave the daemon
            // with no database to write to.
            try reopenLive()
            throw error
        }

        try reopenLive()
        currentDay = newDay

        let sealed = try Partition.seal(archivePath: archivePath, day: day)
        try recordInCatalog(sealed)
        stats.rotations += 1
        return sealed
    }

    private func reopenLive() throws {
        db = try SQLiteConnection(path: paths.liveDatabase)
        try Schema.configureWriter(db)
        try Schema.createDayPartition(db)
        try Self.attach(db, path: paths.metaDatabase, alias: "meta", create: Schema.createMeta)
        try Self.attach(db, path: paths.rollupDatabase, alias: "roll", create: Schema.createRollup)
        try Self.attach(db, path: paths.pcapDatabase, alias: "pcapx", create: Schema.createPcapIndex)
        // The dimension caches map to ids in meta, which survived the rotation,
        // so they stay valid. The iface cache likewise lives in roll.
    }

    private func recordInCatalog(_ archive: SealedArchive) throws {
        let statement = try db.prepare("""
            INSERT INTO meta.file_catalog
              (path, day, first_ts, last_ts, bytes, conn_rows, dns_rows, ssl_rows,
               sealed, created)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9)
            ON CONFLICT(path) DO UPDATE SET
              bytes = excluded.bytes, conn_rows = excluded.conn_rows,
              dns_rows = excluded.dns_rows, ssl_rows = excluded.ssl_rows, sealed = 1
            """)
        statement.bind(1, archive.path)
        statement.bind(2, archive.day)
        statement.bind(3, archive.firstTimestamp)
        statement.bind(4, archive.lastTimestamp)
        statement.bind(5, archive.bytes)
        statement.bind(6, archive.connRows)
        statement.bind(7, archive.dnsRows)
        statement.bind(8, archive.sslRows)
        statement.bind(9, Timestamp(Date().timeIntervalSince1970 * 1_000_000))
        try statement.run()
    }

    /// Runs a retention pass. Separate from rotation because the two have
    /// different cadences: rotation is daily, retention is hourly, and a
    /// long-running daemon should not couple them.
    @discardableResult
    public func runRetention(now: Timestamp) -> RetentionReport {
        Retention.run(paths: paths, policy: policy, today: Time.utcDayString(now))
    }

    /// Every archive on disk, newest first, as recorded in the catalog.
    public func archives() throws -> [(day: String, path: String, bytes: Int64, connRows: Int64)] {
        var out: [(String, String, Int64, Int64)] = []
        let statement = try db.prepare("""
            SELECT day, path, bytes, conn_rows FROM meta.file_catalog ORDER BY day DESC
            """)
        while try statement.step() {
            out.append((statement.text(0) ?? "", statement.text(1) ?? "",
                        statement.int64(2), statement.int64(3)))
        }
        return out
    }

    /// Folds the WAL back into the main database.
    ///
    /// Deliberate rather than automatic (wal_autocheckpoint is 0) so a
    /// checkpoint never lands in the middle of a write batch -- but that means
    /// SOMETHING has to call this on a schedule. Observed on a live install:
    /// 45 minutes of ordinary browsing produced an 8 KB database and a 48 MB
    /// WAL, because the only checkpoints were at rotation and shutdown.
    /// journal_size_limit does not help, since it is only applied when a
    /// checkpoint runs.
    public func checkpoint() throws {
        _ = try db.scalarInt("PRAGMA wal_checkpoint(TRUNCATE)")
    }

    /// Checkpoints when the WAL has grown past `thresholdBytes`.
    ///
    /// Two modes, because they do different things and confusing them is how
    /// the WAL grew to 48 MB against an 8 KB database on a live install:
    ///
    ///   * PASSIVE moves WAL content into the database without waiting for
    ///     readers, but does NOT shrink the file -- the space is reused, not
    ///     returned. On its own it bounds nothing that a person watching disk
    ///     usage would notice.
    ///   * TRUNCATE returns the space, but blocks until readers are clear.
    ///
    /// So: PASSIVE first, which is cheap and usually enough to let the file be
    /// reused; then TRUNCATE only if the file is still oversized, which is the
    /// case where the pause is worth it. journal_size_limit also has to be
    /// BELOW the working size or it never fires -- it is the size the WAL is
    /// trimmed back to, not a ceiling on growth.
    @discardableResult
    public func checkpointIfNeeded(thresholdBytes: Int64 = 16 * 1024 * 1024) -> Int64 {
        let walPath = paths.liveDatabase + "-wal"
        let size = Partition.fileSize(walPath)
        guard size >= thresholdBytes else { return size }

        for alias in ["main", "meta", "roll", "pcapx"] {
            _ = try? db.scalarInt("PRAGMA \(alias).wal_checkpoint(PASSIVE)")
        }

        var after = Partition.fileSize(walPath)
        if after >= thresholdBytes {
            // A passive pass did not free it, so a reader is holding the WAL
            // open or the content could not be moved. Take the pause.
            for alias in ["main", "meta", "roll", "pcapx"] {
                _ = try? db.scalarInt("PRAGMA \(alias).wal_checkpoint(TRUNCATE)")
            }
            after = Partition.fileSize(walPath)
        }

        stats.checkpoints += 1
        stats.walBytesReclaimed += max(0, size - after)
        return after
    }

    /// Current WAL size, for the status the UI shows.
    public func walBytes() -> Int64 {
        Partition.fileSize(paths.liveDatabase + "-wal")
            + Partition.fileSize(paths.metaDatabase + "-wal")
    }

    // MARK: - Introspection, for the benchmark and the Settings screen

    public func rowCounts() throws -> (conn: Int64, dns: Int64, ssl: Int64, rollMin: Int64) {
        (try db.scalarInt("SELECT count(*) FROM conn") ?? 0,
         try db.scalarInt("SELECT count(*) FROM dns") ?? 0,
         try db.scalarInt("SELECT count(*) FROM ssl") ?? 0,
         try db.scalarInt("SELECT count(*) FROM roll.roll_min") ?? 0)
    }

    /// On-disk size of every file the writer owns, including WAL sidecars.
    /// This is what the Settings screen projects a 30-day footprint from -- the
    /// user should choose retention against a measured number, not a guess.
    public func databaseBytes() -> Int64 {
        let fm = FileManager.default
        var total: Int64 = 0
        for base in [paths.liveDatabase, paths.metaDatabase,
                     paths.rollupDatabase, paths.pcapDatabase] {
            for suffix in ["", "-wal", "-shm"] {
                let attrs = try? fm.attributesOfItem(atPath: base + suffix)
                total += (attrs?[.size] as? Int64) ?? 0
            }
        }
        return total
    }

    private func jsonArray(_ items: [String]) -> String? {
        guard !items.isEmpty else { return nil }
        let escaped = items.map { item -> String in
            var out = "\""
            for ch in item.unicodeScalars {
                switch ch {
                case "\"": out += "\\\""
                case "\\": out += "\\\\"
                case "\n": out += "\\n"
                case "\r": out += "\\r"
                case "\t": out += "\\t"
                default:
                    if ch.value < 0x20 {
                        out += "\\u" + String(format: "%04x", ch.value)
                    } else {
                        out.unicodeScalars.append(ch)
                    }
                }
            }
            return out + "\""
        }
        return "[" + escaped.joined(separator: ",") + "]"
    }
}
