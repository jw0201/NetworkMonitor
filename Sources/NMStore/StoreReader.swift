//
//  StoreReader.swift
//
//  Read-only queries for the UI.
//
//  One partition is queried at a time and results are merged in Swift, rather
//  than ATTACHing everything and letting SQLite union it. SQLITE_MAX_ATTACHED
//  is 10 in this build and meta/rollup/pcap take three of those, so a 30-day
//  query cannot be expressed as one statement at all. Paging within a day and
//  then crossing the boundary is also exactly what a keyset-paginated view
//  wants to do anyway.
//

import Foundation
import NMCore

public actor StoreReader {

    private let paths: Paths
    private var partitionConnections: [String: SQLiteConnection] = [:]
    /// Which partition a connection covers: nil for the live one.
    private var metaAttached: Set<String> = []

    public private(set) var stats = Stats()

    public struct Stats: Sendable, Equatable {
        public var queries: Int64 = 0
        public var rowsRead: Int64 = 0
        public var partitionsOpened: Int64 = 0
        public var recoveryFallbacks: Int64 = 0
    }

    public init(paths: Paths) {
        self.paths = paths
    }

    // No deinit: an actor's deinit is nonisolated and cannot touch isolated
    // state. Callers close explicitly, which is also the only way to be sure a
    // connection is released at a known point rather than whenever ARC gets to
    // it.
    public func close() {
        for (_, connection) in partitionConnections { connection.close() }
        partitionConnections.removeAll()
        metaAttached.removeAll()
    }

    // MARK: - Partitions

    /// Partition keys, newest first: the live file, then archives by day.
    public func availablePartitions() -> [String] {
        var keys: [String] = []
        if FileManager.default.fileExists(atPath: paths.liveDatabase) { keys.append("live") }
        keys.append(contentsOf: Partition.archives(paths: paths).map(\.day))
        return keys
    }

    private func path(for key: String) -> String {
        key == "live" ? paths.liveDatabase : paths.archiveDatabase(day: key)
    }

    private func connection(for key: String) throws -> SQLiteConnection {
        if let existing = partitionConnections[key] { return existing }

        // A sealed archive never changes, so immutable=1 is both correct and
        // faster: it disables locking and change detection entirely. Using it
        // on the live file would be a serious bug.
        let target = key == "live"
            ? paths.liveDatabase
            : Schema.archiveURI(path: paths.archiveDatabase(day: key))

        let connection: SQLiteConnection
        do {
            connection = try SQLiteConnection(path: target, readOnly: true)
        } catch let error as SQLiteError where error.isReadOnlyRecovery {
            // The daemon was killed with a hot WAL and a read-only connection
            // cannot run recovery. Reported rather than retried, so the UI can
            // say "the service is recovering" instead of showing a corruption
            // error to a user who has done nothing wrong.
            stats.recoveryFallbacks += 1
            throw error
        }

        try Schema.configureReader(connection)

        // meta holds the exec/name/fingerprint dimensions every query joins to.
        let attach = try connection.prepare("ATTACH DATABASE ?1 AS meta")
        attach.bind(1, paths.metaDatabase)
        try attach.run()
        metaAttached.insert(key)

        partitionConnections[key] = connection
        stats.partitionsOpened += 1
        return connection
    }

    // MARK: - Queries

    public func connectionRows(_ spec: QuerySpec) throws -> Page<ConnRow> {
        try page(spec) { connection, key, clause, limit in
            var rows: [ConnRow] = []
            let sql = """
                SELECT c.id, c.uid, c.ts, c.duration_us, c.proto,
                       c.saddr, c.sport, c.daddr, c.dport,
                       n.text, c.host_src, c.host_ambig, c.service, c.state, c.history,
                       c.oipbytes, c.iipbytes, c.opkts, c.ipkts,
                       e.name, p.name, c.loss
                  FROM conn c
                  LEFT JOIN meta.name n ON n.id = c.host_id
                  LEFT JOIN meta.exec e ON e.id = c.exec_id
                  LEFT JOIN meta.exec p ON p.id = c.proxy_exec_id
                 WHERE \(clause.sql)
                 ORDER BY c.ts DESC, c.id DESC
                 LIMIT \(limit)
                """
            let statement = try connection.prepare(sql)
            clause.bind(statement)

            while try statement.step() {
                rows.append(ConnRow(
                    id: statement.int64(0),
                    uid: UInt64(bitPattern: statement.int64(1)),
                    ts: statement.int64(2),
                    durationUs: statement.int64OrNil(3),
                    proto: UInt8(truncatingIfNeeded: statement.int64(4)),
                    localAddress: address(statement.blob(5)),
                    localPort: UInt16(truncatingIfNeeded: statement.int64(6)),
                    remoteAddress: address(statement.blob(7)),
                    remotePort: UInt16(truncatingIfNeeded: statement.int64(8)),
                    hostname: statement.text(9),
                    hostnameSource: statement.int(10),
                    hostnameAmbiguous: statement.bool(11),
                    service: statement.text(12),
                    state: statement.text(13) ?? "OTH",
                    history: statement.text(14) ?? "",
                    bytesOut: statement.int64(15),
                    bytesIn: statement.int64(16),
                    packetsOut: statement.int64(17),
                    packetsIn: statement.int64(18),
                    processName: statement.text(19),
                    proxyName: statement.text(20),
                    lossSuspected: statement.bool(21),
                    day: key))
            }
            statement.reset()
            return rows
        } cursorFor: { row in
            PageCursor(day: row.day, timestamp: row.ts, rowID: row.id)
        }
    }

    public func dnsQueries(_ spec: QuerySpec) throws -> Page<DNSRow> {
        try page(spec) { connection, key, clause, limit in
            var rows: [DNSRow] = []
            let sql = """
                SELECT d.id, d.ts, n.text, d.qtype, d.rcode, d.rtt_us,
                       d.answers, d.rejected, e.name
                  FROM dns d
                  LEFT JOIN meta.name n ON n.id = d.qname_id
                  LEFT JOIN meta.exec e ON e.id = d.exec_id
                 WHERE \(clause.sql)
                 ORDER BY d.ts DESC, d.id DESC
                 LIMIT \(limit)
                """
            let statement = try connection.prepare(sql)
            clause.bind(statement)

            while try statement.step() {
                rows.append(DNSRow(
                    id: statement.int64(0),
                    ts: statement.int64(1),
                    query: statement.text(2) ?? "",
                    qtype: UInt16(truncatingIfNeeded: statement.int64(3)),
                    rcode: UInt16(truncatingIfNeeded: statement.int64(4)),
                    rttUs: statement.int64OrNil(5),
                    answers: decodeJSONArray(statement.text(6)),
                    rejected: statement.bool(7),
                    processName: statement.text(8),
                    day: key))
            }
            statement.reset()
            return rows
        } cursorFor: { row in
            PageCursor(day: row.day, timestamp: row.ts, rowID: row.id)
        }
    }

    public func tlsSessions(_ spec: QuerySpec) throws -> Page<SSLRow> {
        try page(spec) { connection, key, clause, limit in
            var rows: [SSLRow] = []
            let sql = """
                SELECT s.id, s.ts, s.daddr, s.dport, n.text, s.sni_outer,
                       s.version, s.cipher, s.alpn, f.ja4, f.ja3,
                       s.certs_encrypted, s.subject, s.issuer, s.not_after,
                       s.established, e.name
                  FROM ssl s
                  LEFT JOIN meta.name n ON n.id = s.sni_id
                  LEFT JOIN meta.fingerprint f ON f.id = s.fp_id
                  LEFT JOIN meta.exec e ON e.id = s.exec_id
                 WHERE \(clause.sql)
                 ORDER BY s.ts DESC, s.id DESC
                 LIMIT \(limit)
                """
            let statement = try connection.prepare(sql)
            clause.bind(statement)

            while try statement.step() {
                rows.append(SSLRow(
                    id: statement.int64(0),
                    ts: statement.int64(1),
                    serverAddress: address(statement.blob(2)),
                    serverPort: UInt16(truncatingIfNeeded: statement.int64(3)),
                    sni: statement.text(4),
                    sniIsOuter: statement.bool(5),
                    version: UInt16(truncatingIfNeeded: statement.int64(6)),
                    cipher: UInt16(truncatingIfNeeded: statement.int64(7)),
                    alpn: statement.text(8),
                    ja4: statement.text(9),
                    ja3: statement.text(10),
                    certsEncrypted: statement.bool(11),
                    subject: statement.text(12),
                    issuer: statement.text(13),
                    notAfter: statement.int64OrNil(14),
                    established: statement.bool(15),
                    processName: statement.text(16),
                    day: key))
            }
            statement.reset()
            return rows
        } cursorFor: { row in
            PageCursor(day: row.day, timestamp: row.ts, rowID: row.id)
        }
    }

    // MARK: - Paging across partitions

    /// Walks partitions newest-first until `limit` rows are gathered.
    ///
    /// Crossing a day boundary is just moving to the next file: the cursor
    /// carries which partition it was in, so resuming does not re-read
    /// everything that came before.
    private func page<Row: Sendable>(
        _ spec: QuerySpec,
        run: (SQLiteConnection, String, CompiledClause, Int) throws -> [Row],
        cursorFor: (Row) -> PageCursor
    ) throws -> Page<Row> {
        stats.queries += 1

        var partitions = availablePartitions()
        // Resume in the partition the cursor came from, skipping the ones
        // already exhausted.
        if let day = spec.cursor?.day,
           let index = partitions.firstIndex(of: day) {
            partitions = Array(partitions[index...])
        }

        var rows: [Row] = []
        var cursor = spec.cursor

        for (offset, key) in partitions.enumerated() {
            guard rows.count < spec.limit else { break }
            // The cursor only constrains the partition it came from; later ones
            // start from their own newest row.
            let effectiveCursor = offset == 0 ? cursor : nil

            let connection: SQLiteConnection
            do {
                connection = try self.connection(for: key)
            } catch {
                continue    // a partition that cannot be opened is skipped, not fatal
            }

            let clause = CompiledClause(spec.filter, cursor: effectiveCursor,
                                        kind: spec.kind)
            let remaining = spec.limit - rows.count
            let batch = try run(connection, key, clause, remaining)
            rows.append(contentsOf: batch)
            stats.rowsRead += Int64(batch.count)
            cursor = nil
        }

        let next = rows.count == spec.limit ? rows.last.map(cursorFor) : nil
        return Page(rows: rows, next: next)
    }

    // MARK: - Helpers

    private func address(_ bytes: [UInt8]?) -> String {
        guard let bytes, let address = IPAddress(storageBytes: bytes) else { return "—" }
        return address.description
    }

    private func decodeJSONArray(_ text: String?) -> [String] {
        guard let text, let data = text.data(using: .utf8),
              let array = try? JSONDecoder().decode([String].self, from: data) else {
            return []
        }
        return array
    }
}

// MARK: - Filter compilation

/// A filter compiled to a parameterised WHERE clause.
///
/// Values are always bound, never interpolated. User text reaching a query as
/// SQL would be bad anywhere; here it would be bad in a database written by a
/// root process.
struct CompiledClause {
    private(set) var sql: String
    private var texts: [(index: Int32, value: String)] = []
    private var integers: [(index: Int32, value: Int64)] = []
    private var blobs: [(index: Int32, value: [UInt8])] = []

    init(_ filter: QueryFilter, cursor: PageCursor?, kind: LogKind) {
        var conditions: [String] = []
        var index: Int32 = 1
        let alias = kind == .conn ? "c" : (kind == .dns ? "d" : "s")

        // Keyset, never OFFSET. `(ts, id) < (?, ?)` expressed as a disjunction
        // because SQLite does not compare row values against an index usefully.
        if let cursor {
            conditions.append("(\(alias).ts < ?\(index) OR "
                              + "(\(alias).ts = ?\(index) AND \(alias).id < ?\(index + 1)))")
            integers.append((index, cursor.timestamp))
            integers.append((index + 1, cursor.rowID))
            index += 2
        }

        if let since = filter.since {
            conditions.append("\(alias).ts >= ?\(index)")
            integers.append((index, since)); index += 1
        }
        if let until = filter.until {
            conditions.append("\(alias).ts <= ?\(index)")
            integers.append((index, until)); index += 1
        }
        if let process = filter.process {
            conditions.append("e.name = ?\(index)")
            texts.append((index, process)); index += 1
        }

        switch kind {
        case .conn:
            if let host = filter.host {
                conditions.append("n.text = ?\(index)")
                texts.append((index, host)); index += 1
            }
            if let prefix = filter.address {
                // BETWEEN over the BLOB column: an index range scan. Stored as
                // text this would be a full table scan.
                conditions.append("c.daddr BETWEEN ?\(index) AND ?\(index + 1)")
                blobs.append((index, prefix.lower.storageBytes))
                blobs.append((index + 1, prefix.upper.storageBytes))
                index += 2
            }
            if let port = filter.port {
                conditions.append("c.dport = ?\(index)")
                integers.append((index, Int64(port))); index += 1
            }
            if let proto = filter.proto {
                conditions.append("c.proto = ?\(index)")
                integers.append((index, Int64(proto))); index += 1
            }
            if let service = filter.service {
                conditions.append("c.service = ?\(index)")
                texts.append((index, service)); index += 1
            }
            if let state = filter.state {
                conditions.append("c.state = ?\(index)")
                texts.append((index, state)); index += 1
            }
            if let minimum = filter.minimumBytes {
                conditions.append("(c.oipbytes + c.iipbytes) >= ?\(index)")
                integers.append((index, minimum)); index += 1
            }
            if filter.lossOnly { conditions.append("c.loss = 1") }
            if let text = filter.text {
                conditions.append("(n.text LIKE ?\(index) OR e.name LIKE ?\(index))")
                texts.append((index, "%\(text)%")); index += 1
            }

        case .dns:
            if let host = filter.host {
                conditions.append("n.text = ?\(index)")
                texts.append((index, host)); index += 1
            }
            if let text = filter.text {
                conditions.append("(n.text LIKE ?\(index) OR e.name LIKE ?\(index))")
                texts.append((index, "%\(text)%")); index += 1
            }

        case .ssl:
            if let host = filter.host {
                conditions.append("n.text = ?\(index)")
                texts.append((index, host)); index += 1
            }
            if let text = filter.text {
                conditions.append("(n.text LIKE ?\(index) OR e.name LIKE ?\(index) "
                                  + "OR f.ja4 LIKE ?\(index))")
                texts.append((index, "%\(text)%")); index += 1
            }
        }

        sql = conditions.isEmpty ? "1" : conditions.joined(separator: " AND ")
    }

    func bind(_ statement: Statement) {
        for item in texts { statement.bind(item.index, item.value) }
        for item in integers { statement.bind(item.index, item.value) }
        for item in blobs { statement.bind(item.index, item.value) }
    }
}
