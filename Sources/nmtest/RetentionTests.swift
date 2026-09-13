//
//  RetentionTests.swift
//
//  Retention deletes user data, so the tests that matter are the ones that
//  prove it deletes the right things and nothing else.
//

import Foundation
import NMCore
import NMStore
import NMTestKit

private func temporaryRoot(_ name: String) -> String {
    let path = NSTemporaryDirectory() + "nm-retention-\(name)-\(getpid())-\(Int.random(in: 0...99999))"
    try? FileManager.default.removeItem(atPath: path)
    return path
}

private func makeArchive(at paths: Paths, day: String, connRows: Int,
                         dnsRows: Int = 0) {
    try? FileManager.default.createDirectory(atPath: paths.archiveDirectory,
                                             withIntermediateDirectories: true)
    let path = paths.archiveDatabase(day: day)
    guard let db = try? SQLiteConnection(path: path) else { return }
    defer { db.close() }
    try? Schema.createDayPartition(db)

    for i in 0..<connRows {
        guard let s = try? db.prepare("""
            INSERT INTO conn (uid, ts, af, proto, saddr, daddr, sport, dport)
            VALUES (?1, ?2, 2, 6, x'0a000001', x'08080808', 1234, 443)
            """) else { break }
        s.bind(1, Int64(i))
        s.bind(2, Timestamp(i) * 1000)
        try? s.run()
    }
    for i in 0..<dnsRows {
        guard let s = try? db.prepare("""
            INSERT INTO dns (uid, ts, proto, af) VALUES (?1, ?2, 17, 2)
            """) else { break }
        s.bind(1, Int64(i))
        s.bind(2, Timestamp(i) * 1000)
        try? s.run()
    }
}

private func tableExists(_ path: String, _ table: String) -> Bool {
    guard let db = try? SQLiteConnection(path: path, readOnly: true) else { return false }
    defer { db.close() }
    let count = (try? db.scalarInt("""
        SELECT count(*) FROM sqlite_schema WHERE type='table' AND name='\(table)'
        """)) ?? 0
    return (count ?? 0) > 0
}

func runRetentionTests() async {
    NMTest.suite("Partition / day arithmetic") {

        NMTest.test("day differences are computed without a date formatter") {
            NMTest.equal(Partition.ageInDays(day: "2026-09-01", asOf: "2026-09-13"), 12)
            NMTest.equal(Partition.ageInDays(day: "2026-09-13", asOf: "2026-09-13"), 0)
            NMTest.equal(Partition.ageInDays(day: "2025-12-31", asOf: "2026-01-01"), 1)
            NMTest.equal(Partition.ageInDays(day: "2024-02-28", asOf: "2024-03-01"), 2,
                         "2024 is a leap year")
            NMTest.equal(Partition.ageInDays(day: "2023-02-28", asOf: "2023-03-01"), 1)
        }

        NMTest.test("a rotation suffix does not confuse the date") {
            NMTest.equal(Partition.ageInDays(day: "2026-09-01-2", asOf: "2026-09-13"), 12)
        }

        NMTest.test("an unparseable name yields nil rather than a wrong age") {
            NMTest.expect(Partition.ageInDays(day: "garbage", asOf: "2026-09-13") == nil)
            NMTest.expect(Partition.ageInDays(day: "2026-09", asOf: "2026-09-13") == nil)
        }

        NMTest.test("the UTC day string is stable and locale-independent") {
            // 2026-09-13T00:00:00Z exactly.
            let midnight = Timestamp(1_789_257_600) * Time.microsPerSecond
            NMTest.equal(Time.utcDayString(midnight), "2026-09-13")
            NMTest.equal(Time.utcDayString(midnight + 86_399 * Time.microsPerSecond),
                         "2026-09-13", "still the same day one second before midnight")
            NMTest.equal(Time.utcDayString(midnight + 86_400 * Time.microsPerSecond),
                         "2026-09-14")
        }
    }

    NMTest.suite("Partition / rotate and seal") {

        NMTest.test("rotation renames the live file into the archive") {
            let root = temporaryRoot("rotate")
            defer { try? FileManager.default.removeItem(atPath: root) }
            let paths = Paths.temporary(root)
            try FileManager.default.createDirectory(atPath: paths.databaseDirectory,
                                                    withIntermediateDirectories: true)
            do {
                let db = try SQLiteConnection(path: paths.liveDatabase)
                try Schema.createDayPartition(db)
                db.close()
            }

            let destination = try Partition.rotate(paths: paths, day: "2026-09-13")
            NMTest.expect(!FileManager.default.fileExists(atPath: paths.liveDatabase),
                          "the live file must have moved, not been copied")
            NMTest.expect(FileManager.default.fileExists(atPath: destination))
            NMTest.expect(destination.hasSuffix("nm-2026-09-13.db"))
        }

        // Losing a partition because the daemon restarted twice in a day would
        // be silent data loss.
        NMTest.test("rotating twice on one day does not overwrite the first archive") {
            let root = temporaryRoot("twice")
            defer { try? FileManager.default.removeItem(atPath: root) }
            let paths = Paths.temporary(root)
            try FileManager.default.createDirectory(atPath: paths.databaseDirectory,
                                                    withIntermediateDirectories: true)

            var destinations: [String] = []
            for _ in 0..<2 {
                let db = try SQLiteConnection(path: paths.liveDatabase)
                try Schema.createDayPartition(db)
                db.close()
                destinations.append(try Partition.rotate(paths: paths, day: "2026-09-13"))
            }
            NMTest.expect(destinations[0] != destinations[1])
            NMTest.expect(FileManager.default.fileExists(atPath: destinations[0]))
            NMTest.expect(FileManager.default.fileExists(atPath: destinations[1]))
        }

        NMTest.test("sealing removes the WAL sidecars and adds read indices") {
            let root = temporaryRoot("seal")
            defer { try? FileManager.default.removeItem(atPath: root) }
            let paths = Paths.temporary(root)
            makeArchive(at: paths, day: "2026-09-10", connRows: 200)
            let path = paths.archiveDatabase(day: "2026-09-10")

            let sealed = try Partition.seal(archivePath: path, day: "2026-09-10")
            NMTest.equal(sealed.connRows, 200)
            NMTest.expect(sealed.bytes > 0)

            // A sealed file has no -wal, which is what makes a read-only
            // cross-process open free of the -shm write requirement.
            NMTest.expect(!FileManager.default.fileExists(atPath: path + "-wal"))
            NMTest.expect(!FileManager.default.fileExists(atPath: path + "-shm"))

            let db = try SQLiteConnection(path: path, readOnly: true)
            defer { db.close() }
            let mode = try db.scalarText("PRAGMA journal_mode")
            NMTest.equal(mode, "delete")
            let indices = try db.scalarInt("""
                SELECT count(*) FROM sqlite_schema WHERE type='index' AND name='ix_conn_dport'
                """)
            NMTest.equal(indices, 1, "seal-time indices are free on a file nobody writes")
        }

        NMTest.test("a sealed archive is readable and its rows intact") {
            let root = temporaryRoot("readable")
            defer { try? FileManager.default.removeItem(atPath: root) }
            let paths = Paths.temporary(root)
            makeArchive(at: paths, day: "2026-09-10", connRows: 50, dnsRows: 20)
            let path = paths.archiveDatabase(day: "2026-09-10")
            _ = try Partition.seal(archivePath: path, day: "2026-09-10")

            let db = try SQLiteConnection(path: Schema.archiveURI(path: path), readOnly: true)
            defer { db.close() }
            NMTest.equal(try db.scalarInt("SELECT count(*) FROM conn"), 50)
            NMTest.equal(try db.scalarInt("SELECT count(*) FROM dns"), 20)
        }
    }

    NMTest.suite("Retention / expiry") {

        NMTest.test("a file past every retention is unlinked") {
            let root = temporaryRoot("unlink")
            defer { try? FileManager.default.removeItem(atPath: root) }
            let paths = Paths.temporary(root)
            var policy = RetentionPolicy()
            policy.connDays = 30; policy.dnsDays = 14
            policy.sslDays = 30; policy.payloadDays = 7

            makeArchive(at: paths, day: "2026-07-01", connRows: 10)   // 74 days old
            makeArchive(at: paths, day: "2026-09-10", connRows: 10)   // 3 days old

            let report = Retention.run(paths: paths, policy: policy, today: "2026-09-13")
            NMTest.equal(report.filesDeleted, ["2026-07-01"])
            NMTest.expect(!FileManager.default.fileExists(
                atPath: paths.archiveDatabase(day: "2026-07-01")))
            NMTest.expect(FileManager.default.fileExists(
                atPath: paths.archiveDatabase(day: "2026-09-10")),
                "a file inside every retention must be untouched")
        }

        // The case a single flat retention cannot express: dns has expired but
        // conn has not, so the file survives with one table dropped.
        NMTest.test("a file in the mixed band loses only the expired tables") {
            let root = temporaryRoot("mixed")
            defer { try? FileManager.default.removeItem(atPath: root) }
            let paths = Paths.temporary(root)
            var policy = RetentionPolicy()
            policy.connDays = 30; policy.dnsDays = 14
            policy.sslDays = 30; policy.payloadDays = 7

            makeArchive(at: paths, day: "2026-08-25", connRows: 100, dnsRows: 50)  // 19 days
            let path = paths.archiveDatabase(day: "2026-08-25")

            let report = Retention.run(paths: paths, policy: policy, today: "2026-09-13")
            NMTest.expect(report.filesDeleted.isEmpty, "the file itself must survive")
            NMTest.expect(report.filesTrimmed.contains("2026-08-25"))
            NMTest.expect(!tableExists(path, "dns"), "dns is past 14 days")
            NMTest.expect(!tableExists(path, "payload"), "payload is past 7 days")
            NMTest.expect(tableExists(path, "conn"), "conn is inside 30 days")
            NMTest.expect(tableExists(path, "ssl"))
        }

        NMTest.test("a second pass over a trimmed file does no further work") {
            let root = temporaryRoot("idempotent")
            defer { try? FileManager.default.removeItem(atPath: root) }
            let paths = Paths.temporary(root)
            var policy = RetentionPolicy()
            policy.dnsDays = 1
            makeArchive(at: paths, day: "2026-09-01", connRows: 10, dnsRows: 5)

            let first = Retention.run(paths: paths, policy: policy, today: "2026-09-13")
            let second = Retention.run(paths: paths, policy: policy, today: "2026-09-13")
            NMTest.expect(first.filesTrimmed.contains("2026-09-01"))
            NMTest.expect(second.filesTrimmed.isEmpty, "already trimmed; nothing to redo")
        }

        NMTest.test("a bad retention value is clamped rather than deleting everything") {
            var policy = RetentionPolicy()
            policy.connDays = 0
            policy.dnsDays = -5
            let validated = policy.validated()
            NMTest.equal(validated.connDays, 1)
            NMTest.equal(validated.dnsDays, 1)
        }

        NMTest.test("an unparseable archive name is reported, not deleted") {
            let root = temporaryRoot("badname")
            defer { try? FileManager.default.removeItem(atPath: root) }
            let paths = Paths.temporary(root)
            try FileManager.default.createDirectory(atPath: paths.archiveDirectory,
                                                    withIntermediateDirectories: true)
            let stray = paths.archiveDirectory + "/nm-not-a-date.db"
            FileManager.default.createFile(atPath: stray, contents: Data([1, 2, 3]))

            let report = Retention.run(paths: paths, policy: RetentionPolicy(),
                                       today: "2026-09-13")
            NMTest.expect(FileManager.default.fileExists(atPath: stray),
                          "an unrecognised file must never be deleted on a guess")
            NMTest.expect(!report.errors.isEmpty)
        }
    }

    NMTest.suite("Retention / pcap budget") {

        NMTest.test("the ring is trimmed to its budget, oldest first") {
            let root = temporaryRoot("pcap")
            defer { try? FileManager.default.removeItem(atPath: root) }
            let paths = Paths.temporary(root)
            try FileManager.default.createDirectory(atPath: paths.pcapDirectory,
                                                    withIntermediateDirectories: true)

            let chunk = Data(repeating: 0, count: 100_000)
            for i in 0..<10 {
                FileManager.default.createFile(atPath: paths.pcapSegment(sequence: UInt32(i)),
                                               contents: chunk)
            }
            var policy = RetentionPolicy()
            policy.pcapBudgetBytes = 450_000
            policy.freeSpaceFloorBytes = 0

            let report = Retention.run(paths: paths, policy: policy, today: "2026-09-13")
            NMTest.expect(report.pcapFilesDeleted >= 5,
                          "deleted \(report.pcapFilesDeleted)")
            NMTest.expect(!FileManager.default.fileExists(atPath: paths.pcapSegment(sequence: 0)),
                          "the oldest segment goes first")
            NMTest.expect(FileManager.default.fileExists(atPath: paths.pcapSegment(sequence: 9)),
                          "the newest survives")
        }
    }

    await NMTest.suite("Retention / through the writer") {

        await NMTest.test("a day change rotates, seals and catalogs") {
            let root = temporaryRoot("writer")
            defer { try? FileManager.default.removeItem(atPath: root) }

            let day1 = Timestamp(1_789_257_600) * Time.microsPerSecond   // 2026-09-13T00:00Z
            let day2 = day1 + 86_400 * Time.microsPerSecond

            let writer = try StoreWriter(paths: Paths.temporary(root))

            var first = RecordBatch()
            first.conns = [sampleConn(ts: day1 + 1000, uid: 1)]
            try await writer.write(first)

            var second = RecordBatch()
            second.conns = [sampleConn(ts: day2 + 1000, uid: 2)]
            try await writer.write(second)

            let archives = try await writer.archives()
            NMTest.equal(archives.count, 1, "one day closed, one still live")
            NMTest.equal(archives.first?.day, "2026-09-13")
            NMTest.equal(archives.first?.connRows, 1)
            NMTest.equal(await writer.currentDay, "2026-09-14")

            let counts = try await writer.rowCounts()
            NMTest.equal(counts.conn, 1, "the live file holds only the new day")

            await writer.close()
        }

        await NMTest.test("the rollup history survives rotation") {
            let root = temporaryRoot("rollup")
            defer { try? FileManager.default.removeItem(atPath: root) }

            let day1 = Timestamp(1_789_257_600) * Time.microsPerSecond
            let writer = try StoreWriter(paths: Paths.temporary(root))

            for minute in 0..<5 {
                var batch = RecordBatch()
                batch.conns = [sampleConn(ts: day1 + Timestamp(minute) * Time.microsPerMinute,
                                          uid: Int64(minute))]
                try await writer.write(batch)
            }
            var next = RecordBatch()
            next.conns = [sampleConn(ts: day1 + 86_400 * Time.microsPerSecond, uid: 99)]
            try await writer.write(next)
            try await writer.flush()

            let counts = try await writer.rowCounts()
            NMTest.expect(counts.rollMin > 0,
                          "rollups live in their own database and must outlive the partition")
            await writer.close()
        }
    }
}

private func sampleConn(ts: Timestamp, uid: Int64) -> ConnRecord {
    var c = ConnRecord(uid: FlowID(raw: UInt64(uid)), ts: ts, proto: 6,
                       origAddr: IPAddress("10.0.0.1")!, origPort: 40000,
                       respAddr: IPAddress("8.8.8.8")!, respPort: 443,
                       iface: "en0", state: .sf, history: "ShADadFf", pid: 501)
    c.tsEnd = ts + 1000
    c.origIPBytes = 1000
    c.respIPBytes = 2000
    c.origPkts = 5
    c.respPkts = 6
    return c
}

/// Checkpointing has its own schedule because wal_autocheckpoint is off, and
/// nothing else shrinks the WAL. Observed on a live install: 45 minutes of
/// ordinary browsing produced an 8 KB database and a 48 MB WAL.
func runCheckpointTests() async {
    await NMTest.suite("StoreWriter / checkpointing") {

        await NMTest.test("the WAL is reclaimed once it passes the threshold") {
            let root = temporaryRootForCheckpoint()
            defer { try? FileManager.default.removeItem(atPath: root) }
            let paths = Paths.temporary(root)
            let writer = try StoreWriter(paths: paths)

            let base: Timestamp = 1_789_257_600_000_000
            for chunk in 0..<12 {
                var batch = RecordBatch()
                for i in 0..<4_000 {
                    let uid = chunk * 4_000 + i
                    batch.conns.append(sampleConnForCheckpoint(
                        ts: base + Timestamp(uid), uid: Int64(uid)))
                }
                try await writer.write(batch)
            }
            try await writer.flush()

            let before = await writer.walBytes()
            NMTest.expect(before > 0, "the WAL should hold the writes")

            // A low threshold so the test does not have to generate 16 MB.
            _ = await writer.checkpointIfNeeded(thresholdBytes: 64 * 1024)
            let after = await writer.walBytes()

            NMTest.expect(after < before,
                          "WAL went \(before) -> \(after); it must shrink")
            NMTest.expect(await writer.stats.checkpoints > 0)

            // The rows must still be there afterwards.
            let counts = try await writer.rowCounts()
            NMTest.equal(counts.conn, 48_000)
            await writer.close()
        }

        await NMTest.test("a small WAL is left alone") {
            let root = temporaryRootForCheckpoint()
            defer { try? FileManager.default.removeItem(atPath: root) }
            let writer = try StoreWriter(paths: Paths.temporary(root))

            var batch = RecordBatch()
            batch.conns = [sampleConnForCheckpoint(ts: 1_789_257_600_000_000, uid: 1)]
            try await writer.write(batch)

            _ = await writer.checkpointIfNeeded(thresholdBytes: 64 * 1024 * 1024)
            NMTest.equal(await writer.stats.checkpoints, 0,
                         "checkpointing a tiny WAL is pure overhead")
            await writer.close()
        }
    }
}

private func temporaryRootForCheckpoint() -> String {
    let path = NSTemporaryDirectory()
        + "nm-ckpt-\(getpid())-\(Int.random(in: 0...99999))"
    try? FileManager.default.removeItem(atPath: path)
    return path
}

private func sampleConnForCheckpoint(ts: Timestamp, uid: Int64) -> ConnRecord {
    var c = ConnRecord(uid: FlowID(raw: UInt64(uid)), ts: ts, proto: 6,
                       origAddr: IPAddress("10.0.0.1")!, origPort: 40000,
                       respAddr: IPAddress("8.8.8.8")!, respPort: 443,
                       iface: "en0", state: .sf, history: "ShADadFf", pid: 501)
    c.tsEnd = ts + 1000
    c.origIPBytes = 1000
    c.respIPBytes = 2000
    return c
}
