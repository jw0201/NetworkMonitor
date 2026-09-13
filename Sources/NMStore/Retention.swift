//
//  Retention.swift
//
//  Enforcing the policy.
//
//  Three shapes of expiry, in decreasing order of how cheap they are:
//
//    1. A day file past EVERY retention: unlink(). No open, no lock, no
//       transaction. This is the common case and it costs nothing.
//    2. A day file in the mixed band -- older than the shortest retention but
//       younger than the longest -- gets opened once in its life to drop the
//       tables that have expired, then incremental-vacuumed.
//    3. Rollups and alerts live in their own databases and expire by row.
//
//  A file is never partially deleted twice: once trimmed, the catalog records
//  which tables are gone so the next pass skips it.
//

import Foundation
import NMCore

public enum Retention {

    /// Runs one maintenance pass.
    ///
    /// `today` is passed rather than read from the clock so the caller controls
    /// it -- tests need to age files without waiting, and the daemon wants one
    /// consistent "now" across a whole pass rather than a clock that ticks
    /// between steps.
    public static func run(paths: Paths, policy: RetentionPolicy,
                           today: String) -> RetentionReport {
        var report = RetentionReport()
        let policy = policy.validated()

        for archive in Partition.archives(paths: paths) {
            guard let age = Partition.ageInDays(day: archive.day, asOf: today) else {
                report.errors.append("unparseable archive name: \(archive.day)")
                continue
            }
            guard age > policy.minimumRawDays else { continue }

            if age > policy.maximumRawDays {
                let size = Partition.fileSize(archive.path)
                do {
                    try FileManager.default.removeItem(atPath: archive.path)
                    report.filesDeleted.append(archive.day)
                    report.bytesReclaimed += size
                } catch {
                    report.errors.append("cannot delete \(archive.day): \(error)")
                }
                continue
            }

            // Mixed band: some tables have expired, some have not.
            let expired = policy.expiredTables(ageInDays: age)
            guard !expired.isEmpty else { continue }
            do {
                let trimmed = try trim(archive.path, tables: expired)
                if !trimmed.isEmpty {
                    report.filesTrimmed.append(archive.day)
                    report.tablesTrimmed.append(contentsOf: trimmed.map { "\(archive.day)/\($0)" })
                }
            } catch {
                report.errors.append("cannot trim \(archive.day): \(error)")
            }
        }

        trimRollups(paths: paths, policy: policy, today: today, report: &report)
        enforcePcapBudget(paths: paths, policy: policy, report: &report)
        return report
    }

    /// Drops expired tables from one archive.
    ///
    /// A table that has already been dropped is skipped rather than re-dropped,
    /// so repeated passes over the same file do no work.
    private static func trim(_ path: String, tables: [String]) throws -> [String] {
        let db = try SQLiteConnection(path: path)
        defer { db.close() }

        var dropped: [String] = []
        for table in tables {
            let exists = try db.scalarInt("""
                SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = '\(table)'
                """) ?? 0
            guard exists > 0 else { continue }
            try db.exec("DROP TABLE \(table)")
            dropped.append(table)
        }
        guard !dropped.isEmpty else { return [] }

        // Reclaim the freed pages in bounded chunks. A sealed archive has
        // auto_vacuum = INCREMENTAL precisely so this does not have to rewrite
        // the whole file.
        try db.exec("PRAGMA incremental_vacuum")
        try db.exec("PRAGMA optimize")
        return dropped
    }

    private static func trimRollups(paths: Paths, policy: RetentionPolicy,
                                    today: String, report: inout RetentionReport) {
        guard FileManager.default.fileExists(atPath: paths.rollupDatabase) else { return }
        guard let todayNumber = Partition.dayNumber(today) else { return }

        do {
            let db = try SQLiteConnection(path: paths.rollupDatabase)
            defer { db.close() }
            try db.exec("PRAGMA busy_timeout = 5000")

            // Buckets are unit-of-time counters since the epoch, so the cutoff
            // is arithmetic rather than a date comparison.
            let cutoffs: [(table: String, column: String, cutoff: Int64)] = [
                ("roll_min", "bucket",
                 Int64(todayNumber - policy.rollupMinuteDays) * 24 * 60),
                ("roll_hour", "bucket",
                 Int64(todayNumber - policy.rollupHourDays) * 24),
                ("roll_day", "bucket",
                 Int64(todayNumber - policy.rollupDayDays)),
                ("roll_peer_hour", "bucket",
                 Int64(todayNumber - policy.rollupHourDays) * 24),
                ("roll_dns_hour", "bucket",
                 Int64(todayNumber - policy.rollupHourDays) * 24),
            ]

            for (table, column, cutoff) in cutoffs where cutoff > 0 {
                let statement = try db.prepare("DELETE FROM \(table) WHERE \(column) < ?1")
                statement.bind(1, cutoff)
                try statement.run()
                report.rollupRowsDeleted += Int64(db.changes)
            }
        } catch {
            report.errors.append("rollup trim failed: \(error)")
        }
    }

    /// Keeps the packet ring inside its byte budget, oldest first.
    ///
    /// Also honours a free-space floor. A capture tool that fills the user's
    /// boot volume has done something much worse than lose some packets.
    private static func enforcePcapBudget(paths: Paths, policy: RetentionPolicy,
                                          report: inout RetentionReport) {
        let fm = FileManager.default
        guard let names = try? fm.contentsOfDirectory(atPath: paths.pcapDirectory) else {
            return
        }

        var segments = names
            .filter { $0.hasPrefix("nm-") && $0.hasSuffix(".pcap") }
            .map { (path: paths.pcapDirectory + "/" + $0,
                    size: Partition.fileSize(paths.pcapDirectory + "/" + $0)) }
            .sorted { $0.path < $1.path }          // filenames are zero-padded sequence numbers

        var total = segments.reduce(Int64(0)) { $0 + $1.size }
        let free = Partition.freeSpace(at: paths.pcapDirectory)
        // Under the floor, shed harder than the budget alone would.
        let effectiveBudget = free < policy.freeSpaceFloorBytes
            ? total / 2
            : policy.pcapBudgetBytes

        while total > effectiveBudget, !segments.isEmpty {
            let oldest = segments.removeFirst()
            do {
                try fm.removeItem(atPath: oldest.path)
                total -= oldest.size
                report.pcapFilesDeleted += 1
                report.pcapBytesReclaimed += oldest.size
            } catch {
                report.errors.append("cannot delete \(oldest.path): \(error)")
                break
            }
        }
    }

    /// Projected disk use at the current rate, for the Settings screen.
    ///
    /// The point of showing this is that retention should be chosen against a
    /// measured figure. At a heavy rate a flat 30-day raw retention needs more
    /// space than a laptop has, and a number on screen makes that obvious
    /// before the disk fills rather than after.
    public static func projection(bytesPerRow: Double, rowsPerMinute: Double,
                                  policy: RetentionPolicy) -> (perDay: Int64, total: Int64) {
        let perDay = bytesPerRow * rowsPerMinute * 60 * 24
        // Raw records dominate; the rollups are negligible by comparison.
        let days = Double(policy.maximumRawDays)
        return (Int64(perDay), Int64(perDay * days))
    }
}
