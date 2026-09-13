//
//  Partition.swift
//
//  Day rotation and sealing.
//
//  Rotation is rename(). That is the whole reason the store is split into day
//  files: retention becomes unlink(), which is O(1), takes no lock, needs no
//  free space, and stalls nothing. The alternative -- one database with a
//  nightly DELETE -- writes every freed page to the WAL (costlier in I/O than
//  the original insert), never shrinks the file, and if corrected with VACUUM
//  takes an exclusive lock for minutes on a laptop SSD.
//
//  Sealing is the other half. A file nobody will ever write again can carry as
//  many read indices as queries want, at zero cost to the hot write path, and
//  it can drop its WAL entirely -- which also removes the -shm permission
//  problem that makes cross-process reads of a live WAL database awkward.
//

import Foundation
import NMCore

public struct SealedArchive: Sendable, Equatable {
    public var path: String
    public var day: String
    public var bytes: Int64
    public var connRows: Int64
    public var dnsRows: Int64
    public var sslRows: Int64
    public var firstTimestamp: Timestamp?
    public var lastTimestamp: Timestamp?
    /// Size before VACUUM, so the compaction is visible rather than assumed.
    public var bytesBeforeCompaction: Int64
}

public enum PartitionError: Error, CustomStringConvertible {
    case liveFileMissing(String)
    case archiveExists(String)
    case renameFailed(String, String, errno: Int32)

    public var description: String {
        switch self {
        case .liveFileMissing(let p): return "no live database at \(p)"
        case .archiveExists(let p): return "archive already exists: \(p)"
        case .renameFailed(let from, let to, let e):
            return "cannot rename \(from) -> \(to): \(String(cString: strerror(e)))"
        }
    }
}

public enum Partition {

    /// Moves `live.db` to the archive directory under the day it covers.
    ///
    /// The caller must have checkpointed and closed the database first: this is
    /// a filesystem operation and knows nothing about open handles.
    ///
    /// The -wal and -shm sidecars are removed rather than moved. After a
    /// TRUNCATE checkpoint the WAL holds nothing, and a clean close deletes
    /// them -- but a previous crash can leave them behind, and carrying a stale
    /// WAL into an archive would make the archive look like it needs recovery.
    public static func rotate(paths: Paths, day: String) throws -> String {
        let live = paths.liveDatabase
        let destination = paths.archiveDatabase(day: day)
        let fm = FileManager.default

        guard fm.fileExists(atPath: live) else {
            throw PartitionError.liveFileMissing(live)
        }

        // A second rotation on the same day appends a suffix rather than
        // overwriting: losing a partition because the daemon restarted twice
        // would be a silent data loss.
        var finalDestination = destination
        var suffix = 1
        while fm.fileExists(atPath: finalDestination) {
            finalDestination = paths.archiveDatabase(day: "\(day)-\(suffix)")
            suffix += 1
            if suffix > 99 { throw PartitionError.archiveExists(destination) }
        }

        try fm.createDirectory(atPath: paths.archiveDirectory,
                               withIntermediateDirectories: true,
                               attributes: [.posixPermissions: 0o750])

        guard rename(live, finalDestination) == 0 else {
            throw PartitionError.renameFailed(live, finalDestination, errno: errno)
        }

        for sidecar in ["-wal", "-shm"] {
            try? fm.removeItem(atPath: live + sidecar)
        }
        return finalDestination
    }

    /// Prepares an archive for a life of being read and never written.
    ///
    /// Steps, in this order for a reason:
    ///   1. journal_mode = DELETE, so the file has no -wal/-shm at all. A
    ///      read-only connection to a WAL database needs WRITE access to the
    ///      -shm, which is exactly the cross-process permission trap that makes
    ///      sharing a live database awkward. A sealed file simply does not have
    ///      the problem.
    ///   2. Build the extra read indices. Free here, because nothing is
    ///      competing for the write path.
    ///   3. VACUUM INTO a temporary file, then replace. This compacts and
    ///      defragments in one pass, and doing it via INTO rather than in-place
    ///      VACUUM means no exclusive lock on anything anyone might be reading.
    @discardableResult
    public static func seal(archivePath: String, day: String) throws -> SealedArchive {
        let fm = FileManager.default
        let sizeBefore = fileSize(archivePath)

        var counts = (conn: Int64(0), dns: Int64(0), ssl: Int64(0))
        var range: (first: Timestamp?, last: Timestamp?) = (nil, nil)

        do {
            let db = try SQLiteConnection(path: archivePath)
            defer { db.close() }
            _ = try db.pragma("journal_mode = DELETE")
            try db.exec("PRAGMA auto_vacuum = INCREMENTAL")
            try db.exec(Schema.archiveSealDDL)
            try db.exec("ANALYZE")

            counts.conn = try db.scalarInt("SELECT count(*) FROM conn") ?? 0
            counts.dns = try db.scalarInt("SELECT count(*) FROM dns") ?? 0
            counts.ssl = try db.scalarInt("SELECT count(*) FROM ssl") ?? 0
            range.first = try db.scalarInt("SELECT min(ts) FROM conn")
            range.last = try db.scalarInt("SELECT max(ts) FROM conn")
        }

        // Compact into a sibling, then swap. If anything fails the original is
        // still there and still readable.
        let temporary = archivePath + ".compacting"
        try? fm.removeItem(atPath: temporary)
        do {
            let db = try SQLiteConnection(path: archivePath)
            defer { db.close() }
            let statement = try db.prepare("VACUUM INTO ?1")
            statement.bind(1, temporary)
            try statement.run()
        }

        if fm.fileExists(atPath: temporary) {
            try? fm.removeItem(atPath: archivePath)
            guard rename(temporary, archivePath) == 0 else {
                throw PartitionError.renameFailed(temporary, archivePath, errno: errno)
            }
        }

        // Group-readable, never world-readable: these files hold every user's
        // browsing metadata and, if payload capture is on, plaintext bytes.
        try? fm.setAttributes([.posixPermissions: 0o640], ofItemAtPath: archivePath)

        return SealedArchive(path: archivePath, day: day,
                             bytes: fileSize(archivePath),
                             connRows: counts.conn, dnsRows: counts.dns, sslRows: counts.ssl,
                             firstTimestamp: range.first, lastTimestamp: range.last,
                             bytesBeforeCompaction: sizeBefore)
    }

    /// Archive files present, newest first.
    public static func archives(paths: Paths) -> [(path: String, day: String)] {
        let fm = FileManager.default
        guard let names = try? fm.contentsOfDirectory(atPath: paths.archiveDirectory) else {
            return []
        }
        return names
            .filter { $0.hasPrefix("nm-") && $0.hasSuffix(".db") }
            .compactMap { name in
                let day = String(name.dropFirst(3).dropLast(3))
                guard day.count >= 10 else { return nil }
                return (paths.archiveDirectory + "/" + name, day)
            }
            .sorted { $0.day > $1.day }
    }

    /// Whole days between two "YYYY-MM-DD" strings.
    ///
    /// Parsed and differenced arithmetically rather than through a date
    /// formatter: retention must not depend on the machine's locale or time
    /// zone, and a file named for a UTC day means the same thing everywhere.
    public static func ageInDays(day: String, asOf today: String) -> Int? {
        guard let a = dayNumber(day), let b = dayNumber(today) else { return nil }
        return b - a
    }

    static func dayNumber(_ text: String) -> Int? {
        // Accept a rotation suffix ("2026-09-13-1") by taking the date prefix.
        let parts = text.split(separator: "-")
        guard parts.count >= 3,
              let year = Int(parts[0]), let month = Int(parts[1]),
              let day = Int(parts[2]) else { return nil }
        return daysFromCivil(year: year, month: month, day: day)
    }

    /// Howard Hinnant's days-from-civil. Pure integer arithmetic, correct for
    /// any proleptic Gregorian date, no Foundation and no locale.
    static func daysFromCivil(year: Int, month: Int, day: Int) -> Int {
        let y = month <= 2 ? year - 1 : year
        let era = (y >= 0 ? y : y - 399) / 400
        let yoe = y - era * 400
        let mp = (month + 9) % 12
        let doy = (153 * mp + 2) / 5 + day - 1
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        return era * 146_097 + doe - 719_468
    }

    public static func fileSize(_ path: String) -> Int64 {
        let attributes = try? FileManager.default.attributesOfItem(atPath: path)
        return (attributes?[.size] as? Int64) ?? 0
    }

    /// Free space on the volume holding `path`.
    public static func freeSpace(at path: String) -> Int64 {
        guard let values = try? URL(fileURLWithPath: path)
            .resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey]),
              let capacity = values.volumeAvailableCapacityForImportantUsage else {
            return Int64.max
        }
        return capacity
    }
}
