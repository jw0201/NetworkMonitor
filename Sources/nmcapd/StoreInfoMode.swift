//
//  StoreInfoMode.swift
//
//  `nmcapd --store-info <dir> [--run-retention]` -- what is on disk, what it
//  projects to, and what retention would remove.
//
//  Retention deletes user data, so it is inspectable before it runs. The
//  default is a dry report; deletion needs an explicit flag.
//

import Foundation
import NMCore
import NMStore

func runStoreInfo(root: String, applyRetention: Bool) async -> Int32 {
    let paths = Paths.temporary(root)
    let fm = FileManager.default

    guard fm.fileExists(atPath: paths.databaseDirectory) else {
        print("no store at \(root)")
        return 1
    }

    print("""
    NetworkMonitor store
    ====================
    root       \(root)
    """)

    // MARK: Live partition

    let liveBytes = Partition.fileSize(paths.liveDatabase)
        + Partition.fileSize(paths.liveDatabase + "-wal")
    var liveRows: Int64 = 0
    var liveDay = "-"
    if let db = try? SQLiteConnection(path: paths.liveDatabase, readOnly: true) {
        liveRows = ((try? db.scalarInt("SELECT count(*) FROM conn")) ?? nil) ?? 0
        if let latest = ((try? db.scalarInt("SELECT max(ts) FROM conn")) ?? nil), latest > 0 {
            liveDay = Time.utcDayString(latest)
        }
        db.close()
    }

    print("""

    Live partition
    \(rule())
      day               \(liveDay)
      conn rows         \(formatted(Int(liveRows)))
      size              \(humanBytes(liveBytes))
    """)

    // MARK: Archives

    let archives = Partition.archives(paths: paths)
    let today = Time.utcDayString(Timestamp(Date().timeIntervalSince1970 * 1_000_000))
    let policy = RetentionPolicy()

    if archives.isEmpty {
        print("\n  no sealed archives yet")
    } else {
        print("""

        Archives
        \(rule())
          \(pad("day", 14))\(pad("age", 8))\(pad("size", 12))\(pad("conn", 12))status
        """)
        var archiveBytes: Int64 = 0
        for archive in archives.prefix(40) {
            let size = Partition.fileSize(archive.path)
            archiveBytes += size
            let age = Partition.ageInDays(day: archive.day, asOf: today)
            var rows: Int64 = 0
            if let db = try? SQLiteConnection(path: archive.path, readOnly: true) {
                rows = ((try? db.scalarInt("SELECT count(*) FROM conn")) ?? nil) ?? 0
                db.close()
            }

            let status: String
            if let age {
                if age > policy.maximumRawDays { status = "expired -- would be deleted" }
                else if !policy.expiredTables(ageInDays: age).isEmpty {
                    status = "trim: " + policy.expiredTables(ageInDays: age).joined(separator: ", ")
                } else { status = "retained" }
            } else {
                status = "unrecognised name -- never deleted automatically"
            }

            print("  " + pad(archive.day, 14)
                  + pad(age.map { "\($0)d" } ?? "?", 8)
                  + pad(humanBytes(size), 12)
                  + pad(formatted(Int(rows)), 12) + status)
        }
        print("\n  total archived   \(humanBytes(archiveBytes))")
    }

    // MARK: Projection

    let totalRows = liveRows + archives.reduce(Int64(0)) { sum, archive in
        guard let db = try? SQLiteConnection(path: archive.path, readOnly: true) else { return sum }
        defer { db.close() }
        return sum + (((try? db.scalarInt("SELECT count(*) FROM conn")) ?? nil) ?? 0)
    }
    let totalBytes = liveBytes + archives.reduce(Int64(0)) { $0 + Partition.fileSize($1.path) }

    // A projection from a nearly empty store is nonsense: SQLite allocates
    // pages and indices up front, so a handful of rows measures the fixed
    // overhead rather than the marginal cost. Below this threshold, say so and
    // fall back to the figure the storage benchmark measured over 800k rows.
    let minimumRowsForProjection: Int64 = 10_000
    let benchmarkedBytesPerRow = 175.0

    if totalRows > 0 {
        let measured = Double(totalBytes) / Double(totalRows)
        let haveEnough = totalRows >= minimumRowsForProjection
        let bytesPerRow = haveEnough ? measured : benchmarkedBytesPerRow
        print("""

        Retention policy and projection
        \(rule())
          conn \(policy.connDays)d   dns \(policy.dnsDays)d   ssl \(policy.sslDays)d   \
        payload \(policy.payloadDays)d
          rollups: minute \(policy.rollupMinuteDays)d, hour \(policy.rollupHourDays)d
          pcap ring budget  \(humanBytes(policy.pcapBudgetBytes))

          bytes/row         \(String(format: "%.0f", bytesPerRow))\
        \(haveEnough ? " measured over \(formatted(Int(totalRows))) rows"
                     : " (benchmark figure)")
        """)

        if !haveEnough {
            print("""
              Only \(formatted(Int(totalRows))) rows on disk, which measures SQLite's fixed
              page and index overhead rather than the marginal cost per row
              (\(String(format: "%.0f", measured)) bytes/row here). Projecting from that would be
              meaningless, so the figure below uses the benchmarked value instead.
            """)
        }

        // Retention should be chosen against a measured figure. At a heavy rate
        // a flat 30-day raw retention needs more space than a laptop has, and
        // seeing that before the disk fills is the entire point of printing it.
        for rate in [5_000.0, 50_000.0] {
            let projection = Retention.projection(bytesPerRow: bytesPerRow,
                                                  rowsPerMinute: rate, policy: policy)
            let free = Partition.freeSpace(at: paths.databaseDirectory)
            let warning = projection.total > free ? "  EXCEEDS FREE SPACE" : ""
            print("""
              at \(formatted(Int(rate))) rows/min:  \(humanBytes(projection.perDay))/day, \
            \(humanBytes(projection.total)) over \(policy.maximumRawDays) days\(warning)
            """)
        }
        print("  free space        \(humanBytes(Partition.freeSpace(at: paths.databaseDirectory)))")
    }

    // MARK: Retention

    if applyRetention {
        print("\n  running retention...")
        let report = Retention.run(paths: paths, policy: policy, today: today)
        if report.didAnything {
            if !report.filesDeleted.isEmpty {
                print("  deleted   \(report.filesDeleted.joined(separator: ", "))  "
                      + "(\(humanBytes(report.bytesReclaimed)))")
            }
            if !report.tablesTrimmed.isEmpty {
                print("  trimmed   \(report.tablesTrimmed.joined(separator: ", "))")
            }
            if report.pcapFilesDeleted > 0 {
                print("  pcap      \(report.pcapFilesDeleted) segment(s), "
                      + "\(humanBytes(report.pcapBytesReclaimed))")
            }
            if report.rollupRowsDeleted > 0 {
                print("  rollups   \(report.rollupRowsDeleted) row(s)")
            }
        } else {
            print("  nothing to do")
        }
        for error in report.errors { print("  ERROR  \(error)") }
    } else if !archives.isEmpty {
        print("\n  (dry report -- pass --run-retention to actually delete)")
    }

    return 0
}

private func rule() -> String { String(repeating: "-", count: 70) }

private func pad(_ s: String, _ width: Int) -> String {
    s.count >= width ? String(s.prefix(width - 1)) + " "
                     : s + String(repeating: " ", count: width - s.count)
}

private func humanBytes(_ n: Int64) -> String {
    if n < 1024 { return "\(n) B" }
    if n < 1024 * 1024 { return String(format: "%.1f KB", Double(n) / 1024) }
    if n < 1024 * 1024 * 1024 { return String(format: "%.1f MB", Double(n) / 1_048_576) }
    return String(format: "%.1f GB", Double(n) / 1_073_741_824)
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
