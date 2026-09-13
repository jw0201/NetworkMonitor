//
//  RetentionPolicy.swift
//
//  How long things are kept, and what happens when the disk fills.
//
//  These defaults are tiered rather than uniform, and the reason is measured
//  rather than aesthetic: at 50k conn rows/minute the store costs about 19 GB
//  per day, so a flat 30-day raw retention needs roughly 580 GB. That does not
//  fit a typical laptop disk. Raw records therefore expire quickly and the
//  rollups -- which are four orders of magnitude smaller -- carry the long
//  history the dashboard actually reads.
//
//  The numbers are settings, not constants, because the right answer depends on
//  how much traffic a machine actually sees. The Settings screen shows a
//  projection computed from measured bytes/row so the choice is made against a
//  real figure rather than a guess.
//

import Foundation
import NMCore

public struct RetentionPolicy: Sendable, Codable, Equatable {

    // Raw records, in days.
    public var connDays: Int = 30
    public var dnsDays: Int = 14
    public var sslDays: Int = 30
    /// Payload bytes are the most sensitive thing the product stores, so they
    /// get the shortest life regardless of what else is configured.
    public var payloadDays: Int = 7

    // Aggregates. Cheap, so they outlive the rows they came from.
    public var rollupMinuteDays: Int = 2
    public var rollupHourDays: Int = 90
    public var rollupDayDays: Int = 3650

    /// Alerts live in meta and carry a JSON snapshot, so they stay meaningful
    /// after the rows that produced them are gone.
    public var alertDays: Int = 365

    /// Packet ring, in bytes.
    public var pcapBudgetBytes: Int64 = 20 * 1024 * 1024 * 1024
    /// Stop writing packets entirely below this much free space. Filling a
    /// user's boot volume is not a trade-off, it is a bug.
    public var freeSpaceFloorBytes: Int64 = 2 * 1024 * 1024 * 1024

    /// Rotate early if today's file gets this large, so a very busy day does
    /// not produce one enormous partition.
    public var maximumLiveBytes: Int64 = 4 * 1024 * 1024 * 1024

    public init() {}

    /// The longest any raw record is kept. A day file older than this can be
    /// unlinked outright without opening it.
    public var maximumRawDays: Int {
        max(connDays, max(dnsDays, max(sslDays, payloadDays)))
    }

    /// The shortest raw retention. Between this and `maximumRawDays` a file
    /// holds some tables that have expired and some that have not.
    public var minimumRawDays: Int {
        min(connDays, min(dnsDays, min(sslDays, payloadDays)))
    }

    /// Tables whose retention has elapsed for a file of this age.
    public func expiredTables(ageInDays: Int) -> [String] {
        var tables: [String] = []
        if ageInDays > connDays { tables.append("conn") }
        if ageInDays > dnsDays { tables.append("dns") }
        if ageInDays > sslDays { tables.append("ssl") }
        if ageInDays > payloadDays { tables.append("payload") }
        return tables
    }

    public func validated() -> RetentionPolicy {
        var p = self
        // A retention of zero would delete data before it could be read, and a
        // negative one is meaningless. Clamp rather than reject, so a bad value
        // in a config file does not stop the daemon starting.
        p.connDays = max(1, connDays)
        p.dnsDays = max(1, dnsDays)
        p.sslDays = max(1, sslDays)
        p.payloadDays = max(1, payloadDays)
        p.rollupMinuteDays = max(1, rollupMinuteDays)
        p.rollupHourDays = max(1, rollupHourDays)
        p.alertDays = max(1, alertDays)
        p.pcapBudgetBytes = max(0, pcapBudgetBytes)
        p.freeSpaceFloorBytes = max(0, freeSpaceFloorBytes)
        p.maximumLiveBytes = max(64 * 1024 * 1024, maximumLiveBytes)
        return p
    }
}

/// What a maintenance pass did. Reported rather than silent, because deleting
/// a user's data without saying so is the kind of thing people only notice
/// when they go looking for something that is gone.
public struct RetentionReport: Sendable, Equatable {
    public var filesDeleted: [String] = []
    public var filesTrimmed: [String] = []
    public var tablesTrimmed: [String] = []
    public var bytesReclaimed: Int64 = 0
    public var pcapFilesDeleted = 0
    public var pcapBytesReclaimed: Int64 = 0
    public var rollupRowsDeleted: Int64 = 0
    public var errors: [String] = []

    public var didAnything: Bool {
        !filesDeleted.isEmpty || !filesTrimmed.isEmpty || pcapFilesDeleted > 0
            || rollupRowsDeleted > 0
    }
}
