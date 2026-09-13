//
//  Timestamp.swift
//
//  One time representation for the whole system: INTEGER microseconds since
//  the Unix epoch, UTC.
//
//  Why not Double/REAL: today's values are ~1.76e15 microseconds. That is still
//  under 2^53 so a Double holds it exactly, but only by one order of magnitude,
//  and a float makes BETWEEN boundaries and de-duplication keys subtly wrong.
//  A primary key component must never be a float.
//
//  Why not ISO-8601 TEXT: 27 bytes instead of 8. At 72M rows/day that choice
//  alone costs over a gigabyte a day, and every comparison becomes a string
//  compare.
//
//  pcap hands us a `struct timeval` (seconds + microseconds), so integer
//  microseconds is also the lossless, conversion-free landing spot.
//
//  All formatting to local time happens in the UI. Nothing below the UI ever
//  thinks about time zones -- day partitions roll on UTC boundaries precisely
//  so that DST does not produce a duplicated or missing hour twice a year.
//

public typealias Timestamp = Int64

public enum Time {
    public static let microsPerSecond: Int64 = 1_000_000
    public static let microsPerMinute: Int64 = 60 * 1_000_000
    public static let microsPerHour: Int64 = 3_600 * 1_000_000
    public static let microsPerDay: Int64 = 86_400 * 1_000_000

    @inlinable
    public static func micros(seconds: Int64, microseconds: Int64) -> Timestamp {
        seconds * microsPerSecond + microseconds
    }

    /// From the `struct timeval` a pcap header carries.
    @inlinable
    public static func micros(timevalSec: Int, timevalUsec: Int32) -> Timestamp {
        Int64(timevalSec) * microsPerSecond + Int64(timevalUsec)
    }

    // MARK: - Bucketing
    //
    // Integer division, which the benchmark showed is effectively free even
    // over millions of rows. These are the bucket keys for the rollup tables.

    @inlinable public static func minuteBucket(_ ts: Timestamp) -> Int64 { ts / microsPerMinute }
    @inlinable public static func hourBucket(_ ts: Timestamp) -> Int64 { ts / microsPerHour }
    @inlinable public static func dayBucket(_ ts: Timestamp) -> Int64 { ts / microsPerDay }

    @inlinable public static func startOfMinute(_ ts: Timestamp) -> Timestamp {
        minuteBucket(ts) * microsPerMinute
    }
    @inlinable public static func startOfDayUTC(_ ts: Timestamp) -> Timestamp {
        dayBucket(ts) * microsPerDay
    }

    // MARK: - Day partition naming

    /// "2026-09-13" for the UTC day containing `ts`. This is the archive file
    /// name, so it must be stable and never depend on the machine's locale.
    public static func utcDayString(_ ts: Timestamp) -> String {
        let days = Int(dayBucket(ts))
        var (y, m, d) = civilFromDays(days)
        if ts < 0 && ts % microsPerDay != 0 { (y, m, d) = civilFromDays(days - 1) }
        return "\(pad4(y))-\(pad2(m))-\(pad2(d))"
    }

    /// Howard Hinnant's days-from-civil, inverted. Pure integer arithmetic, no
    /// Foundation, no locale, correct for any proleptic Gregorian date.
    static func civilFromDays(_ z0: Int) -> (year: Int, month: Int, day: Int) {
        var z = z0
        z += 719_468
        let era = (z >= 0 ? z : z - 146_096) / 146_097
        let doe = z - era * 146_097                                   // 0...146096
        let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365
        let y = yoe + era * 400
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100)             // 0...365
        let mp = (5 * doy + 2) / 153                                  // 0...11
        let d = doy - (153 * mp + 2) / 5 + 1                          // 1...31
        let m = mp < 10 ? mp + 3 : mp - 9                             // 1...12
        return (m <= 2 ? y + 1 : y, m, d)
    }

    private static func pad2(_ n: Int) -> String { n < 10 ? "0\(n)" : "\(n)" }
    private static func pad4(_ n: Int) -> String {
        n < 10 ? "000\(n)" : n < 100 ? "00\(n)" : n < 1000 ? "0\(n)" : "\(n)"
    }
}
