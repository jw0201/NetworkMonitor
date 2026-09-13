//
//  QuerySpec.swift
//
//  What the UI asks for, and where it left off.
//
//  The cursor is the important type here. Pagination is keyset, never OFFSET,
//  for two reasons -- one measured and one correctness:
//
//    * OFFSET N makes SQLite produce and discard N rows. Measured at 500k rows,
//      a page deep in the table cost 8.26 ms against 0.07 ms for the keyset
//      equivalent, and it degrades linearly as you scroll.
//    * The daemon writes while a person browses, which is the NORMAL state
//      here. A row inserted at the head shifts every subsequent page boundary,
//      so an offset-paginated view shows duplicated and skipped rows. A keyset
//      cursor is anchored to data rather than to position.
//

import Foundation
import NMCore

/// Which log a query is against.
public enum LogKind: String, Sendable, CaseIterable {
    case conn, dns, ssl
}

/// Where a page ended, so the next one can resume exactly there.
///
/// `(ts, id)` rather than `ts` alone: timestamps collide constantly at
/// microsecond resolution under load, and a cursor on a non-unique column
/// either repeats or skips rows at every page boundary.
public struct PageCursor: Sendable, Equatable, Codable {
    public var day: String?
    public var timestamp: Timestamp
    public var rowID: Int64

    public init(day: String? = nil, timestamp: Timestamp, rowID: Int64) {
        self.day = day
        self.timestamp = timestamp
        self.rowID = rowID
    }
}

/// A parsed filter.
///
/// Deliberately a small closed set rather than free-form SQL. Everything here
/// compiles to a parameterised clause -- user text never reaches the query as
/// SQL, because this runs against a database written by a root process.
public struct QueryFilter: Sendable, Equatable {
    public var text: String?
    public var process: String?
    public var host: String?
    public var address: IPPrefix?
    public var port: UInt16?
    public var proto: UInt8?
    public var service: String?
    public var state: String?
    public var minimumBytes: Int64?
    public var since: Timestamp?
    public var until: Timestamp?
    /// Only connections whose byte counts are known to be approximate.
    public var lossOnly = false

    public init() {}

    public var isEmpty: Bool {
        text == nil && process == nil && host == nil && address == nil
            && port == nil && proto == nil && service == nil && state == nil
            && minimumBytes == nil && since == nil && until == nil && !lossOnly
    }
}

public struct QuerySpec: Sendable {
    public var kind: LogKind
    public var filter: QueryFilter
    public var limit: Int
    public var cursor: PageCursor?

    public init(kind: LogKind, filter: QueryFilter = QueryFilter(),
                limit: Int = 200, cursor: PageCursor? = nil) {
        self.kind = kind
        self.filter = filter
        self.limit = min(max(limit, 1), 1000)
        self.cursor = cursor
    }
}

// MARK: - Rows

public struct ConnRow: Sendable, Identifiable {
    public var id: Int64
    public var uid: UInt64
    public var ts: Timestamp
    public var durationUs: Int64?
    public var proto: UInt8
    public var localAddress: String
    public var localPort: UInt16
    public var remoteAddress: String
    public var remotePort: UInt16
    public var hostname: String?
    public var hostnameSource: Int
    public var hostnameAmbiguous: Bool
    public var service: String?
    public var state: String
    public var history: String
    public var bytesOut: Int64
    public var bytesIn: Int64
    public var packetsOut: Int64
    public var packetsIn: Int64
    public var processName: String?
    public var proxyName: String?
    public var lossSuspected: Bool
    public var day: String?

    public var totalBytes: Int64 { bytesIn + bytesOut }
}

public struct DNSRow: Sendable, Identifiable {
    public var id: Int64
    public var ts: Timestamp
    public var query: String
    public var qtype: UInt16
    public var rcode: UInt16
    public var rttUs: Int64?
    public var answers: [String]
    public var rejected: Bool
    public var processName: String?
    public var day: String?

    public var qtypeName: String {
        switch qtype {
        case 1: return "A"
        case 5: return "CNAME"
        case 12: return "PTR"
        case 16: return "TXT"
        case 28: return "AAAA"
        case 33: return "SRV"
        case 65: return "HTTPS"
        default: return "TYPE\(qtype)"
        }
    }

    public var rcodeName: String {
        switch rcode {
        case 0: return "NOERROR"
        case 1: return "FORMERR"
        case 2: return "SERVFAIL"
        case 3: return "NXDOMAIN"
        case 5: return "REFUSED"
        default: return "RCODE\(rcode)"
        }
    }

    /// A lookup that failed or was never answered. Worth surfacing: it is what
    /// a blocked resolver, a captive portal or a dropped packet looks like.
    public var isProblem: Bool { rejected || rcode != 0 }
}

public struct SSLRow: Sendable, Identifiable {
    public var id: Int64
    public var ts: Timestamp
    public var serverAddress: String
    public var serverPort: UInt16
    public var sni: String?
    public var sniIsOuter: Bool
    public var version: UInt16
    public var cipher: UInt16
    public var alpn: String?
    public var ja4: String?
    public var ja3: String?
    public var certsEncrypted: Bool
    public var subject: String?
    public var issuer: String?
    public var notAfter: Timestamp?
    public var established: Bool
    public var processName: String?
    public var day: String?

    public var versionName: String {
        switch version {
        case 0x0304: return "TLS 1.3"
        case 0x0303: return "TLS 1.2"
        case 0x0302: return "TLS 1.1"
        case 0x0301: return "TLS 1.0"
        case 0x0300: return "SSL 3.0"
        default: return "0x" + String(version, radix: 16)
        }
    }

    /// Anything below TLS 1.2 is deprecated and worth flagging.
    public var isWeakVersion: Bool { version != 0 && version < 0x0303 }
}

public struct Page<Row: Sendable>: Sendable {
    public var rows: [Row]
    public var next: PageCursor?
    /// Nil when counting was abandoned rather than zero. A UI must not render
    /// "0 matches" for "we stopped counting".
    public var estimatedTotal: Int64?

    public init(rows: [Row], next: PageCursor? = nil, estimatedTotal: Int64? = nil) {
        self.rows = rows
        self.next = next
        self.estimatedTotal = estimatedTotal
    }
}
