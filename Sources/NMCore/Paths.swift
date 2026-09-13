//
//  Paths.swift
//
//  Every filesystem location in one place.
//
//  NOT /var/db: that is Apple-reserved system state, opaque to users, and
//  hostile to backup, support-bundle and "show me my data" workflows.
//  /Library/Application Support/NetworkMonitor is the documented location for
//  third-party system-wide application data and is visible in Finder.
//
//  Ownership matters here. These files contain every user's browsing metadata
//  and, if payload capture is enabled, plaintext bytes. Nothing is ever
//  world-readable: the data directory is 0770 root:_networkmonitor.
//
//  The directory is 0770 rather than 0750 for a specific reason. A read-only
//  SQLite connection to a WAL database needs WRITE access to the -shm file (it
//  mmaps the wal-index read-write to register its read mark), and if the daemon
//  is not running the -shm does not exist and the reader must CREATE it -- which
//  needs write permission on the directory. With 0750 that fails only when the
//  daemon is down, which is the worst possible time for a confusing error.
//

public struct Paths: Sendable {
    public let root: String

    public static let systemRoot = "/Library/Application Support/NetworkMonitor"

    public init(root: String = Paths.systemRoot) {
        self.root = root
    }

    public var configFile: String { "\(root)/config.json" }
    /// cdhashes of the app and the daemon, written at install time so each can
    /// pin the other's code-signing requirement. Neither binary can contain the
    /// other's hash, so it is resolved out of band.
    public var peersFile: String { "\(root)/peers.plist" }

    public var databaseDirectory: String { "\(root)/db" }
    public var archiveDirectory: String { "\(root)/db/archive" }
    public var pcapDirectory: String { "\(root)/pcap" }
    public var exportDirectory: String { "\(root)/export" }

    public var liveDatabase: String { "\(databaseDirectory)/live.db" }
    public var metaDatabase: String { "\(databaseDirectory)/meta.db" }
    public var rollupDatabase: String { "\(databaseDirectory)/rollup.db" }
    public var pcapDatabase: String { "\(databaseDirectory)/pcap.db" }

    public func archiveDatabase(day: String) -> String {
        "\(archiveDirectory)/nm-\(day).db"
    }

    public func archiveDatabase(forTimestamp ts: Timestamp) -> String {
        archiveDatabase(day: Time.utcDayString(ts))
    }

    public func pcapSegment(sequence: UInt32) -> String {
        var s = String(sequence)
        while s.count < 6 { s = "0" + s }
        return "\(pcapDirectory)/nm-\(s).pcap"
    }

    public var allDirectories: [String] {
        [root, databaseDirectory, archiveDirectory, pcapDirectory, exportDirectory]
    }

    /// A root under a caller-chosen directory, for tests and benchmarks.
    public static func temporary(_ path: String) -> Paths { Paths(root: path) }
}

/// Limits that exist to bound an attacker's influence, collected so they are
/// reviewable in one place rather than scattered through parsers.
public enum Limits {
    // Flow table
    public static let maxConcurrentFlows = 262_144
    public static let maxReassemblyFlows = 4_096
    public static let reassemblyBufferBytes = 8 * 1024
    public static let maxHistoryCharacters = 64

    // DNS parsing. The compression-pointer rules are the ones that matter:
    // a pointer that does not strictly decrease is the classic infinite loop.
    public static let maxDNSCompressionJumps = 16
    public static let maxDNSNameLength = 255
    public static let maxDNSLabelLength = 63
    public static let maxDNSLabels = 127
    public static let maxDNSRecords = 64
    public static let maxCNAMEChain = 8

    // TLS parsing
    public static let maxTLSExtensions = 64
    public static let maxTLSCipherSuites = 256
    public static let maxTLSCertificates = 16
    public static let maxTLSRecordLength = 16_640
    public static let maxTLSHandshakeBytes = 128 * 1024

    // IP parsing
    public static let maxIPv6ExtensionHeaders = 8
    public static let maxVLANTags = 2

    // Caches
    public static let dnsCacheEntries = 65_536
    public static let dnsNegativeCacheEntries = 4_096
    public static let maxHostnameCandidatesPerAddress = 4

    // Storage
    public static let writeBatchRows = 2_000
    public static let writeBatchIntervalMs = 250
    /// SQLITE_MAX_ATTACHED is 10 in this build. meta, rollup and pcap take
    /// three, leaving seven for day files.
    public static let maxAttachedDayFiles = 7
}
