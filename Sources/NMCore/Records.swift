//
//  Records.swift
//
//  The log records this system produces. The field sets follow Zeek's
//  conn.log / dns.log / ssl.log vocabulary, because that vocabulary is
//  well-understood and because the user asked for Zeek-like logs -- with
//  macOS-specific process attribution added, which is the part Zeek cannot do.
//
//  Everything here is Sendable: these values cross from the analyzer thread to
//  the storage actor.
//

/// A flow identifier. Stable for the life of a connection and used to join
/// conn <-> dns <-> ssl <-> payload <-> pcap segments.
public struct FlowID: Hashable, Sendable, CustomStringConvertible {
    public var raw: UInt64
    public init(raw: UInt64) { self.raw = raw }
    public var description: String { String(raw, radix: 16, uppercase: false) }

    /// Persisted as an INTEGER rather than an 8-byte BLOB. SQLite varint-encodes
    /// integers, so a sequential flow id costs 2-4 bytes on the row and again in
    /// every index that carries it, where a BLOB always costs 8 plus a header.
    public var storageValue: Int64 { Int64(bitPattern: raw) }

    public init(storageValue: Int64) { self.raw = UInt64(bitPattern: storageValue) }
}

public enum IPProto: UInt8, Sendable {
    case icmp = 1
    case tcp = 6
    case udp = 17
    case icmpv6 = 58

    public var name: String {
        switch self {
        case .icmp: return "icmp"
        case .tcp: return "tcp"
        case .udp: return "udp"
        case .icmpv6: return "icmp6"
        }
    }
}

/// Zeek's `conn_state`. The full vocabulary, because the distinctions are what
/// make questions like "which processes are talking to hosts that never answer"
/// a one-click filter rather than an analysis project.
public enum ConnState: String, Sendable, CaseIterable {
    /// SYN from originator, nothing back. Also: a UDP flow seen in one direction only.
    case s0 = "S0"
    /// Established, never closed.
    case s1 = "S1"
    /// Established and normally terminated. Also: a UDP flow seen both ways.
    case sf = "SF"
    /// SYN answered with RST.
    case rej = "REJ"
    /// Established; originator sent FIN, responder did not.
    case s2 = "S2"
    /// Established; responder sent FIN, originator did not.
    case s3 = "S3"
    /// Established; originator sent RST.
    case rsto = "RSTO"
    /// Established; responder sent RST.
    case rstr = "RSTR"
    /// Originator sent SYN then RST; no SYN-ACK ever seen.
    case rstos0 = "RSTOS0"
    /// Responder sent SYN-ACK then RST; no originator SYN seen.
    case rstrh = "RSTRH"
    /// Originator sent SYN then FIN, no SYN-ACK. A stealth-scan signature.
    case sh = "SH"
    /// Responder sent SYN-ACK then FIN, no originator SYN.
    case shr = "SHR"
    /// Midstream -- no SYN observed, so the handshake is unknown.
    case oth = "OTH"

    public var isEstablished: Bool {
        switch self {
        case .s1, .sf, .s2, .s3, .rsto, .rstr: return true
        default: return false
        }
    }
}

/// How a connection's hostname was determined. Stored so the UI can be honest
/// about provenance instead of presenting a guess as a fact.
public enum HostnameSource: Int, Sendable {
    case none = 0
    /// TLS SNI. Highest confidence, and what the client actually asked for.
    case tlsSNI = 1
    /// HTTP Host header.
    case httpHost = 2
    /// Our DNS cache, keyed by (requesting pid, IP). The pktap advantage:
    /// unambiguous even when a CDN address serves many names.
    case dnsPerProcess = 3
    /// Our DNS cache, matched on IP alone. Ambiguous for shared addresses.
    case dnsWildcard = 4
    /// Reverse PTR lookup. Opt-in, because it generates traffic of its own.
    case reversePTR = 5

    public var isHighConfidence: Bool { self == .tlsSNI || self == .dnsPerProcess }

    /// How much a source is trusted, higher being better. Used to decide
    /// whether a newly learned name should replace one already on the flow.
    ///
    /// SNI outranks the DNS cache because it is what the client literally asked
    /// the server for on this connection, rather than an inference from a
    /// lookup that happened earlier and might have been someone else's.
    public var strength: Int {
        switch self {
        case .none: return 0
        case .reversePTR: return 1
        case .dnsWildcard: return 2
        case .dnsPerProcess: return 3
        case .httpHost: return 4
        case .tlsSNI: return 5
        }
    }
}

/// Process and binary identity. Interned into a dimension table so conn/dns/ssl
/// rows carry a small integer rather than a repeated path string.
public struct ExecInfo: Hashable, Sendable {
    public var path: String
    public var name: String
    public var bundleID: String?
    public var teamID: String?
    public var signingID: String?
    /// Mach-O UUID from the pktap header. Combined with the pid this detects
    /// pid reuse exactly and for free.
    public var uuidHi: UInt64
    public var uuidLo: UInt64
    /// An Apple platform binary. Useful default filter: most users want to see
    /// their own apps, not 40 system daemons.
    public var isPlatform: Bool

    public init(path: String, name: String, bundleID: String? = nil,
                teamID: String? = nil, signingID: String? = nil,
                uuidHi: UInt64 = 0, uuidLo: UInt64 = 0, isPlatform: Bool = false) {
        self.path = path
        self.name = name
        self.bundleID = bundleID
        self.teamID = teamID
        self.signingID = signingID
        self.uuidHi = uuidHi
        self.uuidLo = uuidLo
        self.isPlatform = isPlatform
    }
}

public struct ConnRecord: Sendable {
    public var uid: FlowID
    public var ts: Timestamp
    public var tsEnd: Timestamp?
    public var durationUs: Int64?

    public var proto: UInt8
    public var origAddr: IPAddress
    public var origPort: UInt16
    public var respAddr: IPAddress
    public var respPort: UInt16

    public var iface: String
    /// Application-layer protocol inferred by whichever analyzer claimed the
    /// flow: "dns", "ssl", "http", "quic".
    public var service: String?
    public var state: ConnState
    /// Zeek's history string. Uppercase is the originator, lowercase the
    /// responder. Hard-capped at 64 characters -- an unbounded history is a
    /// memory-exhaustion vector that has bitten Zeek itself.
    public var history: String

    public var origPkts: Int64 = 0
    public var origBytes: Int64 = 0          // L4 payload
    public var origIPBytes: Int64 = 0        // on-wire, what the throughput chart uses
    public var respPkts: Int64 = 0
    public var respBytes: Int64 = 0
    public var respIPBytes: Int64 = 0
    /// Bytes we know we missed, from a gap in the TCP sequence space.
    public var missedBytes: Int64 = 0

    public var localOrig: Bool
    public var localResp: Bool

    // macOS process attribution.
    /// The application the traffic belongs to. For delegated traffic this is
    /// the effective pid, not the proxy -- users want "Safari used 2 GB", not
    /// "nsurlsessiond used 2 GB".
    public var exec: ExecInfo?
    public var pid: Int32
    /// The proxy process, when the kernel says the traffic was delegated.
    /// Kept alongside rather than discarded, and shown in the detail pane.
    public var proxyExec: ExecInfo?
    public var proxyPid: Int32?
    /// UID owning the socket, so the UI can filter per user on a shared Mac.
    public var userID: UInt32?

    public var hostname: String?
    public var hostnameSource: HostnameSource = .none
    /// More than one plausible hostname existed for this address at connect
    /// time. Recorded and shown rather than silently resolved -- admitting
    /// ambiguity beats presenting a coin flip as a fact.
    public var hostnameAmbiguous: Bool = false

    /// Packets were dropped somewhere in this flow's lifetime, so the byte
    /// counts are approximate. The packet-level equivalent of Zeek's
    /// missed_bytes, and what keeps the numbers honest.
    public var captureLossSuspected: Bool = false

    /// Range of pcap ring segments containing this flow's packets. Two integers
    /// per flow instead of a row per packet.
    public var firstPcapSegment: UInt32?
    public var lastPcapSegment: UInt32?

    /// When set, this row stands for this many shed flows rather than one.
    ///
    /// Under a scan or flood the table sheds flows faster than they could ever
    /// be read, and writing fifty thousand near-identical rows would bury the
    /// log without telling anyone anything. One aggregated row per
    /// (process, destination, port, state) says the same thing and stays
    /// legible.
    public var aggregatedFlows: Int?

    public init(uid: FlowID, ts: Timestamp, proto: UInt8,
                origAddr: IPAddress, origPort: UInt16,
                respAddr: IPAddress, respPort: UInt16,
                iface: String, state: ConnState = .oth, history: String = "",
                pid: Int32 = 0) {
        self.uid = uid
        self.ts = ts
        self.proto = proto
        self.origAddr = origAddr
        self.origPort = origPort
        self.respAddr = respAddr
        self.respPort = respPort
        self.iface = iface
        self.state = state
        self.history = history
        self.pid = pid
        self.localOrig = origAddr.isLocalScope
        self.localResp = respAddr.isLocalScope
    }

    public var totalBytes: Int64 { origIPBytes + respIPBytes }
}

public struct DNSRecord: Sendable {
    public var uid: FlowID?
    public var ts: Timestamp
    public var proto: UInt8
    public var clientAddr: IPAddress
    public var serverAddr: IPAddress
    public var serverPort: UInt16

    public var transactionID: UInt16
    /// Nil when the query went unanswered. An unanswered query is itself
    /// diagnostic -- it is what a blocked or broken resolver looks like.
    public var rttUs: Int64?
    public var query: String
    public var qtype: UInt16
    public var qclass: UInt16
    public var rcode: UInt16
    public var flags: UInt16
    public var answers: [String]
    public var ttls: [UInt32]
    public var rejected: Bool

    public var exec: ExecInfo?
    public var pid: Int32

    public init(ts: Timestamp, proto: UInt8, clientAddr: IPAddress,
                serverAddr: IPAddress, serverPort: UInt16,
                transactionID: UInt16, query: String, qtype: UInt16,
                qclass: UInt16 = 1, rcode: UInt16 = 0, flags: UInt16 = 0,
                answers: [String] = [], ttls: [UInt32] = [],
                rejected: Bool = false, pid: Int32 = 0) {
        self.ts = ts
        self.proto = proto
        self.clientAddr = clientAddr
        self.serverAddr = serverAddr
        self.serverPort = serverPort
        self.transactionID = transactionID
        self.query = query
        self.qtype = qtype
        self.qclass = qclass
        self.rcode = rcode
        self.flags = flags
        self.answers = answers
        self.ttls = ttls
        self.rejected = rejected
        self.pid = pid
    }

    /// The query name with labels reversed ("www.example.com" ->
    /// "com.example.www"). Indexed so that a domain-suffix search becomes a
    /// prefix scan -- `LIKE 'com.example.%'` uses the index, `LIKE '%.example.com'`
    /// cannot.
    public var queryReversed: String {
        query.split(separator: ".").reversed().joined(separator: ".")
    }
}

public struct SSLRecord: Sendable {
    public var uid: FlowID?
    public var ts: Timestamp
    public var clientAddr: IPAddress
    public var serverAddr: IPAddress
    public var serverPort: UInt16

    public var version: UInt16
    public var cipher: UInt16
    public var curve: UInt16?
    public var sni: String?
    /// The ClientHello carried an Encrypted Client Hello extension, so the
    /// visible SNI is the OUTER name and is NOT the real destination. Showing
    /// it as if it were would be worse than showing nothing.
    public var sniIsOuter: Bool = false
    public var alpn: String?
    public var sslHistory: String = ""
    public var established: Bool = false
    public var resumed: Bool = false

    public var ja4: String?
    /// The unhashed JA4 string. Free to keep, and without it a fingerprint
    /// mismatch against another tool is undebuggable.
    public var ja4Raw: String?
    public var ja3: String?
    public var ja4s: String?
    public var ja3s: String?

    /// TLS 1.3 encrypts the Certificate message, so subject/issuer/validity are
    /// simply unavailable for most modern traffic. Recorded explicitly so the
    /// UI can say "encrypted" rather than "unknown".
    public var certsEncrypted: Bool = false
    public var subject: String?
    public var issuer: String?
    public var notBefore: Timestamp?
    public var notAfter: Timestamp?
    public var chainFingerprints: [String] = []

    public var exec: ExecInfo?
    public var pid: Int32

    public init(ts: Timestamp, clientAddr: IPAddress, serverAddr: IPAddress,
                serverPort: UInt16, version: UInt16, cipher: UInt16, pid: Int32 = 0) {
        self.ts = ts
        self.clientAddr = clientAddr
        self.serverAddr = serverAddr
        self.serverPort = serverPort
        self.version = version
        self.cipher = cipher
        self.pid = pid
    }

    public var sniReversed: String? {
        sni.map { $0.split(separator: ".").reversed().joined(separator: ".") }
    }

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
}

/// One batch of records handed from the analyzer to storage. Batching is what
/// keeps SQLite at four transactions a second instead of thousands.
public struct RecordBatch: Sendable {
    public var conns: [ConnRecord] = []
    public var dns: [DNSRecord] = []
    public var ssl: [SSLRecord] = []

    public init() {}

    public var count: Int { conns.count + dns.count + ssl.count }
    public var isEmpty: Bool { count == 0 }

    public mutating func append(_ other: RecordBatch) {
        conns.append(contentsOf: other.conns)
        dns.append(contentsOf: other.dns)
        ssl.append(contentsOf: other.ssl)
    }
}
