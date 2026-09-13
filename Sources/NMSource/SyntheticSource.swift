//
//  SyntheticSource.swift
//
//  Plausible fake traffic, generated deterministically.
//
//  This exists so the storage, rollup, retention, IPC and UI layers can be
//  built and benchmarked before the packet parser exists and without root. It
//  is not a toy: the shape of the data matters, because a uniform random load
//  would not exercise the things that actually hurt --
//
//    - a few processes producing most of the bytes, with a long tail
//      (this is what makes rollup cardinality realistic)
//    - DNS lookups that PRECEDE the connections they resolve, so the hostname
//      enrichment path is exercised in the right order
//    - repeated destinations, so index selectivity is realistic
//    - a mix of short-lived and long-lived flows
//    - a realistic proportion of delegated traffic (nsurlsessiond on behalf of
//      an app), because that is the attribution path most likely to be wrong
//

import Foundation
import NMCore

public final class SyntheticSource: RecordSource, @unchecked Sendable {

    public struct Config: Sendable {
        /// Target conn records per minute. The plan's benchmark points are
        /// 5k (realistic), 50k (heavy) and 200k (breaking).
        public var connsPerMinute: Int = 5_000
        /// Roughly one DNS query per this many connections. Real traffic reuses
        /// resolved addresses heavily.
        public var connsPerDNSQuery: Int = 4
        /// Fraction of connections that are TLS and so also emit an ssl row.
        public var tlsFraction: Double = 0.7
        /// Deterministic seed, so a benchmark or a failure can be replayed.
        public var seed: UInt64 = 0x5EED_1234_5678_9ABC
        /// Wall-clock pacing. False generates as fast as possible, which is
        /// what the storage benchmark wants.
        public var realTime: Bool = true
        /// Timestamp of the first record. Defaults to now.
        public var startTime: Timestamp?

        public init() {}
    }

    // A small cast of processes with believable traffic profiles. Weights are
    // deliberately skewed: real machines have two or three heavy talkers and a
    // long tail of chatty system daemons.
    private struct Actor {
        let exec: ExecInfo
        let weight: Int
        let hosts: [String]
        let ports: [UInt16]
        /// Traffic is proxied by nsurlsessiond on this app's behalf.
        let delegated: Bool
        let bytesScale: Int64
    }

    private static func makeExec(_ name: String, _ path: String, _ bundle: String?,
                                 _ team: String?, platform: Bool, seedWord: UInt64) -> ExecInfo {
        ExecInfo(path: path, name: name, bundleID: bundle, teamID: team,
                 signingID: bundle, uuidHi: seedWord, uuidLo: ~seedWord, isPlatform: platform)
    }

    private static let actors: [Actor] = [
        Actor(exec: makeExec("Safari", "/Applications/Safari.app/Contents/MacOS/Safari",
                             "com.apple.Safari", "APPLE", platform: true, seedWord: 1),
              weight: 30,
              hosts: ["www.apple.com", "apple.com", "cdn.example.com", "www.wikipedia.org",
                      "news.ycombinator.com", "github.com", "static.cloudfront.net"],
              ports: [443, 443, 443, 80], delegated: false, bytesScale: 200_000),

        Actor(exec: makeExec("Slack", "/Applications/Slack.app/Contents/MacOS/Slack",
                             "com.tinyspeck.slackmacgap", "BQR82RBBHL", platform: false, seedWord: 2),
              weight: 18,
              hosts: ["slack.com", "edgeapi.slack.com", "wss-primary.slack.com",
                      "files.slack.com"],
              ports: [443], delegated: false, bytesScale: 80_000),

        Actor(exec: makeExec("Mail", "/System/Applications/Mail.app/Contents/MacOS/Mail",
                             "com.apple.mail", "APPLE", platform: true, seedWord: 3),
              weight: 8,
              hosts: ["imap.mail.me.com", "smtp.mail.me.com", "p01-mailws.icloud.com"],
              ports: [993, 587, 443], delegated: true, bytesScale: 40_000),

        Actor(exec: makeExec("Spotify", "/Applications/Spotify.app/Contents/MacOS/Spotify",
                             "com.spotify.client", "2FNC3A47ZF", platform: false, seedWord: 4),
              weight: 12,
              hosts: ["audio-fa.scdn.co", "apresolve.spotify.com", "gew1-spclient.spotify.com"],
              ports: [443], delegated: false, bytesScale: 500_000),

        Actor(exec: makeExec("mDNSResponder", "/usr/sbin/mDNSResponder", nil, "APPLE",
                             platform: true, seedWord: 5),
              weight: 20,
              hosts: ["_companion-link._tcp.local", "_airplay._tcp.local", "_raop._tcp.local"],
              ports: [5353], delegated: false, bytesScale: 400),

        Actor(exec: makeExec("nsurlsessiond", "/usr/libexec/nsurlsessiond", nil, "APPLE",
                             platform: true, seedWord: 6),
              weight: 6,
              hosts: ["gateway.icloud.com", "gsp-ssl.ls.apple.com", "configuration.apple.com"],
              ports: [443], delegated: true, bytesScale: 20_000),

        Actor(exec: makeExec("Terminal", "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
                             "com.apple.Terminal", "APPLE", platform: true, seedWord: 7),
              weight: 3,
              hosts: ["github.com", "registry.npmjs.org", "pypi.org"],
              ports: [22, 443], delegated: false, bytesScale: 30_000),

        Actor(exec: makeExec("trustd", "/usr/libexec/trustd", nil, "APPLE",
                             platform: true, seedWord: 8),
              weight: 3,
              hosts: ["ocsp.apple.com", "valid.apple.com", "crl.apple.com"],
              ports: [80, 443], delegated: false, bytesScale: 3_000),
    ]

    private let config: Config
    private var rng: SplitMix64
    private var handler: (@Sendable (RecordBatch) -> Void)?
    private var thread: Thread?
    private var shouldStop = false
    private let lock = NSLock()

    private var _counters = SourceCounters()
    private var nextFlowID: UInt64 = 1
    private var clock: Timestamp
    private var weightedActors: [Int] = []

    /// Addresses we have "resolved", so connections can reuse them and the
    /// hostname enrichment path sees repeats the way it would in reality.
    private var resolvedHosts: [String: IPAddress] = [:]

    public init(config: Config = Config()) {
        self.config = config
        self.rng = SplitMix64(seed: config.seed)
        self.clock = config.startTime ?? Timestamp(Date().timeIntervalSince1970 * 1_000_000)
        for (i, a) in Self.actors.enumerated() {
            weightedActors.append(contentsOf: Array(repeating: i, count: a.weight))
        }
    }

    public var counters: SourceCounters {
        lock.lock(); defer { lock.unlock() }
        return _counters
    }

    public var descriptionText: String {
        "synthetic traffic, \(config.connsPerMinute) conns/min, seed 0x"
            + String(config.seed, radix: 16)
    }

    // MARK: - RecordSource

    public func start(_ handler: @escaping @Sendable (RecordBatch) -> Void) throws {
        self.handler = handler
        shouldStop = false
        let t = Thread { [weak self] in self?.run() }
        t.name = "nm.synthetic"
        t.qualityOfService = .utility
        thread = t
        t.start()
    }

    public func stop() {
        lock.lock(); shouldStop = true; lock.unlock()
    }

    private func run() {
        // Emit on the same cadence the real pipeline uses: 4 Hz batches.
        let batchesPerSecond = 4
        let connsPerBatch = max(1, config.connsPerMinute / 60 / batchesPerSecond)

        while true {
            lock.lock()
            let stopping = shouldStop
            lock.unlock()
            if stopping { break }

            let batch = generate(connCount: connsPerBatch)
            handler?(batch)

            if config.realTime {
                Thread.sleep(forTimeInterval: 1.0 / Double(batchesPerSecond))
            } else {
                // Free-running: advance the virtual clock instead of sleeping,
                // so a ten-minute benchmark takes seconds.
                clock += Time.microsPerSecond / Int64(batchesPerSecond)
            }
        }
    }

    // MARK: - Generation

    /// Produces one batch. Public so benchmarks can drive it directly without
    /// starting a thread.
    public func generate(connCount: Int) -> RecordBatch {
        var batch = RecordBatch()
        batch.conns.reserveCapacity(connCount)

        for _ in 0..<connCount {
            let actorIndex = weightedActors[Int(rng.next() % UInt64(weightedActors.count))]
            let actor = Self.actors[actorIndex]
            let host = actor.hosts[Int(rng.next() % UInt64(actor.hosts.count))]
            let port = actor.ports[Int(rng.next() % UInt64(actor.ports.count))]

            // Occasionally resolve the host first, so a DNS row precedes the
            // conn row that depends on it -- the same ordering the real
            // enrichment path relies on.
            let addr: IPAddress
            if let known = resolvedHosts[host], rng.next() % UInt64(config.connsPerDNSQuery) != 0 {
                addr = known
            } else {
                addr = randomPublicAddress()
                resolvedHosts[host] = addr
                if port != 5353 {
                    batch.dns.append(makeDNSRecord(actor: actor, host: host, addr: addr))
                }
            }

            let conn = makeConnRecord(actor: actor, host: host, addr: addr, port: port)

            if port == 443 && Double(rng.next() % 1000) / 1000.0 < config.tlsFraction {
                batch.ssl.append(makeSSLRecord(conn: conn, actor: actor, host: host))
            }
            batch.conns.append(conn)
        }

        lock.lock()
        _counters.flowsOpened += Int64(batch.conns.count)
        _counters.flowsClosed += Int64(batch.conns.count)
        for c in batch.conns {
            _counters.packets += c.origPkts + c.respPkts
            _counters.bytesOut += c.origIPBytes
            _counters.bytesIn += c.respIPBytes
        }
        lock.unlock()

        return batch
    }

    private func makeConnRecord(actor: Actor, host: String,
                                addr: IPAddress, port: UInt16) -> ConnRecord {
        let uid = FlowID(raw: nextFlowID)
        nextFlowID += 1

        let isMulticastDNS = port == 5353
        let localAddr = IPAddress(v4HostOrder: 0xC0A8_0000 | UInt32(rng.next() % 254 + 1))
        let proto: UInt8 = isMulticastDNS ? 17 : 6

        var c = ConnRecord(
            uid: uid,
            ts: clock,
            proto: proto,
            origAddr: localAddr,
            origPort: UInt16(49152 + rng.next() % 16000),
            respAddr: addr,
            respPort: port,
            iface: isMulticastDNS ? "en0" : (rng.next() % 20 == 0 ? "utun0" : "en0"),
            state: .sf,
            history: isMulticastDNS ? "Dd" : "ShADadFf",
            pid: Int32(1000 + actorIndexHash(actor))
        )

        // Log-ish size distribution: most flows small, a few very large.
        let magnitude = rng.next() % 100
        let scale: Int64
        if magnitude < 70 { scale = actor.bytesScale / 10 }
        else if magnitude < 95 { scale = actor.bytesScale }
        else { scale = actor.bytesScale * 20 }

        c.origBytes = Int64(rng.next() % UInt64(max(1, scale / 4))) + 100
        c.respBytes = Int64(rng.next() % UInt64(max(1, scale))) + 100
        c.origPkts = max(1, c.origBytes / 1200 + 4)
        c.respPkts = max(1, c.respBytes / 1400 + 4)
        c.origIPBytes = c.origBytes + c.origPkts * 40
        c.respIPBytes = c.respBytes + c.respPkts * 40

        let durationUs = Int64(rng.next() % 30_000_000) + 1_000
        c.durationUs = durationUs
        c.tsEnd = clock + durationUs

        if actor.delegated {
            // The kernel reports nsurlsessiond as pid but the real application
            // as epid. Both are kept: the UI shows the app, the detail pane
            // shows the proxy.
            c.proxyExec = Self.actors.first { $0.exec.name == "nsurlsessiond" }?.exec
            c.proxyPid = 130
        }
        c.exec = actor.exec
        c.userID = 501

        c.hostname = host
        c.hostnameSource = actor.delegated ? .dnsWildcard : .dnsPerProcess
        c.service = isMulticastDNS ? "dns" : (port == 443 ? "ssl" : (port == 80 ? "http" : nil))

        // A small fraction of flows are marked as having suffered capture loss,
        // so the UI's "approximate" rendering path is exercised in development
        // rather than discovered in production.
        c.captureLossSuspected = rng.next() % 500 == 0

        clock += Int64(rng.next() % 2_000)
        return c
    }

    private func makeDNSRecord(actor: Actor, host: String, addr: IPAddress) -> DNSRecord {
        var d = DNSRecord(
            ts: clock,
            proto: 17,
            clientAddr: IPAddress(v4HostOrder: 0xC0A8_0001),
            serverAddr: IPAddress(v4HostOrder: 0xC0A8_0001),
            serverPort: 53,
            transactionID: UInt16(rng.next() % 65536),
            query: host,
            qtype: 1,
            answers: [addr.description],
            ttls: [UInt32(60 + rng.next() % 3540)],
            pid: Int32(1000 + actorIndexHash(actor))
        )
        d.exec = actor.exec
        // A few percent of lookups fail. Unanswered and NXDOMAIN queries are
        // diagnostically valuable, so they must exist in test data.
        let roll = rng.next() % 100
        if roll < 2 { d.rcode = 3; d.answers = []; d.rejected = false }       // NXDOMAIN
        else if roll < 3 { d.rejected = true; d.answers = [] }                // no response
        else { d.rttUs = Int64(rng.next() % 80_000) + 800 }
        return d
    }

    private func makeSSLRecord(conn: ConnRecord, actor: Actor, host: String) -> SSLRecord {
        var s = SSLRecord(ts: conn.ts, clientAddr: conn.origAddr,
                          serverAddr: conn.respAddr, serverPort: conn.respPort,
                          version: rng.next() % 10 == 0 ? 0x0303 : 0x0304,
                          cipher: 0x1301, pid: conn.pid)
        s.uid = conn.uid
        s.sni = host
        s.alpn = rng.next() % 3 == 0 ? "http/1.1" : "h2"
        s.established = true
        s.sslHistory = "CsHF"
        s.exec = actor.exec
        // TLS 1.3 encrypts the Certificate message, so cert fields are simply
        // unavailable for most flows. The synthetic data reflects that, because
        // a UI built against always-present certs would be wrong in production.
        s.certsEncrypted = s.version == 0x0304
        if !s.certsEncrypted {
            s.subject = "CN=\(host)"
            s.issuer = "CN=Example CA R3, O=Example, C=US"
            s.notBefore = conn.ts - 30 * Time.microsPerDay
            s.notAfter = conn.ts + 60 * Time.microsPerDay
        }
        // A small share of flows carry ECH, where the visible SNI is the outer
        // name and is NOT the real destination.
        if rng.next() % 50 == 0 {
            s.sniIsOuter = true
            s.sni = "cloudflare-ech.com"
        }
        s.ja4 = "t13d1516h2_8daaf6152771_b0da82dd1658"
        s.ja4Raw = "t13d1516h2_002f,0035,009c,009d,1301,1302,1303_0005,000a,000b,000d"
        s.ja3 = "cd08e31494f9531f560d64c695473da9"
        return s
    }

    private func randomPublicAddress() -> IPAddress {
        // Avoid private and reserved ranges so `local_resp` classification in
        // the synthetic data is meaningful.
        var a = UInt32(rng.next() % 223) + 1
        while a == 10 || a == 127 || a == 172 || a == 192 || a == 169 || a == 100 {
            a = UInt32(rng.next() % 223) + 1
        }
        let b = UInt32(rng.next() % 256)
        let c = UInt32(rng.next() % 256)
        let d = UInt32(rng.next() % 254) + 1
        return IPAddress(v4HostOrder: (a << 24) | (b << 16) | (c << 8) | d)
    }

    private func actorIndexHash(_ actor: Actor) -> UInt64 {
        UInt64(abs(actor.exec.name.hashValue % 900))
    }
}

