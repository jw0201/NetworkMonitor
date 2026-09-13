//
//  DemoHistory.swift
//
//  Invented log rows, for when there is no store to read.
//
//  Shaped rather than uniform, and for the same reason the synthetic capture
//  source is: a screen built against tidy data breaks the first time it meets
//  real data. So this includes unanswered DNS queries, NXDOMAIN, TLS 1.3
//  sessions whose certificates cannot be read, an ECH connection whose visible
//  name is not the destination, a deprecated TLS version, connections that were
//  refused, and rows whose byte counts are marked approximate.
//

import Foundation
import NMCore
import NMStore

final class DemoHistory {

    struct AnyPage {
        var conns: [ConnRow] = []
        var dns: [DNSRow] = []
        var ssl: [SSLRow] = []
        var next: PageCursor?
    }

    private var random = SplitMix64(seed: 0xDEC0_DE)
    private let now = Timestamp(Date().timeIntervalSince1970 * 1_000_000)

    private struct Site {
        let host: String
        let process: String
        let port: UInt16
        let service: String
    }

    private let sites: [Site] = [
        Site(host: "www.apple.com", process: "Safari", port: 443, service: "ssl"),
        Site(host: "github.com", process: "Safari", port: 443, service: "ssl"),
        Site(host: "edgeapi.slack.com", process: "Slack", port: 443, service: "ssl"),
        Site(host: "audio-fa.scdn.co", process: "Spotify", port: 443, service: "ssl"),
        Site(host: "imap.mail.me.com", process: "Mail", port: 993, service: "ssl"),
        Site(host: "ocsp.apple.com", process: "trustd", port: 80, service: "http"),
        Site(host: "_airplay._tcp.local", process: "mDNSResponder", port: 5353, service: "dns"),
        Site(host: "gateway.icloud.com", process: "nsurlsessiond", port: 443, service: "ssl"),
    ]

    private let states = ["SF", "SF", "SF", "SF", "S1", "S0", "REJ", "RSTO", "OTH"]

    /// A synthetic page. The cursor behaves like the real one -- rows go back
    /// in time and a page ends where the next begins -- so the views' paging
    /// logic is exercised rather than bypassed.
    func page(_ spec: QuerySpec) -> AnyPage {
        var page = AnyPage()
        let startTime = spec.cursor?.timestamp ?? now
        let startID = spec.cursor?.rowID ?? 100_000

        // Stop after a few pages so "end of results" is reachable.
        guard startID > 99_000 else { return page }

        for offset in 0..<spec.limit {
            let id = startID - Int64(offset) - 1
            let ts = startTime - Int64(offset + 1) * Int64(random.next() % 900_000 + 100_000)
            let site = sites[Int(random.next() % UInt64(sites.count))]

            switch spec.kind {
            case .conn:
                if let row = makeConn(id: id, ts: ts, site: site, filter: spec.filter) {
                    page.conns.append(row)
                }
            case .dns:
                if let row = makeDNS(id: id, ts: ts, site: site, filter: spec.filter) {
                    page.dns.append(row)
                }
            case .ssl:
                if let row = makeSSL(id: id, ts: ts, site: site, filter: spec.filter) {
                    page.ssl.append(row)
                }
            }
        }

        let lastID = startID - Int64(spec.limit)
        page.next = lastID > 99_000
            ? PageCursor(timestamp: startTime - Int64(spec.limit) * 500_000, rowID: lastID)
            : nil
        return page
    }

    private func makeConn(id: Int64, ts: Timestamp, site: Site,
                          filter: QueryFilter) -> ConnRow? {
        if let process = filter.process, process != site.process { return nil }
        if let host = filter.host, host != site.host { return nil }
        if let port = filter.port, port != site.port { return nil }
        if let service = filter.service, service != site.service { return nil }

        let state = states[Int(random.next() % UInt64(states.count))]
        if let wanted = filter.state, wanted != state { return nil }

        let out = Int64(random.next() % 400_000) + 200
        let inbound = Int64(random.next() % 2_000_000) + 400
        if let minimum = filter.minimumBytes, out + inbound < minimum { return nil }

        // A small share of rows have counts we know are approximate, so the
        // "approximate" rendering path is exercised in development.
        let lossy = random.next() % 25 == 0
        // And a small share resolved through another process's lookup, so the
        // weaker provenance is visible too.
        let ambiguous = random.next() % 12 == 0

        if filter.lossOnly && !lossy { return nil }
        if let text = filter.text,
           !site.host.localizedCaseInsensitiveContains(text),
           !site.process.localizedCaseInsensitiveContains(text) { return nil }

        return ConnRow(
            id: id, uid: UInt64(id), ts: ts,
            durationUs: Int64(random.next() % 30_000_000),
            proto: site.port == 5353 ? 17 : 6,
            localAddress: "192.168.0.31", localPort: UInt16(49152 + random.next() % 15000),
            remoteAddress: randomAddress(),
            remotePort: site.port,
            hostname: site.host,
            hostnameSource: ambiguous ? HostnameSource.dnsWildcard.rawValue
                                      : HostnameSource.tlsSNI.rawValue,
            hostnameAmbiguous: ambiguous,
            service: site.service,
            state: state,
            history: state == "SF" ? "ShADadFf" : (state == "S0" ? "S" : "ShADR"),
            bytesOut: out, bytesIn: state == "S0" ? 0 : inbound,
            packetsOut: out / 1400 + 3, packetsIn: inbound / 1400 + 3,
            processName: site.process,
            proxyName: site.process == "Mail" ? "nsurlsessiond" : nil,
            lossSuspected: lossy, day: nil)
    }

    private func makeDNS(id: Int64, ts: Timestamp, site: Site,
                         filter: QueryFilter) -> DNSRow? {
        if let process = filter.process, process != site.process { return nil }
        if let host = filter.host, host != site.host { return nil }
        if let text = filter.text,
           !site.host.localizedCaseInsensitiveContains(text),
           !site.process.localizedCaseInsensitiveContains(text) { return nil }

        // Failures are a meaningful share, because an unanswered lookup is what
        // a blocked resolver or a captive portal looks like and the screen has
        // to make it obvious.
        let roll = random.next() % 100
        let rejected = roll < 4
        let rcode: UInt16 = roll < 4 ? 0 : (roll < 9 ? 3 : 0)

        return DNSRow(
            id: id, ts: ts, query: site.host,
            qtype: random.next() % 4 == 0 ? 28 : 1,
            rcode: rcode,
            rttUs: rejected ? nil : Int64(random.next() % 90_000) + 700,
            answers: (rejected || rcode != 0) ? [] : [randomAddress()],
            rejected: rejected,
            processName: site.process, day: nil)
    }

    private func makeSSL(id: Int64, ts: Timestamp, site: Site,
                         filter: QueryFilter) -> SSLRow? {
        guard site.service == "ssl" else { return nil }
        if let process = filter.process, process != site.process { return nil }
        if let host = filter.host, host != site.host { return nil }
        if let text = filter.text,
           !site.host.localizedCaseInsensitiveContains(text),
           !site.process.localizedCaseInsensitiveContains(text) { return nil }

        let roll = random.next() % 100
        let isTLS13 = roll >= 12
        let isECH = roll < 4
        let isLegacy = roll >= 4 && roll < 8

        var row = SSLRow(
            id: id, ts: ts,
            serverAddress: randomAddress(), serverPort: site.port,
            sni: isECH ? "cloudflare-ech.com" : site.host,
            sniIsOuter: isECH,
            version: isLegacy ? 0x0301 : (isTLS13 ? 0x0304 : 0x0303),
            cipher: isTLS13 ? 0x1301 : 0xC02F,
            alpn: isTLS13 ? nil : "h2",
            ja4: "t13d1516h2_8daaf6152771_02713d6af862",
            ja3: "cd08e31494f9531f560d64c695473da9",
            // TLS 1.3 encrypts the certificate, so it is unavailable rather
            // than unknown -- the distinction the UI has to make.
            certsEncrypted: isTLS13,
            subject: isTLS13 ? nil : "CN=\(site.host)",
            issuer: isTLS13 ? nil : "CN=Example CA R3, O=Example, C=US",
            notAfter: isTLS13 ? nil : ts + 60 * Time.microsPerDay,
            established: random.next() % 30 != 0,
            processName: site.process, day: nil)
        if !row.established { row.certsEncrypted = false }
        return row
    }

    private func randomAddress() -> String {
        var a = UInt32(random.next() % 223) + 1
        while a == 10 || a == 127 || a == 172 || a == 192 || a == 169 {
            a = UInt32(random.next() % 223) + 1
        }
        return "\(a).\(random.next() % 256).\(random.next() % 256).\(random.next() % 254 + 1)"
    }
}
