//
//  StoreReaderTests.swift
//
//  The property that matters is that paging returns every row exactly once,
//  including while the daemon is writing -- which is the normal state, not an
//  edge case. That is the correctness argument for keyset over OFFSET, and it
//  is invisible in a test that pages a static table.
//

import Foundation
import NMCore
import NMFlow
import NMStore
import NMTestKit

private func temporaryRoot(_ name: String) -> String {
    let path = NSTemporaryDirectory() + "nm-reader-\(name)-\(getpid())-\(Int.random(in: 0...99999))"
    try? FileManager.default.removeItem(atPath: path)
    return path
}

private func makeConn(ts: Timestamp, uid: Int64, host: String? = nil,
                      process: String? = nil, port: UInt16 = 443,
                      remote: String = "93.184.216.34",
                      state: ConnState = .sf, bytes: Int64 = 1000) -> ConnRecord {
    var c = ConnRecord(uid: FlowID(raw: UInt64(uid)), ts: ts, proto: 6,
                       origAddr: IPAddress("192.168.0.31")!, origPort: 49152,
                       respAddr: IPAddress(remote)!, respPort: port,
                       iface: "en0", state: state, history: "ShADadFf", pid: 501)
    c.tsEnd = ts + 1000
    c.origIPBytes = bytes
    c.respIPBytes = bytes * 2
    c.hostname = host
    c.hostnameSource = host == nil ? .none : .dnsPerProcess
    if let process { c.exec = ExecInfo(path: "/usr/bin/\(process)", name: process) }
    return c
}

func runStoreReaderTests() async {

    await NMTest.suite("StoreReader / paging") {

        await NMTest.test("paging returns every row exactly once") {
            let root = temporaryRoot("paging")
            defer { try? FileManager.default.removeItem(atPath: root) }
            let paths = Paths.temporary(root)

            let writer = try StoreWriter(paths: paths)
            var batch = RecordBatch()
            let base: Timestamp = 1_789_257_600_000_000
            for i in 0..<250 {
                batch.conns.append(makeConn(ts: base + Timestamp(i) * 1000, uid: Int64(i)))
            }
            try await writer.write(batch)
            try await writer.flush()
            await writer.close()

            let reader = StoreReader(paths: paths)
            var seen: [UInt64] = []
            var cursor: PageCursor?
            var pages = 0

            repeat {
                let page = try await reader.connectionRows(
                    QuerySpec(kind: .conn, limit: 40, cursor: cursor))
                seen.append(contentsOf: page.rows.map(\.uid))
                cursor = page.next
                pages += 1
            } while cursor != nil && pages < 20

            NMTest.equal(seen.count, 250, "got \(seen.count) rows over \(pages) pages")
            NMTest.equal(Set(seen).count, 250, "no row may be returned twice")
            await reader.close()
        }

        // The correctness argument for keyset. With OFFSET, a row inserted at
        // the head shifts every later page boundary, so a reader sees some rows
        // twice and misses others entirely.
        await NMTest.test("rows inserted while paging do not duplicate or skip earlier rows") {
            let root = temporaryRoot("concurrent")
            defer { try? FileManager.default.removeItem(atPath: root) }
            let paths = Paths.temporary(root)

            let writer = try StoreWriter(paths: paths)
            let base: Timestamp = 1_789_257_600_000_000
            var initial = RecordBatch()
            for i in 0..<120 {
                initial.conns.append(makeConn(ts: base + Timestamp(i) * 1000, uid: Int64(i)))
            }
            try await writer.write(initial)
            try await writer.flush()

            let reader = StoreReader(paths: paths)
            var seen: [UInt64] = []
            var cursor: PageCursor?
            var pages = 0

            repeat {
                let page = try await reader.connectionRows(
                    QuerySpec(kind: .conn, limit: 25, cursor: cursor))
                seen.append(contentsOf: page.rows.map(\.uid))
                cursor = page.next
                pages += 1

                // The daemon keeps writing between pages, which is the normal
                // state rather than a contrived one.
                var more = RecordBatch()
                for i in 0..<10 {
                    let uid = 1000 + pages * 10 + i
                    more.conns.append(makeConn(ts: base + Timestamp(2_000_000 + uid),
                                               uid: Int64(uid)))
                }
                try await writer.write(more)
                try await writer.flush()
            } while cursor != nil && pages < 12

            let original = seen.filter { $0 < 1000 }
            NMTest.equal(Set(original).count, original.count,
                         "a row was returned more than once")
            NMTest.equal(Set(original).count, 120,
                         "saw \(Set(original).count) of the 120 original rows")

            await writer.close()
            await reader.close()
        }

        await NMTest.test("paging crosses a day boundary") {
            let root = temporaryRoot("crossday")
            defer { try? FileManager.default.removeItem(atPath: root) }
            let paths = Paths.temporary(root)

            let writer = try StoreWriter(paths: paths)
            let day1: Timestamp = 1_789_257_600_000_000
            let day2 = day1 + 86_400 * Time.microsPerSecond

            var first = RecordBatch()
            for i in 0..<60 {
                first.conns.append(makeConn(ts: day1 + Timestamp(i) * 1000, uid: Int64(i)))
            }
            try await writer.write(first)

            var second = RecordBatch()
            for i in 0..<60 {
                second.conns.append(makeConn(ts: day2 + Timestamp(i) * 1000,
                                             uid: Int64(100 + i)))
            }
            try await writer.write(second)          // triggers rotation
            try await writer.flush()
            await writer.close()

            let reader = StoreReader(paths: paths)
            NMTest.expect(await reader.availablePartitions().count >= 2,
                          "expected a live partition and an archive")

            var seen: [UInt64] = []
            var cursor: PageCursor?
            var pages = 0
            repeat {
                let page = try await reader.connectionRows(
                    QuerySpec(kind: .conn, limit: 25, cursor: cursor))
                seen.append(contentsOf: page.rows.map(\.uid))
                cursor = page.next
                pages += 1
            } while cursor != nil && pages < 12

            NMTest.equal(Set(seen).count, 120,
                         "rows from both partitions must be reachable")
            await reader.close()
        }
    }

    await NMTest.suite("StoreReader / filters") {

        await NMTest.test("filters narrow without dropping matching rows") {
            let root = temporaryRoot("filters")
            defer { try? FileManager.default.removeItem(atPath: root) }
            let paths = Paths.temporary(root)

            let writer = try StoreWriter(paths: paths)
            let base: Timestamp = 1_789_257_600_000_000
            var batch = RecordBatch()
            for i in 0..<30 {
                batch.conns.append(makeConn(ts: base + Timestamp(i) * 1000, uid: Int64(i),
                                            host: "example.com", process: "Safari",
                                            port: 443, remote: "93.184.216.34"))
            }
            for i in 30..<50 {
                batch.conns.append(makeConn(ts: base + Timestamp(i) * 1000, uid: Int64(i),
                                            host: "slack.com", process: "Slack",
                                            port: 80, remote: "10.1.2.3",
                                            state: .s0, bytes: 10))
            }
            try await writer.write(batch)
            try await writer.flush()
            await writer.close()

            let reader = StoreReader(paths: paths)

            var byProcess = QueryFilter()
            byProcess.process = "Slack"
            let slack = try await reader.connectionRows(
                QuerySpec(kind: .conn, filter: byProcess, limit: 500))
            NMTest.equal(slack.rows.count, 20)

            var byHost = QueryFilter()
            byHost.host = "example.com"
            let example = try await reader.connectionRows(
                QuerySpec(kind: .conn, filter: byHost, limit: 500))
            NMTest.equal(example.rows.count, 30)

            var byPort = QueryFilter()
            byPort.port = 80
            NMTest.equal(try await reader.connectionRows(
                QuerySpec(kind: .conn, filter: byPort, limit: 500)).rows.count, 20)

            var byState = QueryFilter()
            byState.state = "S0"
            NMTest.equal(try await reader.connectionRows(
                QuerySpec(kind: .conn, filter: byState, limit: 500)).rows.count, 20)

            var bySize = QueryFilter()
            bySize.minimumBytes = 1000
            NMTest.equal(try await reader.connectionRows(
                QuerySpec(kind: .conn, filter: bySize, limit: 500)).rows.count, 30)

            await reader.close()
        }

        // CIDR compiles to BETWEEN over the BLOB column, which is an index
        // range scan. Stored as text the same filter would be a full scan.
        await NMTest.test("a CIDR filter selects by address range") {
            let root = temporaryRoot("cidr")
            defer { try? FileManager.default.removeItem(atPath: root) }
            let paths = Paths.temporary(root)

            let writer = try StoreWriter(paths: paths)
            let base: Timestamp = 1_789_257_600_000_000
            var batch = RecordBatch()
            for (i, remote) in ["10.0.0.5", "10.0.1.9", "10.255.255.1",
                                "11.0.0.1", "9.255.255.255", "8.8.8.8"].enumerated() {
                batch.conns.append(makeConn(ts: base + Timestamp(i) * 1000,
                                            uid: Int64(i), remote: remote))
            }
            try await writer.write(batch)
            try await writer.flush()
            await writer.close()

            let reader = StoreReader(paths: paths)
            var filter = QueryFilter()
            filter.address = IPPrefix("10.0.0.0/8")
            let page = try await reader.connectionRows(
                QuerySpec(kind: .conn, filter: filter, limit: 500))

            NMTest.equal(page.rows.count, 3, "10/8 contains exactly three of these")
            NMTest.expect(page.rows.allSatisfy { $0.remoteAddress.hasPrefix("10.") })
            await reader.close()
        }

        // User text must never reach the query as SQL: this reads a database
        // written by a root process.
        await NMTest.test("filter text is bound, not interpolated") {
            let root = temporaryRoot("injection")
            defer { try? FileManager.default.removeItem(atPath: root) }
            let paths = Paths.temporary(root)

            let writer = try StoreWriter(paths: paths)
            var batch = RecordBatch()
            batch.conns = [makeConn(ts: 1_789_257_600_000_000, uid: 1, host: "example.com")]
            try await writer.write(batch)
            try await writer.flush()
            await writer.close()

            let reader = StoreReader(paths: paths)
            var hostile = QueryFilter()
            hostile.text = "'; DROP TABLE conn; --"
            let page = try await reader.connectionRows(
                QuerySpec(kind: .conn, filter: hostile, limit: 100))
            NMTest.equal(page.rows.count, 0, "no match, and no damage")

            // The table must still be there.
            let all = try await reader.connectionRows(QuerySpec(kind: .conn, limit: 100))
            NMTest.equal(all.rows.count, 1, "the table survived")
            await reader.close()
        }
    }

    await NMTest.suite("StoreReader / DNS and TLS") {

        await NMTest.test("DNS rows carry their answers, rtt and failure state") {
            let root = temporaryRoot("dns")
            defer { try? FileManager.default.removeItem(atPath: root) }
            let paths = Paths.temporary(root)

            let writer = try StoreWriter(paths: paths)
            let base: Timestamp = 1_789_257_600_000_000
            var batch = RecordBatch()

            var answered = DNSRecord(ts: base, proto: 17,
                                     clientAddr: IPAddress("192.168.0.31")!,
                                     serverAddr: IPAddress("192.168.0.1")!,
                                     serverPort: 53, transactionID: 1,
                                     query: "example.com", qtype: 1,
                                     answers: ["93.184.216.34"], ttls: [300])
            answered.rttUs = 12_500
            answered.exec = ExecInfo(path: "/Applications/Safari.app", name: "Safari")

            let unanswered = DNSRecord(ts: base + 1000, proto: 17,
                                       clientAddr: IPAddress("192.168.0.31")!,
                                       serverAddr: IPAddress("192.168.0.1")!,
                                       serverPort: 53, transactionID: 2,
                                       query: "blackhole.example.com", qtype: 1,
                                       rejected: true)
            batch.dns = [answered, unanswered]
            try await writer.write(batch)
            try await writer.flush()
            await writer.close()

            let reader = StoreReader(paths: paths)
            let page = try await reader.dnsQueries(QuerySpec(kind: .dns, limit: 100))
            NMTest.equal(page.rows.count, 2)

            let byName = Dictionary(uniqueKeysWithValues: page.rows.map { ($0.query, $0) })
            NMTest.equal(byName["example.com"]?.rttUs, 12_500)
            NMTest.equal(byName["example.com"]?.answers, ["93.184.216.34"])
            NMTest.equal(byName["example.com"]?.processName, "Safari")
            NMTest.expect(byName["blackhole.example.com"]?.isProblem == true)
            await reader.close()
        }

        await NMTest.test("TLS rows carry SNI, fingerprints and certificate state") {
            let root = temporaryRoot("tls")
            defer { try? FileManager.default.removeItem(atPath: root) }
            let paths = Paths.temporary(root)

            let writer = try StoreWriter(paths: paths)
            let base: Timestamp = 1_789_257_600_000_000
            var batch = RecordBatch()

            var modern = SSLRecord(ts: base, clientAddr: IPAddress("192.168.0.31")!,
                                   serverAddr: IPAddress("93.184.216.34")!,
                                   serverPort: 443, version: 0x0304, cipher: 0x1301)
            modern.sni = "example.com"
            modern.ja4 = "t13d1516h2_8daaf6152771_02713d6af862"
            modern.ja3 = "cd08e31494f9531f560d64c695473da9"
            modern.certsEncrypted = true
            modern.established = true

            var legacy = SSLRecord(ts: base + 1000, clientAddr: IPAddress("192.168.0.31")!,
                                   serverAddr: IPAddress("10.0.0.9")!,
                                   serverPort: 443, version: 0x0301, cipher: 0xC013)
            legacy.sni = "old.example.net"
            legacy.subject = "CN=old.example.net"
            legacy.established = true

            batch.ssl = [modern, legacy]
            try await writer.write(batch)
            try await writer.flush()
            await writer.close()

            let reader = StoreReader(paths: paths)
            let page = try await reader.tlsSessions(QuerySpec(kind: .ssl, limit: 100))
            NMTest.equal(page.rows.count, 2)

            let bySNI = Dictionary(uniqueKeysWithValues: page.rows.compactMap { row in
                row.sni.map { ($0, row) }
            })
            NMTest.equal(bySNI["example.com"]?.versionName, "TLS 1.3")
            NMTest.expect(bySNI["example.com"]?.certsEncrypted == true,
                          "a 1.3 certificate is unavailable, not unknown")
            NMTest.equal(bySNI["example.com"]?.ja4, "t13d1516h2_8daaf6152771_02713d6af862")
            NMTest.expect(bySNI["old.example.net"]?.isWeakVersion == true,
                          "TLS 1.0 must be flagged")
            NMTest.equal(bySNI["old.example.net"]?.subject, "CN=old.example.net")
            await reader.close()
        }

        await NMTest.test("an empty store yields no rows rather than failing") {
            let root = temporaryRoot("empty")
            defer { try? FileManager.default.removeItem(atPath: root) }
            let reader = StoreReader(paths: Paths.temporary(root))
            let page = try await reader.connectionRows(QuerySpec(kind: .conn))
            NMTest.equal(page.rows.count, 0)
            NMTest.expect(page.next == nil)
            await reader.close()
        }
    }
}

/// Attribution has to survive the whole path, not just each layer in isolation.
///
/// Found live: every DNS query from Chrome was recorded against an unrelated
/// helper process. Each layer was correct on its own -- the packets carried the
/// right process, the analyzer read it, the store wrote it -- but the store's
/// identity key was (path, uuid) and analyzers supplied neither, so every
/// analyzer-produced identity interned to one row and inherited whichever name
/// arrived first.
func runAttributionTests() async {
    await NMTest.suite("Attribution / end to end") {

        // A daemon restarting part-way through a day -- an upgrade, a crash, a
        // reboot -- writes into a live.db that already holds today's flows.
        await NMTest.test("flow ids resume after a restart instead of colliding") {
            let root = NSTemporaryDirectory() + "nm-uid-\(getpid())-\(Int.random(in: 0...9999))"
            defer { try? FileManager.default.removeItem(atPath: root) }
            let paths = Paths.temporary(root)
            let base: Timestamp = 1_789_257_600_000_000

            // First run: flow ids 1...20, the sequence a fresh FlowTable hands out.
            let first = try StoreWriter(paths: paths)
            NMTest.equal(first.highestFlowUID, 0, "a fresh store reported flow ids already on file")
            var batch = RecordBatch()
            for uid in 1...20 {
                batch.conns.append(makeConn(ts: base + Timestamp(uid) * 1000, uid: Int64(uid)))
            }
            try await first.write(batch)
            try await first.flush()
            await first.close()

            // Restart.
            let second = try StoreWriter(paths: paths)
            NMTest.equal(second.highestFlowUID, 20,
                         "restart saw \(second.highestFlowUID) as the highest flow id, not 20")

            // The table must continue the sequence, not replay it.
            let resumed = FlowTable(firstUID: second.highestFlowUID + 1)
            NMTest.equal(resumed.peekNextUID, 21,
                         "seeded table would hand out \(resumed.peekNextUID)")

            var more = RecordBatch()
            for uid in 21...30 {
                more.conns.append(makeConn(ts: base + Timestamp(uid) * 1000, uid: Int64(uid)))
            }
            try await second.write(more)
            try await second.flush()
            await second.close()

            let reader = StoreReader(paths: paths)
            let page = try await reader.connectionRows(QuerySpec(kind: .conn, limit: 100))
            NMTest.equal(page.rows.count, 30, "restart lost rows: \(page.rows.count) of 30")
            await reader.close()
        }

        // The control: without the seed the collision is real, and because a
        // batch is one transaction it takes the DNS rows written beside it too.
        await NMTest.test("an unseeded restart loses the whole batch, not just conn") {
            let root = NSTemporaryDirectory() + "nm-uidc-\(getpid())-\(Int.random(in: 0...9999))"
            defer { try? FileManager.default.removeItem(atPath: root) }
            let paths = Paths.temporary(root)
            let base: Timestamp = 1_789_257_600_000_000

            let first = try StoreWriter(paths: paths)
            var batch = RecordBatch()
            for uid in 1...5 { batch.conns.append(makeConn(ts: base + Timestamp(uid) * 1000, uid: Int64(uid))) }
            try await first.write(batch)
            try await first.flush()
            await first.close()

            // Replaying id 1, as an unseeded FlowTable would.
            let second = try StoreWriter(paths: paths)
            var replay = RecordBatch()
            replay.conns.append(makeConn(ts: base + 99_000, uid: 1))
            var dns = DNSRecord(
                ts: base + 99_000, proto: 17,
                clientAddr: IPAddress("192.168.0.31")!, serverAddr: IPAddress("192.168.0.1")!,
                serverPort: 53, transactionID: 7, query: "collateral.example.com",
                qtype: 1, answers: ["1.2.3.4"], ttls: [300])
            dns.rttUs = 1000
            replay.dns.append(dns)

            var threw = false
            do { try await second.write(replay) } catch { threw = true }
            NMTest.expect(threw, "a duplicate flow id was accepted")
            try? await second.flush()
            await second.close()

            let reader = StoreReader(paths: paths)
            let queries = try await reader.dnsQueries(QuerySpec(kind: .dns, limit: 100))
            NMTest.equal(queries.rows.count, 0,
                         "the DNS row survived a rolled-back batch, so the transaction is not atomic")
            await reader.close()
        }

        // The exact situation an existing install is in: meta.db was built by
        // the previous schema, and the daemon is restarted carrying the fix.
        await NMTest.test("an existing meta.db is migrated off the v1 exec index") {
            let root = NSTemporaryDirectory() + "nm-mig-\(getpid())-\(Int.random(in: 0...9999))"
            defer { try? FileManager.default.removeItem(atPath: root) }
            let paths = Paths.temporary(root)

            // Build the tree, then put meta.db back to the v1 index by hand.
            await (try StoreWriter(paths: paths)).close()
            do {
                let side = try SQLiteConnection(path: paths.metaDatabase)
                try side.exec("""
                    DROP INDEX ux_exec_ident;
                    CREATE UNIQUE INDEX ux_exec_ident ON exec(path, uuid_hi, uuid_lo);
                    """)
                // Stamped current even though the index is old -- what a restart
                // on the fixed build actually leaves behind, and the reason the
                // migration reads the index instead of the stamp.
                try side.exec("PRAGMA user_version = \(Schema.version)")
                side.close()
            }

            // Opening a writer must repair it.
            let writer = try StoreWriter(paths: paths)
            let base: Timestamp = 1_789_257_600_000_000
            var batch = RecordBatch()
            // No path and no UUID: identical under the v1 key, distinct under v2.
            for (index, name) in ["Google Chrome Helper", "Aside Helper"].enumerated() {
                var record = DNSRecord(
                    ts: base + Timestamp(index) * 1000, proto: 17,
                    clientAddr: IPAddress("192.168.0.31")!,
                    serverAddr: IPAddress("192.168.0.1")!,
                    serverPort: 53, transactionID: UInt16(index),
                    query: "host\(index).example.com", qtype: 1,
                    answers: ["1.2.3.\(index + 1)"], ttls: [300])
                record.rttUs = 1000
                record.exec = ExecInfo(path: "", name: name, uuidHi: 0, uuidLo: 0)
                batch.dns.append(record)
            }
            try await writer.write(batch)
            try await writer.flush()
            await writer.close()

            let check = try SQLiteConnection(path: paths.metaDatabase)
            let columns = try check.scalarInt(
                "SELECT count(*) FROM pragma_index_info('ux_exec_ident')") ?? 0
            NMTest.equal(columns, 4, "exec index still has \(columns) columns")
            check.close()

            let reader = StoreReader(paths: paths)
            let page = try await reader.dnsQueries(QuerySpec(kind: .dns, limit: 100))
            let names = Set(page.rows.compactMap(\.processName))
            NMTest.equal(names.count, 2,
                         "identities merged after migration: \(names)")
            await reader.close()
        }

        await NMTest.test("processes with no path stay distinct") {
            let root = NSTemporaryDirectory() + "nm-attr-\(getpid())-\(Int.random(in: 0...9999))"
            defer { try? FileManager.default.removeItem(atPath: root) }
            let paths = Paths.temporary(root)
            let writer = try StoreWriter(paths: paths)

            let base: Timestamp = 1_789_257_600_000_000
            var batch = RecordBatch()

            // Exactly what the analyzers produce: a name and a UUID, no path.
            for (index, name) in ["Google Chrome Helper", "gh", "Slack"].enumerated() {
                var record = DNSRecord(
                    ts: base + Timestamp(index) * 1000, proto: 17,
                    clientAddr: IPAddress("192.168.0.31")!,
                    serverAddr: IPAddress("192.168.0.1")!,
                    serverPort: 53, transactionID: UInt16(index),
                    query: "host\(index).example.com", qtype: 1,
                    answers: ["1.2.3.\(index + 1)"], ttls: [300])
                record.rttUs = 1000
                record.exec = ExecInfo(path: "", name: name,
                                       uuidHi: UInt64(0xAAAA + index),
                                       uuidLo: UInt64(0xBBBB + index))
                batch.dns.append(record)
            }
            try await writer.write(batch)
            try await writer.flush()
            await writer.close()

            let reader = StoreReader(paths: paths)
            let page = try await reader.dnsQueries(QuerySpec(kind: .dns, limit: 100))
            let names = Set(page.rows.compactMap(\.processName))

            NMTest.equal(names.count, 3,
                         "three processes collapsed to \(names.count): \(names)")
            NMTest.expect(names.contains("Google Chrome Helper"))
            NMTest.expect(names.contains("gh"))
            await reader.close()
        }

        // The safety net for the case that actually happened: no path AND no
        // UUID. Distinct names must still not merge.
        await NMTest.test("identities with neither path nor UUID stay distinct") {
            let root = NSTemporaryDirectory() + "nm-attr2-\(getpid())-\(Int.random(in: 0...9999))"
            defer { try? FileManager.default.removeItem(atPath: root) }
            let paths = Paths.temporary(root)
            let writer = try StoreWriter(paths: paths)

            var batch = RecordBatch()
            for (index, name) in ["Safari", "Mail", "Spotify"].enumerated() {
                var record = DNSRecord(
                    ts: 1_789_257_600_000_000 + Timestamp(index), proto: 17,
                    clientAddr: IPAddress("192.168.0.31")!,
                    serverAddr: IPAddress("192.168.0.1")!,
                    serverPort: 53, transactionID: UInt16(index),
                    query: "q\(index).example.com", qtype: 1)
                record.exec = ExecInfo(path: "", name: name)   // no uuid at all
                batch.dns.append(record)
            }
            try await writer.write(batch)
            try await writer.flush()
            await writer.close()

            let reader = StoreReader(paths: paths)
            let page = try await reader.dnsQueries(QuerySpec(kind: .dns, limit: 100))
            NMTest.equal(Set(page.rows.compactMap(\.processName)).count, 3,
                         "a zero UUID must not merge distinct processes")
            await reader.close()
        }
    }
}
