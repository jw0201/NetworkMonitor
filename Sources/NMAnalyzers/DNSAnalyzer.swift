//
//  DNSAnalyzer.swift
//
//  Turns DNS traffic into dns.log rows, and offers every resolved address to
//  the enrichment cache.
//
//  The pending-query table is the only real state. It exists to compute round
//  trip time and, more importantly, to notice queries that were never answered
//  at all -- which is what a blocked resolver, a captive portal or a firewall
//  drop looks like, and which a request/response pairing that only fires on
//  responses would never report.
//

import NMCore
import NMFlow

public final class DNSAnalyzer: PacketAnalyzer {

    public let identifier = "dns"

    public var triggers: [AnalyzerTrigger] {
        [
            .port(proto: TransportParser.udp, port: 53),
            .port(proto: TransportParser.tcp, port: 53),
            .port(proto: TransportParser.udp, port: 5353),   // mDNS
            .port(proto: TransportParser.udp, port: 5355),   // LLMNR
        ]
    }

    /// A query awaiting its answer.
    private struct PendingQuery {
        var askedAt: Timestamp
        var question: DNSQuestion
        var clientAddress: IPAddress
        var serverAddress: IPAddress
        var serverPort: UInt16
        var proto: UInt8
        var pid: Int32
        var processName: String
        var flowUID: FlowID
    }

    /// Keyed on more than the transaction ID: a 16-bit ID is reused constantly,
    /// and matching on it alone across flows would pair a response with the
    /// wrong question.
    private struct PendingKey: Hashable {
        var flowUID: UInt64
        var transactionID: UInt16
        var questionHash: UInt64
    }

    private var pending: [PendingKey: PendingQuery] = [:]
    private var lastSweep: Timestamp = 0

    /// How long to wait before declaring a query unanswered.
    public var queryTimeoutSeconds: Int64 = 5
    /// Bounded because queries are attacker-generated: a flood of unanswerable
    /// lookups must not choose our memory footprint.
    public var maximumPending = 4096

    public private(set) var stats = Stats()

    public struct Stats: Sendable, Equatable {
        public var queries: Int64 = 0
        public var responses: Int64 = 0
        public var unanswered: Int64 = 0
        public var malformed: Int64 = 0
        public var truncatedParses: Int64 = 0
        public var pendingEvicted: Int64 = 0
        public var namesResolved: Int64 = 0
    }

    public init() {}

    // MARK: - Analysis

    public func analyze(_ context: AnalyzerContext,
                        payload: ByteReader,
                        emit: (AnalyzerOutput) -> Void) -> AnalyzerVerdict {
        var reader = payload

        // DNS over TCP prefixes each message with a 2-byte length. Only the
        // first message in a segment is handled: a pipelined second message
        // needs stream reassembly, which is not yet built.
        if context.proto == TransportParser.tcp {
            guard let length = try? reader.u16be(), length > 0 else {
                return .notMine
            }
            guard let scoped = try? reader.sub(min(Int(length), reader.remaining)) else {
                return .wantMore
            }
            reader = scoped
        }

        guard let message = try? DNSParser.parse(reader), isPlausiblyDNS(message) else {
            // Traffic on port 53 that is not DNS is usually a tunnel or a scan,
            // and labelling it "dns" would be worse than labelling it nothing.
            //
            // The parser alone is not enough of a filter: twelve bytes of
            // anything form a syntactically valid header, so random payloads
            // parse into a message with a garbage opcode and no questions.
            // A real query always carries a question, and a real response
            // echoes one back.
            stats.malformed += 1
            return context.proto == TransportParser.tcp ? .notMine : .wantMore
        }

        if message.parseTruncated { stats.truncatedParses += 1 }
        emit(.service(serviceName(for: context)))

        if message.header.isResponse {
            handleResponse(message, context, emit)
        } else {
            handleQuery(message, context)
        }
        return .wantMore
    }

    /// Cheap structural sanity checks that separate DNS from arbitrary bytes
    /// that happen to be at least twelve long.
    private func isPlausiblyDNS(_ message: DNSMessage) -> Bool {
        // Opcodes above 5 are unassigned. QUERY(0), IQUERY(1), STATUS(2),
        // NOTIFY(4) and UPDATE(5) are what real traffic uses.
        guard message.header.opcode <= 5 else { return false }
        // Response codes above 10 are unassigned in the 4-bit field.
        guard message.header.responseCode <= 10 else { return false }
        // Both directions carry the question section.
        guard !message.questions.isEmpty else { return false }
        // A question that decoded to nothing means the name parser bailed on
        // the first byte, which random data does constantly.
        guard let first = message.primaryQuestion, first.name != "." else { return false }
        return true
    }

    private func serviceName(for context: AnalyzerContext) -> String {
        if context.destinationPort == 5353 || context.sourcePort == 5353 { return "mdns" }
        if context.destinationPort == 5355 || context.sourcePort == 5355 { return "llmnr" }
        return "dns"
    }

    private func handleQuery(_ message: DNSMessage, _ context: AnalyzerContext) {
        guard let question = message.primaryQuestion else { return }
        stats.queries += 1

        // Multicast DNS queries are broadcast with no expectation of a matching
        // response on the same flow, so pairing them would only ever produce
        // false "unanswered" rows.
        guard context.destinationPort != 5353 else { return }

        if pending.count >= maximumPending {
            // Drop the oldest rather than refusing new ones: a flood of
            // unanswerable queries should not blind us to real traffic.
            if let oldest = pending.min(by: { $0.value.askedAt < $1.value.askedAt }) {
                pending.removeValue(forKey: oldest.key)
                stats.pendingEvicted += 1
            }
        }

        let key = PendingKey(flowUID: context.flowUID.raw,
                             transactionID: message.header.transactionID,
                             questionHash: hash(question.name, question.type))
        pending[key] = PendingQuery(askedAt: context.packet.timestamp,
                                    question: question,
                                    clientAddress: context.sourceAddress,
                                    serverAddress: context.destinationAddress,
                                    serverPort: context.destinationPort,
                                    proto: context.proto,
                                    pid: context.packet.pid ?? 0,
                                    processName: context.packet.processName,
                                    flowUID: context.flowUID)
    }

    private func handleResponse(_ message: DNSMessage, _ context: AnalyzerContext,
                                _ emit: (AnalyzerOutput) -> Void) {
        stats.responses += 1
        guard let question = message.primaryQuestion else { return }

        let key = PendingKey(flowUID: context.flowUID.raw,
                             transactionID: message.header.transactionID,
                             questionHash: hash(question.name, question.type))
        let matched = pending.removeValue(forKey: key)

        var record = DNSRecord(
            ts: matched?.askedAt ?? context.packet.timestamp,
            proto: context.proto,
            clientAddr: matched?.clientAddress ?? context.destinationAddress,
            serverAddr: matched?.serverAddress ?? context.sourceAddress,
            serverPort: matched?.serverPort ?? context.sourcePort,
            transactionID: message.header.transactionID,
            query: question.name,
            qtype: question.type,
            qclass: question.questionClass,
            rcode: UInt16(message.header.responseCode),
            flags: message.header.rawFlags,
            pid: matched?.pid ?? context.packet.pid ?? 0)

        record.uid = context.flowUID
        if let matched {
            record.rttUs = context.packet.timestamp - matched.askedAt
            if !matched.processName.isEmpty {
                record.exec = ExecInfo(path: "", name: matched.processName)
            }
        } else if !context.packet.processName.isEmpty {
            record.exec = ExecInfo(path: "", name: context.packet.processName)
        }

        // Resolve each address back through the CNAME chain to the name that
        // was ORIGINALLY asked for. A CDN answer is a chain of aliases, and
        // reporting the final edge-node name instead of the name the user's
        // application asked for would be technically true and useless.
        var aliases: [String: String] = [:]          // target -> owner
        for answer in message.answers where answer.data.isName {
            if case .name(let target) = answer.data { aliases[target] = answer.name }
        }

        for answer in message.answers {
            record.answers.append(answer.data.displayValue)
            record.ttls.append(answer.ttl)

            guard case .address(let address) = answer.data else { continue }
            let originalName = resolveToOriginalName(answer.name, aliases: aliases)
            stats.namesResolved += 1
            emit(.resolvedName(address: address,
                               name: originalName,
                               ttl: answer.ttl,
                               requestingPID: matched?.pid ?? context.packet.pid ?? 0))
        }

        emit(.dns(record))
    }

    /// Walks alias links back to the name originally queried. Capped, because a
    /// crafted response can contain a cycle of CNAMEs.
    private func resolveToOriginalName(_ name: String,
                                       aliases: [String: String]) -> String {
        var current = name
        var seen = 0
        while let owner = aliases[current], seen < Limits.maxCNAMEChain {
            current = owner
            seen += 1
        }
        return current
    }

    // MARK: - Expiry

    /// Emits rows for queries that were never answered.
    ///
    /// These are the diagnostically valuable ones: a query with no response is
    /// what a blocked resolver, a captive portal or a dropped packet looks
    /// like, and a pairing that only fired on responses would show nothing at
    /// all in exactly the case a user is trying to debug.
    public func tick(now: Timestamp, emit: (AnalyzerOutput) -> Void) {
        guard now - lastSweep >= Time.microsPerSecond else { return }
        lastSweep = now

        let deadline = now - queryTimeoutSeconds * Time.microsPerSecond
        var expired: [PendingKey] = []
        for (key, query) in pending where query.askedAt < deadline {
            expired.append(key)
        }

        for key in expired {
            guard let query = pending.removeValue(forKey: key) else { continue }
            stats.unanswered += 1

            var record = DNSRecord(ts: query.askedAt,
                                   proto: query.proto,
                                   clientAddr: query.clientAddress,
                                   serverAddr: query.serverAddress,
                                   serverPort: query.serverPort,
                                   transactionID: key.transactionID,
                                   query: query.question.name,
                                   qtype: query.question.type,
                                   qclass: query.question.questionClass,
                                   rejected: true,
                                   pid: query.pid)
            record.uid = query.flowUID
            if !query.processName.isEmpty {
                record.exec = ExecInfo(path: "", name: query.processName)
            }
            emit(.dns(record))
        }
    }

    public func flowClosed(_ uid: FlowID, emit: (AnalyzerOutput) -> Void) {
        // Leave pending queries alone: a UDP "flow" expires on an idle timeout
        // that is shorter than some resolvers take to answer, and discarding
        // the query here would turn a slow answer into a lost row. `tick`
        // decides when a query is genuinely unanswered.
    }

    public var pendingCount: Int { pending.count }

    private func hash(_ name: String, _ type: UInt16) -> UInt64 {
        seededHash(UInt64(truncatingIfNeeded: name.hashValue), UInt64(type))
    }
}

private extension DNSRecordData {
    var isName: Bool {
        if case .name = self { return true }
        return false
    }
}
