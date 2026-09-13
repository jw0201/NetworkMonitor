//
//  TLSAnalyzer.swift
//
//  Turns TLS handshakes into ssl.log rows.
//
//  The handshake is watched until both hellos have been seen, then the row is
//  emitted and the analyzer detaches -- everything after that is encrypted and
//  there is nothing further to learn by looking. Detaching matters: a long
//  download would otherwise re-run the deframer over a growing buffer on every
//  segment.
//

import NMCore
import NMFlow

public final class TLSAnalyzer: PacketAnalyzer {

    public let identifier = "ssl"

    public var triggers: [AnalyzerTrigger] {
        [
            .port(proto: TransportParser.tcp, port: 443),
            .port(proto: TransportParser.tcp, port: 8443),
            .port(proto: TransportParser.tcp, port: 993),    // IMAPS
            .port(proto: TransportParser.tcp, port: 995),    // POP3S
            .port(proto: TransportParser.tcp, port: 465),    // SMTPS
            .port(proto: TransportParser.tcp, port: 563),    // NNTPS
            .port(proto: TransportParser.tcp, port: 636),    // LDAPS
            .port(proto: TransportParser.tcp, port: 990),    // FTPS
            .port(proto: TransportParser.tcp, port: 5223),   // APNs
        ]
    }

    /// What has been learned about one handshake so far.
    private struct Session {
        var startedAt: Timestamp
        var clientAddress: IPAddress
        var serverAddress: IPAddress
        var serverPort: UInt16
        var pid: Int32
        var processName: String

        var clientHello: TLSClientHello?
        var serverHello: TLSServerHello?
        var fingerprints = TLSFingerprints()
        var history = ""
        var certificates: [ParsedCertificate] = []
        var sawEncryptedExtensions = false
        var emitted = false
    }

    private var sessions: [UInt64: Session] = [:]
    /// Bounded: a flood of connections to port 443 that never complete a
    /// handshake must not choose how much memory this analyzer uses.
    public var maximumSessions = 4096

    public private(set) var stats = Stats()

    public struct Stats: Sendable, Equatable {
        public var clientHellos: Int64 = 0
        public var serverHellos: Int64 = 0
        public var completed: Int64 = 0
        public var notTLS: Int64 = 0
        public var malformed: Int64 = 0
        public var certificatesParsed: Int64 = 0
        public var encryptedCertificates: Int64 = 0
        public var encryptedClientHellos: Int64 = 0
        public var sessionsEvicted: Int64 = 0
        public var abandonedIncomplete: Int64 = 0
    }

    public init() {}

    public var sessionCount: Int { sessions.count }

    // MARK: - Analysis

    public func analyze(_ context: AnalyzerContext,
                        payload: ByteReader,
                        emit: (AnalyzerOutput) -> Void) -> AnalyzerVerdict {
        // Port 443 carries plenty that is not TLS. Labelling those flows "ssl"
        // would be a confident mislabel, so check the shape first.
        guard TLSRecordLayer.looksLikeTLS(payload) else {
            stats.notTLS += 1
            return .notMine
        }

        // Anything past a gap is guesswork: record boundaries are defined by
        // lengths, so a hole desynchronises the deframer permanently.
        if context.streamHasGap {
            finish(context, emit: emit, reason: .failed("stream gap"))
            return .failed("stream gap")
        }

        emit(.service("ssl"))

        let uid = context.flowUID.raw
        if sessions[uid] == nil {
            guard sessions.count < maximumSessions else {
                stats.sessionsEvicted += 1
                return .notMine
            }
            sessions[uid] = Session(startedAt: context.packet.timestamp,
                                    clientAddress: context.fromOriginator
                                        ? context.sourceAddress : context.destinationAddress,
                                    serverAddress: context.fromOriginator
                                        ? context.destinationAddress : context.sourceAddress,
                                    serverPort: context.fromOriginator
                                        ? context.destinationPort : context.sourcePort,
                                    pid: context.packet.pid ?? 0,
                                    processName: context.packet.processName)
        }
        guard var session = sessions[uid], !session.emitted else { return .satisfied }

        TLSRecordLayer.handshakeMessages(in: payload) { type, _, body in
            guard let type else { return true }
            appendHistory(&session, type, fromClient: context.fromOriginator)

            switch type {
            case .clientHello:
                guard let hello = try? TLSHandshakeParser.parseClientHello(body) else {
                    self.stats.malformed += 1
                    return false
                }
                self.stats.clientHellos += 1
                session.clientHello = hello

                let ja4 = TLSFingerprinter.ja4(hello)
                let ja3 = TLSFingerprinter.ja3(hello)
                session.fingerprints.ja4 = ja4.hash
                session.fingerprints.ja4Raw = ja4.raw
                session.fingerprints.ja3 = ja3.hash
                session.fingerprints.ja3Raw = ja3.raw

                if hello.hasEncryptedClientHello { self.stats.encryptedClientHellos += 1 }

                // SNI is the strongest hostname evidence available: it is what
                // the client literally asked this server for, on this
                // connection. It outranks the DNS cache, which is an inference
                // from a lookup that happened earlier -- unless ECH is in play,
                // in which case the visible name is the public outer name and
                // asserting it would be worse than saying nothing.
                if let sni = hello.serverName, !sni.isEmpty, !hello.hasEncryptedClientHello {
                    emit(.hostname(sni, .tlsSNI))
                }

            case .serverHello:
                guard let hello = try? TLSHandshakeParser.parseServerHello(body) else {
                    self.stats.malformed += 1
                    return false
                }
                self.stats.serverHellos += 1
                session.serverHello = hello
                session.fingerprints.ja4s = TLSFingerprinter.ja4s(hello)
                session.fingerprints.ja3s = TLSFingerprinter.ja3s(hello)

            case .certificate:
                // Reachable only under TLS 1.2 and below. Under 1.3 this
                // message exists but is inside the encrypted handshake, so it
                // never appears here.
                let isTLS13 = session.serverHello?.isTLS13 ?? false
                for der in CertificateParser.certificates(in: body, isTLS13: isTLS13) {
                    guard let parsed = CertificateParser.parse(der: der) else { continue }
                    session.certificates.append(parsed)
                    self.stats.certificatesParsed += 1
                }

            case .encryptedExtensions:
                session.sawEncryptedExtensions = true

            default:
                break
            }
            return true
        }

        sessions[uid] = session

        // Both hellos seen: everything else is encrypted.
        if session.clientHello != nil && session.serverHello != nil {
            finish(context, emit: emit, reason: .satisfied)
            return .satisfied
        }
        return .wantMore
    }

    private func appendHistory(_ session: inout Session, _ type: TLSHandshakeType,
                               fromClient: Bool) {
        guard session.history.count < 32 else { return }
        let letter = type.historyLetter
        let rendered = fromClient ? letter : Character(letter.lowercased())
        if !session.history.contains(rendered) { session.history.append(rendered) }
    }

    // MARK: - Emission

    private func finish(_ context: AnalyzerContext, emit: (AnalyzerOutput) -> Void,
                        reason: AnalyzerVerdict) {
        guard var session = sessions[context.flowUID.raw], !session.emitted else { return }
        session.emitted = true
        sessions[context.flowUID.raw] = session
        emitRecord(session, uid: context.flowUID, emit: emit)
    }

    private func emitRecord(_ session: Session, uid: FlowID,
                            emit: (AnalyzerOutput) -> Void) {
        guard let client = session.clientHello else { return }
        stats.completed += 1

        let server = session.serverHello
        var record = SSLRecord(ts: session.startedAt,
                               clientAddr: session.clientAddress,
                               serverAddr: session.serverAddress,
                               serverPort: session.serverPort,
                               version: server?.effectiveVersion ?? client.effectiveVersion,
                               cipher: server?.cipherSuite ?? 0,
                               pid: session.pid)
        record.uid = uid
        record.curve = server?.selectedGroup
        record.sni = client.serverName
        record.sniIsOuter = client.hasEncryptedClientHello
        // Under TLS 1.3 the server's ALPN is inside EncryptedExtensions, so
        // what the client offered is all that can be shown. Reporting the
        // client's list as the negotiated protocol would be a guess.
        record.alpn = server?.alpnProtocol ?? client.alpnProtocols.first
        record.sslHistory = session.history
        record.established = server != nil
        record.ja4 = session.fingerprints.ja4
        record.ja4Raw = session.fingerprints.ja4Raw
        record.ja3 = session.fingerprints.ja3
        record.ja4s = session.fingerprints.ja4s
        record.ja3s = session.fingerprints.ja3s

        if let first = session.certificates.first {
            record.subject = first.subject
            record.issuer = first.issuer
            record.notBefore = first.notBefore
            record.notAfter = first.notAfter
            record.chainFingerprints = session.certificates.map(\.fingerprint)
        } else if server?.isTLS13 == true {
            // Not "unknown" -- unavailable, and for a specific reason worth
            // recording so the UI can say so rather than shrug.
            record.certsEncrypted = true
            stats.encryptedCertificates += 1
        }

        if !session.processName.isEmpty {
            record.exec = ExecInfo(path: "", name: session.processName)
        }
        emit(.ssl(record))
    }

    public func flowClosed(_ uid: FlowID, emit: (AnalyzerOutput) -> Void) {
        guard let session = sessions.removeValue(forKey: uid.raw), !session.emitted else {
            sessions.removeValue(forKey: uid.raw)
            return
        }
        // A handshake that never completed is still worth a row: a ClientHello
        // with no answer is what a blocked or failing TLS connection looks
        // like, and it carries the SNI and the client fingerprint.
        if session.clientHello != nil {
            stats.abandonedIncomplete += 1
            emitRecord(session, uid: uid, emit: emit)
        }
    }
}
