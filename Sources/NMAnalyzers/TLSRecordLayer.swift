//
//  TLSRecordLayer.swift
//
//  Deframing, in three resumable layers.
//
//  A handshake message legitimately spans several TLS records, and a record
//  legitimately spans several TCP segments, so all three layers have to be
//  restartable: the analyzer is called with a growing prefix of the stream and
//  must produce nothing until a complete message is present, then produce it
//  exactly once.
//
//  Every length here is attacker-supplied. Records are capped at the protocol
//  maximum, handshake messages at a sane ceiling, and total handshake bytes at
//  a budget -- otherwise a peer can keep a flow's parser and buffer alive
//  indefinitely by never completing a handshake.
//

import NMCore

public enum TLSContentType: UInt8, Sendable {
    case changeCipherSpec = 20
    case alert = 21
    case handshake = 22
    case applicationData = 23

    public var name: String {
        switch self {
        case .changeCipherSpec: return "ccs"
        case .alert: return "alert"
        case .handshake: return "handshake"
        case .applicationData: return "data"
        }
    }
}

public enum TLSHandshakeType: UInt8, Sendable {
    case clientHello = 1
    case serverHello = 2
    case newSessionTicket = 4
    case encryptedExtensions = 8
    case certificate = 11
    case serverKeyExchange = 12
    case certificateRequest = 13
    case serverHelloDone = 14
    case certificateVerify = 15
    case clientKeyExchange = 16
    case finished = 20

    /// The letter this message contributes to ssl_history, Zeek style.
    /// Uppercase for client messages, lowercase for server.
    public var historyLetter: Character {
        switch self {
        case .clientHello: return "C"
        case .serverHello: return "S"
        case .newSessionTicket: return "R"
        case .encryptedExtensions: return "E"
        case .certificate: return "T"
        case .serverKeyExchange: return "X"
        case .certificateRequest: return "I"
        case .serverHelloDone: return "G"
        case .certificateVerify: return "Y"
        case .clientKeyExchange: return "K"
        case .finished: return "F"
        }
    }
}

public struct TLSRecord: Sendable {
    public var type: UInt8
    public var legacyVersion: UInt16
    /// Offset and length of the fragment within the stream buffer.
    public var payloadOffset: Int
    public var payloadLength: Int

    public var contentType: TLSContentType? { TLSContentType(rawValue: type) }
}

public enum TLSDeframeError: Error, Equatable {
    case notTLS
    case recordTooLong(Int)
    case messageTooLong(Int)
    case budgetExceeded
}

public enum TLSRecordLayer {

    public static let headerLength = 5
    /// 2^14 plus the maximum expansion the spec allows.
    public static let maximumRecordLength = Limits.maxTLSRecordLength
    public static let maximumHandshakeMessageLength = 65_536

    /// Cheap check that a stream looks like TLS before committing to parsing.
    ///
    /// Port 443 carries plenty of things that are not TLS -- QUIC on the UDP
    /// side, proxies, and anything an application chose to tunnel. Claiming a
    /// flow is TLS when it is not would put a wrong `service` on the conn row.
    public static func looksLikeTLS(_ reader: ByteReader) -> Bool {
        var r = reader
        guard let type = try? r.u8(), let version = try? r.u16be() else { return false }
        guard TLSContentType(rawValue: type) != nil else { return false }
        // The record-layer version is 0x0301-0x0304 in practice; TLS 1.3 still
        // writes 0x0301 or 0x0303 here for middlebox compatibility.
        return version >= 0x0300 && version <= 0x0304
    }

    /// Walks the records present in `reader`, stopping at the first incomplete
    /// one. Returns the offset where parsing should resume next time.
    public static func records(in reader: ByteReader,
                               from startOffset: Int = 0,
                               _ body: (TLSRecord) throws -> Bool) rethrows -> Int {
        var offset = startOffset
        var consumed = 0

        while offset + headerLength <= reader.count {
            guard var header = try? reader.reader(at: offset, count: headerLength) else { break }
            guard let type = try? header.u8(),
                  let version = try? header.u16be(),
                  let length = try? header.u16be() else { break }

            // A length above the protocol maximum means this is not TLS, or is
            // hostile. Either way, stop rather than trusting it.
            guard Int(length) <= maximumRecordLength else { return offset }

            let payloadStart = offset + headerLength
            guard payloadStart + Int(length) <= reader.count else { break }   // incomplete

            consumed += Int(length)
            guard consumed <= Limits.maxTLSHandshakeBytes else { return offset }

            let record = TLSRecord(type: type, legacyVersion: version,
                                   payloadOffset: payloadStart,
                                   payloadLength: Int(length))
            if !(try body(record)) { return payloadStart + Int(length) }
            offset = payloadStart + Int(length)
        }
        return offset
    }

    /// Reassembles handshake messages out of the handshake-type records.
    ///
    /// Handshake messages span records, so the fragments are concatenated
    /// first. That copy is bounded by the handshake budget and happens at most
    /// once per flow per direction, not per packet.
    public static func handshakeMessages(in reader: ByteReader,
                                         _ body: (TLSHandshakeType?, UInt8, ByteReader) throws -> Bool)
    rethrows {
        var fragments = [UInt8]()
        var sawNonHandshake = false

        _ = records(in: reader) { record in
            guard record.type == TLSContentType.handshake.rawValue else {
                // Once the handshake is over, everything is encrypted and there
                // is nothing further to read.
                sawNonHandshake = true
                return false
            }
            guard fragments.count + record.payloadLength <= Limits.maxTLSHandshakeBytes else {
                return false
            }
            if let bytes = try? reader.reader(at: record.payloadOffset,
                                              count: record.payloadLength) {
                var r = bytes
                if let raw = try? r.bytes(record.payloadLength) {
                    fragments.append(contentsOf: raw)
                }
            }
            return true
        }
        _ = sawNonHandshake

        guard !fragments.isEmpty else { return }

        try fragments.withUnsafeBytes { buffer in
            guard let stream = ByteReader(buffer) else { return }
            var offset = 0
            var messages = 0

            while offset + 4 <= stream.count && messages < 32 {
                guard var header = try? stream.reader(at: offset, count: 4) else { return }
                guard let rawType = try? header.u8(),
                      let length = try? header.u24be() else { return }

                guard Int(length) <= maximumHandshakeMessageLength else { return }
                let bodyStart = offset + 4
                guard bodyStart + Int(length) <= stream.count else { return }   // incomplete

                guard let messageBody = try? stream.reader(at: bodyStart,
                                                           count: Int(length)) else { return }
                messages += 1
                if !(try body(TLSHandshakeType(rawValue: rawType), rawType, messageBody)) {
                    return
                }
                offset = bodyStart + Int(length)
            }
        }
    }
}

/// GREASE values, which exist to stop middleboxes hard-coding assumptions about
/// what they see. They must be stripped before fingerprinting or the
/// fingerprint changes on every connection -- which is precisely what they were
/// designed to cause.
@inlinable
public func isGREASE(_ value: UInt16) -> Bool {
    // 0x0A0A, 0x1A1A, ... 0xFAFA: both bytes equal, both of the form 0x?A.
    (value & 0x0F0F) == 0x0A0A && (value >> 8) == (value & 0x00FF)
}
