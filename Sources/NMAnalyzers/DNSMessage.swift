//
//  DNSMessage.swift
//
//  DNS message parsing.
//
//  The counts in a DNS header are attacker-supplied 16-bit numbers. Nothing
//  here allocates or iterates based on them: every loop is bounded by a
//  constant AND by the bytes actually present, so a header claiming 65,535
//  answers in a 40-byte packet costs one bounds check rather than 65,535
//  iterations.
//

import NMCore

public struct DNSHeader: Sendable {
    public var transactionID: UInt16
    public var rawFlags: UInt16
    public var questionCount: UInt16
    public var answerCount: UInt16
    public var authorityCount: UInt16
    public var additionalCount: UInt16

    public var isResponse: Bool { rawFlags & 0x8000 != 0 }
    public var opcode: UInt8 { UInt8((rawFlags >> 11) & 0x0F) }
    public var isAuthoritative: Bool { rawFlags & 0x0400 != 0 }
    /// The response did not fit in a datagram. A truncated answer is not a
    /// parse failure -- it is the server telling the client to retry over TCP.
    public var isTruncated: Bool { rawFlags & 0x0200 != 0 }
    public var recursionDesired: Bool { rawFlags & 0x0100 != 0 }
    public var recursionAvailable: Bool { rawFlags & 0x0080 != 0 }
    public var responseCode: UInt8 { UInt8(rawFlags & 0x000F) }

    public var responseCodeName: String {
        switch responseCode {
        case 0: return "NOERROR"
        case 1: return "FORMERR"
        case 2: return "SERVFAIL"
        case 3: return "NXDOMAIN"
        case 4: return "NOTIMP"
        case 5: return "REFUSED"
        default: return "RCODE\(responseCode)"
        }
    }
}

public enum DNSRecordType: UInt16, Sendable {
    case a = 1, ns = 2, cname = 5, soa = 6, ptr = 12, mx = 15, txt = 16
    case aaaa = 28, srv = 33, opt = 41, sshfp = 44, https = 65, any = 255

    public var name: String {
        switch self {
        case .a: return "A"
        case .ns: return "NS"
        case .cname: return "CNAME"
        case .soa: return "SOA"
        case .ptr: return "PTR"
        case .mx: return "MX"
        case .txt: return "TXT"
        case .aaaa: return "AAAA"
        case .srv: return "SRV"
        case .opt: return "OPT"
        case .sshfp: return "SSHFP"
        case .https: return "HTTPS"
        case .any: return "ANY"
        }
    }

    public static func name(for raw: UInt16) -> String {
        DNSRecordType(rawValue: raw)?.name ?? "TYPE\(raw)"
    }
}

/// The record payloads we interpret. Everything else is recorded by type and
/// length without being parsed -- there is no reason to expand the attack
/// surface for record types this product does not use.
public enum DNSRecordData: Sendable, Equatable {
    case address(IPAddress)
    case name(String)
    case text([String])
    case opaque(type: UInt16, length: Int)

    /// How this record renders in a log's answers column.
    public var displayValue: String {
        switch self {
        case .address(let a): return a.description
        case .name(let n): return n
        case .text(let parts): return parts.joined(separator: " ")
        case .opaque(let type, let length): return "<\(DNSRecordType.name(for: type)) \(length)B>"
        }
    }
}

public struct DNSResourceRecord: Sendable {
    public var name: String
    public var type: UInt16
    public var recordClass: UInt16
    public var ttl: UInt32
    public var data: DNSRecordData

    public var typeName: String { DNSRecordType.name(for: type) }
}

public struct DNSQuestion: Sendable {
    public var name: String
    public var type: UInt16
    public var questionClass: UInt16

    public var typeName: String { DNSRecordType.name(for: type) }
}

public struct DNSMessage: Sendable {
    public var header: DNSHeader
    public var questions: [DNSQuestion] = []
    public var answers: [DNSResourceRecord] = []
    /// A cap was hit, or a record was malformed and the rest was abandoned.
    /// Recorded so a partial parse is visible rather than looking complete.
    public var parseTruncated = false

    public var primaryQuestion: DNSQuestion? { questions.first }
}

public enum DNSParser {

    public static let headerLength = 12

    /// Parses a DNS message. `reader` must span exactly the message, because
    /// compression offsets are relative to its start.
    public static func parse(_ reader: ByteReader) throws -> DNSMessage {
        guard reader.count >= headerLength else {
            throw ParseError.truncated(needed: headerLength, available: reader.count)
        }

        var r = try reader.reader(at: 0, count: headerLength)
        let header = DNSHeader(transactionID: try r.u16be(),
                               rawFlags: try r.u16be(),
                               questionCount: try r.u16be(),
                               answerCount: try r.u16be(),
                               authorityCount: try r.u16be(),
                               additionalCount: try r.u16be())

        var message = DNSMessage(header: header)
        var offset = headerLength
        var recordBudget = Limits.maxDNSRecords

        // Questions. The count is a wire value, so it bounds nothing on its own
        // -- the budget and the remaining bytes do.
        let questionsToRead = min(Int(header.questionCount), recordBudget)
        for _ in 0..<questionsToRead {
            guard offset < reader.count else { message.parseTruncated = true; break }
            do {
                let name = try DNSName.decode(from: reader, offset: &offset)
                var q = try reader.reader(at: offset, count: reader.count - offset)
                let type = try q.u16be()
                let questionClass = try q.u16be()
                offset += 4
                message.questions.append(DNSQuestion(name: name, type: type,
                                                     questionClass: questionClass))
                recordBudget -= 1
            } catch {
                message.parseTruncated = true
                return message
            }
        }
        if Int(header.questionCount) > questionsToRead { message.parseTruncated = true }

        // Answers. Authority and additional sections are not parsed: nothing in
        // this product reads them, and walking them is attack surface for no
        // gain. Their counts are preserved in the header.
        let answersToRead = min(Int(header.answerCount), recordBudget)
        for _ in 0..<answersToRead {
            guard offset < reader.count else { message.parseTruncated = true; break }
            do {
                let record = try parseResourceRecord(reader, offset: &offset)
                message.answers.append(record)
                recordBudget -= 1
            } catch {
                message.parseTruncated = true
                break
            }
        }
        if Int(header.answerCount) > answersToRead { message.parseTruncated = true }

        return message
    }

    private static func parseResourceRecord(_ message: ByteReader,
                                            offset: inout Int) throws -> DNSResourceRecord {
        let name = try DNSName.decode(from: message, offset: &offset)

        var r = try message.reader(at: offset, count: message.count - offset)
        let type = try r.u16be()
        let recordClass = try r.u16be()
        let rawTTL = try r.u32be()
        let dataLength = Int(try r.u16be())
        offset += 10

        guard dataLength <= message.count - offset else {
            throw ParseError.truncated(needed: dataLength, available: message.count - offset)
        }

        // RFC 2181: a TTL with the top bit set is invalid and must be treated
        // as zero. Without this a hostile TTL of 0xFFFFFFFF reads as 136 years.
        let ttl = rawTTL & 0x8000_0000 != 0 ? 0 : rawTTL

        let dataStart = offset
        offset += dataLength

        let data = try parseRecordData(type: type, message: message,
                                       start: dataStart, length: dataLength)

        return DNSResourceRecord(name: name, type: type, recordClass: recordClass,
                                 ttl: ttl, data: data)
    }

    private static func parseRecordData(type: UInt16, message: ByteReader,
                                        start: Int, length: Int) throws -> DNSRecordData {
        var r = try message.reader(at: start, count: length)

        switch DNSRecordType(rawValue: type) {
        case .a:
            guard length == 4 else { return .opaque(type: type, length: length) }
            return .address(IPAddress(v4NetworkOrder: try r.u32le()))

        case .aaaa:
            guard length == 16 else { return .opaque(type: type, length: length) }
            guard let address = IPAddress(v6: try r.bytes(16)) else {
                return .opaque(type: type, length: length)
            }
            return .address(address)

        case .cname, .ptr, .ns:
            // The name inside the record can itself use compression pointing
            // back into the message, so it is decoded against the whole message
            // rather than against the record's own extent.
            var nameOffset = start
            return .name(try DNSName.decode(from: message, offset: &nameOffset))

        case .txt:
            var parts: [String] = []
            var iterations = 0
            // Each string is length-prefixed; the iteration cap stops a record
            // full of zero-length strings from spinning.
            while r.remaining > 0 && iterations < 64 {
                iterations += 1
                let partLength = Int(try r.u8())
                guard partLength > 0, partLength <= r.remaining else { break }
                let bytes = try r.bytes(partLength)
                parts.append(String(decoding: bytes, as: UTF8.self))
            }
            return .text(parts)

        default:
            return .opaque(type: type, length: length)
        }
    }
}
