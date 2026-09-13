//
//  DNSFixture.swift
//
//  Builds DNS messages, including deliberately malformed ones.
//
//  In the library rather than the test target because the enrichment path needs
//  synthesised lookups too, and because reproducing a crash from a saved packet
//  should not require the test bundle.
//

import NMCore

public struct DNSMessageBuilder {
    public var transactionID: UInt16 = 0x1234
    public var isResponse = false
    public var recursionDesired = true
    public var recursionAvailable = false
    public var responseCode: UInt8 = 0
    public var questions: [(name: String, type: UInt16)] = []
    public var answers: [(name: String, type: UInt16, ttl: UInt32, data: DNSRecordData)] = []
    /// Claim more records in the header than are actually present.
    public var answerCountOverride: UInt16?
    public var questionCountOverride: UInt16?

    public init() {}

    public static func query(_ name: String, type: UInt16 = 1,
                             transactionID: UInt16 = 0x1234) -> DNSMessageBuilder {
        var b = DNSMessageBuilder()
        b.transactionID = transactionID
        b.questions = [(name, type)]
        return b
    }

    public static func response(_ name: String, addresses: [IPAddress],
                                ttl: UInt32 = 300,
                                cnameChain: [String] = [],
                                transactionID: UInt16 = 0x1234) -> DNSMessageBuilder {
        var b = DNSMessageBuilder()
        b.transactionID = transactionID
        b.isResponse = true
        b.recursionAvailable = true
        b.questions = [(name, 1)]

        // owner -> target, following the chain, with the addresses hanging off
        // the final target. This is the shape a real CDN answer takes.
        var owner = name
        for target in cnameChain {
            b.answers.append((owner, 5, ttl, .name(target)))
            owner = target
        }
        for address in addresses {
            b.answers.append((owner, address.isIPv4 ? 1 : 28, ttl, .address(address)))
        }
        return b
    }

    public func build() -> [UInt8] {
        var out = [UInt8]()
        var flags: UInt16 = 0
        if isResponse { flags |= 0x8000 }
        if recursionDesired { flags |= 0x0100 }
        if recursionAvailable { flags |= 0x0080 }
        flags |= UInt16(responseCode & 0x0F)

        append16(&out, transactionID)
        append16(&out, flags)
        append16(&out, questionCountOverride ?? UInt16(questions.count))
        append16(&out, answerCountOverride ?? UInt16(answers.count))
        append16(&out, 0)                                    // authority
        append16(&out, 0)                                    // additional

        for q in questions {
            out.append(contentsOf: encodeName(q.name))
            append16(&out, q.type)
            append16(&out, 1)                                // IN
        }

        for a in answers {
            out.append(contentsOf: encodeName(a.name))
            append16(&out, a.type)
            append16(&out, 1)
            append32(&out, a.ttl)
            let payload = encodeData(a.data)
            append16(&out, UInt16(payload.count))
            out.append(contentsOf: payload)
        }
        return out
    }

    /// Uncompressed wire format: a length byte per label, then a root label.
    public static func encodeName(_ name: String) -> [UInt8] {
        var out = [UInt8]()
        if name != "." {
            for label in name.split(separator: ".") {
                let bytes = Array(label.utf8).prefix(63)
                out.append(UInt8(bytes.count))
                out.append(contentsOf: bytes)
            }
        }
        out.append(0)
        return out
    }

    private func encodeName(_ name: String) -> [UInt8] { Self.encodeName(name) }

    private func encodeData(_ data: DNSRecordData) -> [UInt8] {
        switch data {
        case .address(let a): return a.storageBytes
        case .name(let n): return Self.encodeName(n)
        case .text(let parts):
            var out = [UInt8]()
            for part in parts {
                let bytes = Array(part.utf8).prefix(255)
                out.append(UInt8(bytes.count))
                out.append(contentsOf: bytes)
            }
            return out
        case .opaque(_, let length): return [UInt8](repeating: 0, count: length)
        }
    }

    private func append16(_ out: inout [UInt8], _ v: UInt16) {
        out.append(UInt8(v >> 8)); out.append(UInt8(v & 0xFF))
    }
    private func append32(_ out: inout [UInt8], _ v: UInt32) {
        for shift in [24, 16, 8, 0] { out.append(UInt8((v >> UInt32(shift)) & 0xFF)) }
    }
}
