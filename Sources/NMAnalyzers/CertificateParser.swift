//
//  CertificateParser.swift
//
//  X.509 handling, delegated to Security.framework.
//
//  This file deliberately contains no DER parsing. Hand-writing an X.509 parser
//  inside a root process that consumes attacker-supplied certificates would add
//  an entire class of memory-safety bugs for no benefit -- SecCertificate does
//  the job, is maintained by Apple, and runs the same code the rest of the
//  system trusts.
//
//  The only thing computed directly is the SHA-256 fingerprint, which is a hash
//  over the DER bytes and needs no parsing at all.
//

import CryptoKit
import Foundation
import NMCore
import Security

public struct ParsedCertificate: Sendable {
    public var subject: String?
    public var issuer: String?
    public var notBefore: Timestamp?
    public var notAfter: Timestamp?
    /// Lowercase hex SHA-256 of the DER encoding.
    public var fingerprint: String
    public var subjectAlternativeNames: [String] = []
}

public enum CertificateParser {

    /// Parses a DER certificate. Returns nil when Security.framework rejects
    /// it, which is the correct answer for anything malformed.
    public static func parse(der: [UInt8]) -> ParsedCertificate? {
        let data = Data(der) as CFData
        guard let certificate = SecCertificateCreateWithData(nil, data) else { return nil }

        var parsed = ParsedCertificate(fingerprint: sha256Hex(der))

        if let summary = SecCertificateCopySubjectSummary(certificate) {
            parsed.subject = summary as String
        }

        // SecCertificateCopyValues gives the structured fields. It is a
        // dictionary of dictionaries; the shape is stable but verbose.
        var error: Unmanaged<CFError>?
        let keys = [kSecOIDX509V1SubjectName, kSecOIDX509V1IssuerName,
                    kSecOIDX509V1ValidityNotBefore, kSecOIDX509V1ValidityNotAfter,
                    kSecOIDSubjectAltName] as CFArray
        guard let values = SecCertificateCopyValues(certificate, keys, &error)
                as? [CFString: Any] else {
            return parsed
        }

        parsed.issuer = distinguishedName(values[kSecOIDX509V1IssuerName])
        if parsed.subject == nil {
            parsed.subject = distinguishedName(values[kSecOIDX509V1SubjectName])
        }
        parsed.notBefore = validityDate(values[kSecOIDX509V1ValidityNotBefore])
        parsed.notAfter = validityDate(values[kSecOIDX509V1ValidityNotAfter])

        return parsed
    }

    /// Flattens a distinguished name into the conventional "CN=..., O=..." form.
    private static func distinguishedName(_ value: Any?) -> String? {
        guard let entry = value as? [CFString: Any],
              let parts = entry[kSecPropertyKeyValue] as? [[CFString: Any]] else { return nil }

        var components: [String] = []
        for part in parts {
            guard let label = part[kSecPropertyKeyLabel] as? String,
                  let text = part[kSecPropertyKeyValue] as? String else { continue }
            components.append("\(shortLabel(label))=\(text)")
        }
        return components.isEmpty ? nil : components.joined(separator: ", ")
    }

    private static func shortLabel(_ oid: String) -> String {
        switch oid {
        case "2.5.4.3": return "CN"
        case "2.5.4.6": return "C"
        case "2.5.4.7": return "L"
        case "2.5.4.8": return "ST"
        case "2.5.4.10": return "O"
        case "2.5.4.11": return "OU"
        default: return oid
        }
    }

    private static func validityDate(_ value: Any?) -> Timestamp? {
        guard let entry = value as? [CFString: Any],
              let number = entry[kSecPropertyKeyValue] as? NSNumber else { return nil }
        // Security reports these as seconds since the CF reference date.
        let seconds = number.doubleValue + Date.timeIntervalBetween1970AndReferenceDate
        return Timestamp(seconds * 1_000_000)
    }

    public static func sha256Hex(_ bytes: [UInt8]) -> String {
        SHA256.hash(data: Data(bytes)).map { byte in
            var s = String(byte, radix: 16)
            if s.count < 2 { s = "0" + s }
            return s
        }.joined()
    }

    /// Splits a TLS Certificate handshake message into its DER entries.
    ///
    /// The layout differs between versions: TLS 1.3 prefixes a context string
    /// and appends per-certificate extensions. Both are handled, because a
    /// TLS 1.2 server is exactly the case where certificates ARE visible and
    /// therefore worth parsing.
    public static func certificates(in message: ByteReader,
                                    isTLS13: Bool) -> [[UInt8]] {
        var r = message
        var out: [[UInt8]] = []

        if isTLS13 {
            guard let contextLength = try? r.u8() else { return [] }
            guard (try? r.skip(Int(contextLength))) != nil else { return [] }
        }

        guard let listLength = try? r.u24be(),
              var list = try? r.sub(min(Int(listLength), r.remaining)) else { return [] }

        while list.remaining >= 3 && out.count < Limits.maxTLSCertificates {
            guard let length = try? list.u24be(), length > 0,
                  Int(length) <= list.remaining,
                  let der = try? list.bytes(Int(length)) else { break }
            out.append(Array(der))

            if isTLS13 {
                // Per-certificate extensions follow each entry in 1.3.
                guard let extensionsLength = try? list.u16be(),
                      (try? list.skip(min(Int(extensionsLength), list.remaining))) != nil
                else { break }
            }
        }
        return out
    }
}
