//
//  TLSFingerprint.swift
//
//  JA3 and JA4.
//
//  JA4 is the primary. It sorts the cipher and extension lists before hashing,
//  which makes it immune to the extension shuffling Chrome and BoringSSL do
//  deliberately -- shuffling that has made JA3 unstable, and largely useless,
//  for modern browsers. JA3 is computed anyway because every existing threat
//  intelligence feed is keyed on it, and once the ClientHello is parsed it
//  costs one MD5 over a string that is already built.
//
//  The unhashed JA4_r string is stored alongside the hash. It is free, and
//  without it a fingerprint that disagrees with another tool's is undebuggable:
//  two hex digests that differ tell you nothing about which field diverged.
//

import CryptoKit
import Foundation
import NMCore

public struct TLSFingerprints: Sendable {
    public var ja4: String?
    /// The JA4 string before hashing. Kept for debugging mismatches.
    public var ja4Raw: String?
    public var ja3: String?
    public var ja3Raw: String?
    public var ja4s: String?
    public var ja3s: String?
}

public enum TLSFingerprinter {

    public enum Transport: Character, Sendable {
        case tcp = "t"
        case quic = "q"
        case dtls = "d"
    }

    // MARK: - JA4

    /// JA4_a + "_" + JA4_b + "_" + JA4_c
    public static func ja4(_ hello: TLSClientHello,
                           transport: Transport = .tcp) -> (hash: String, raw: String) {
        let a = ja4Part1(hello, transport: transport)

        let ciphers = hello.realCipherSuites.map(hex4).sorted()
        let cipherString = ciphers.joined(separator: ",")
        let b = ciphers.isEmpty ? String(repeating: "0", count: 12)
                                : truncatedSHA256(cipherString)

        // SNI and ALPN are excluded here specifically: they already appear in
        // JA4_a, and including them again would make the fingerprint vary with
        // the destination rather than with the client.
        let extensions = hello.realExtensions
            .filter { $0 != TLSExtensionIDs.serverName && $0 != TLSExtensionIDs.alpn }
            .map(hex4)
            .sorted()
        let signatureAlgorithms = hello.realSignatureAlgorithms.map(hex4)

        var cString = extensions.joined(separator: ",")
        // Signature algorithms keep their ORIGINAL order -- they are ordered by
        // preference and that ordering is itself a client characteristic.
        if !signatureAlgorithms.isEmpty {
            cString += "_" + signatureAlgorithms.joined(separator: ",")
        }
        let c = extensions.isEmpty ? String(repeating: "0", count: 12)
                                   : truncatedSHA256(cString)

        let raw = "\(a)_\(cipherString)_\(cString)"
        return ("\(a)_\(b)_\(c)", raw)
    }

    private static func ja4Part1(_ hello: TLSClientHello, transport: Transport) -> String {
        var out = String(transport.rawValue)
        out += versionCode(hello.effectiveVersion)
        out += hello.serverName != nil ? "d" : "i"
        out += twoDigits(hello.realCipherSuites.count)
        // SNI and ALPN ARE counted here, even though they are excluded from
        // JA4_c. The count and the hash serve different purposes.
        out += twoDigits(hello.realExtensions.count)
        out += alpnCode(hello.alpnProtocols.first)
        return out
    }

    /// JA4S, the server's side.
    public static func ja4s(_ hello: TLSServerHello,
                            transport: Transport = .tcp) -> String {
        var a = String(transport.rawValue)
        a += versionCode(hello.effectiveVersion)
        a += twoDigits(hello.realExtensions.count)
        // Under TLS 1.3 the server's ALPN lives in EncryptedExtensions and is
        // not visible, so "00" is a fact rather than a placeholder.
        a += alpnCode(hello.alpnProtocol)

        let b = hex4(hello.cipherSuite)
        // Server extensions keep their original order; there are few of them
        // and the ordering is stable per implementation.
        let extensions = hello.realExtensions.map(hex4).joined(separator: ",")
        let c = hello.realExtensions.isEmpty ? String(repeating: "0", count: 12)
                                             : truncatedSHA256(extensions)
        return "\(a)_\(b)_\(c)"
    }

    // MARK: - JA3

    /// version,ciphers,extensions,curves,pointFormats -- decimal, dash-joined,
    /// in WIRE ORDER, GREASE removed. Absent fields still contribute a comma.
    public static func ja3(_ hello: TLSClientHello) -> (hash: String, raw: String) {
        let fields = [
            String(hello.legacyVersion),
            hello.realCipherSuites.map(String.init).joined(separator: "-"),
            hello.realExtensions.map(String.init).joined(separator: "-"),
            hello.realSupportedGroups.map(String.init).joined(separator: "-"),
            hello.ecPointFormats.map(String.init).joined(separator: "-"),
        ]
        let raw = fields.joined(separator: ",")
        return (md5Hex(raw), raw)
    }

    public static func ja3s(_ hello: TLSServerHello) -> String {
        let raw = [
            String(hello.legacyVersion),
            String(hello.cipherSuite),
            hello.realExtensions.map(String.init).joined(separator: "-"),
        ].joined(separator: ",")
        return md5Hex(raw)
    }

    // MARK: - Encoding helpers

    private static func versionCode(_ version: UInt16) -> String {
        switch version {
        case 0x0304: return "13"
        case 0x0303: return "12"
        case 0x0302: return "11"
        case 0x0301: return "10"
        case 0x0300: return "s3"
        case 0x0002: return "s2"
        case 0xFEFF: return "d1"
        case 0xFEFD: return "d2"
        case 0xFEFC: return "d3"
        default: return "00"
        }
    }

    /// First and last character of the first ALPN value: "h2" stays "h2",
    /// "http/1.1" becomes "h1", a single character doubles, and a
    /// non-alphanumeric byte is rendered as its two hex digits.
    private static func alpnCode(_ alpn: String?) -> String {
        guard let alpn, !alpn.isEmpty else { return "00" }
        let bytes = Array(alpn.utf8)
        let first = bytes[0]
        let last = bytes[bytes.count - 1]

        func render(_ byte: UInt8) -> Character? {
            let isAlphanumeric = (byte >= 0x30 && byte <= 0x39)
                || (byte >= 0x41 && byte <= 0x5A) || (byte >= 0x61 && byte <= 0x7A)
            return isAlphanumeric ? Character(UnicodeScalar(byte)) : nil
        }

        guard let f = render(first), let l = render(last) else {
            return hex2(first) + hex2(last)
        }
        return String([f, l])
    }

    private static func twoDigits(_ n: Int) -> String {
        let capped = min(n, 99)
        return capped < 10 ? "0\(capped)" : "\(capped)"
    }

    private static func hex4(_ value: UInt16) -> String {
        var s = String(value, radix: 16)
        while s.count < 4 { s = "0" + s }
        return s
    }

    private static func hex2(_ value: UInt8) -> String {
        var s = String(value, radix: 16)
        while s.count < 2 { s = "0" + s }
        return s
    }

    private static func truncatedSHA256(_ input: String) -> String {
        let digest = SHA256.hash(data: Data(input.utf8))
        return digest.map { hex2($0) }.joined().prefix(12).lowercased()
    }

    private static func md5Hex(_ input: String) -> String {
        let digest = Insecure.MD5.hash(data: Data(input.utf8))
        return digest.map { hex2($0) }.joined().lowercased()
    }
}
