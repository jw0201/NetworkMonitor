//
//  TLSHandshake.swift
//
//  ClientHello and ServerHello.
//
//  What is obtainable here, and what is not, is worth stating plainly because
//  the UI has to be built around it:
//
//    * The ClientHello is always in the clear. SNI, ALPN, cipher suites,
//      extensions, supported versions -- all readable, always.
//    * The ServerHello is in the clear, but under TLS 1.3 it carries almost
//      nothing: the selected version hides in an extension, and the server's
//      ALPN moved into EncryptedExtensions, which is encrypted.
//    * Certificates are plaintext under TLS 1.2 and ENCRYPTED under TLS 1.3.
//      Since essentially all modern traffic is 1.3, the certificate fields are
//      usually unavailable rather than merely absent, and the difference
//      matters: "encrypted" is a fact, "unknown" is a shrug.
//    * With Encrypted Client Hello, the visible SNI is the OUTER name and is
//      not the real destination at all.
//

import NMCore

public struct TLSExtensionIDs {
    public static let serverName: UInt16 = 0
    public static let supportedGroups: UInt16 = 10
    public static let ecPointFormats: UInt16 = 11
    public static let signatureAlgorithms: UInt16 = 13
    public static let alpn: UInt16 = 16
    public static let supportedVersions: UInt16 = 43
    public static let keyShare: UInt16 = 51
    /// Encrypted Client Hello. Its presence means the SNI in this message is
    /// the public outer name, not where the client is really going.
    public static let encryptedClientHello: UInt16 = 0xFE0D
}

public struct TLSClientHello: Sendable {
    public var legacyVersion: UInt16 = 0
    /// Highest version offered, from supported_versions when present.
    public var effectiveVersion: UInt16 = 0
    public var cipherSuites: [UInt16] = []
    public var extensions: [UInt16] = []
    public var supportedGroups: [UInt16] = []
    public var ecPointFormats: [UInt8] = []
    public var signatureAlgorithms: [UInt16] = []
    public var alpnProtocols: [String] = []
    public var serverName: String?
    /// The ClientHello carried an ECH extension, so `serverName` is the outer
    /// name. Presenting it as the destination would be confidently wrong.
    public var hasEncryptedClientHello = false
    public var sessionIDLength = 0

    /// GREASE-stripped views, which is what fingerprints are built from.
    public var realCipherSuites: [UInt16] { cipherSuites.filter { !isGREASE($0) } }
    public var realExtensions: [UInt16] { extensions.filter { !isGREASE($0) } }
    public var realSupportedGroups: [UInt16] { supportedGroups.filter { !isGREASE($0) } }
    public var realSignatureAlgorithms: [UInt16] { signatureAlgorithms.filter { !isGREASE($0) } }
}

public struct TLSServerHello: Sendable {
    public var legacyVersion: UInt16 = 0
    /// The version actually selected. Under TLS 1.3 this comes from the
    /// supported_versions extension, not from the legacy field.
    public var effectiveVersion: UInt16 = 0
    public var cipherSuite: UInt16 = 0
    public var extensions: [UInt16] = []
    /// The group the server chose, from its key_share.
    public var selectedGroup: UInt16?
    /// Present only under TLS 1.2 and below. Under 1.3 the server's ALPN is
    /// inside EncryptedExtensions and is simply not visible.
    public var alpnProtocol: String?
    public var sessionIDLength = 0

    public var realExtensions: [UInt16] { extensions.filter { !isGREASE($0) } }
    public var isTLS13: Bool { effectiveVersion == 0x0304 }
}

public enum TLSHandshakeParser {

    /// Parses a ClientHello body (the bytes after the 4-byte message header).
    public static func parseClientHello(_ reader: ByteReader) throws -> TLSClientHello {
        var r = reader
        var hello = TLSClientHello()

        hello.legacyVersion = try r.u16be()
        hello.effectiveVersion = hello.legacyVersion
        try r.skip(32)                                        // random

        let sessionIDLength = Int(try r.u8())
        hello.sessionIDLength = sessionIDLength
        try r.skip(sessionIDLength)

        let cipherBytes = Int(try r.u16be())
        guard cipherBytes % 2 == 0 else { throw ParseError.malformed("odd cipher list") }
        var ciphers = try r.sub(cipherBytes)
        var cipherCount = 0
        while ciphers.remaining >= 2 && cipherCount < Limits.maxTLSCipherSuites {
            hello.cipherSuites.append(try ciphers.u16be())
            cipherCount += 1
        }

        let compressionLength = Int(try r.u8())
        try r.skip(compressionLength)

        // Extensions are optional in the wire format, though absent only in
        // very old clients.
        guard r.remaining >= 2 else { return hello }
        let extensionsLength = Int(try r.u16be())
        var extensions = try r.sub(min(extensionsLength, r.remaining))
        try parseExtensions(&extensions, into: &hello)

        return hello
    }

    /// Walks the extension list.
    ///
    /// A malformed INDIVIDUAL extension is skipped rather than failing the
    /// whole ClientHello. That matters for a passive analyzer: the extension
    /// list is attacker-controlled, and discarding the entire message because
    /// one entry was odd would throw away the SNI and the fingerprint -- which
    /// is precisely what an attacker wanting to stay unlogged would arrange.
    /// The extension's TYPE is still recorded, so the fingerprint still
    /// reflects that it was offered.
    private static func parseExtensions(_ r: inout ByteReader,
                                        into hello: inout TLSClientHello) throws {
        var count = 0
        while r.remaining >= 4 && count < Limits.maxTLSExtensions {
            count += 1
            let type = try r.u16be()
            let length = Int(try r.u16be())
            // A length past the end of the list is unrecoverable: there is no
            // way to find where the next extension starts.
            guard length <= r.remaining else { return }
            let body = try r.sub(length)
            hello.extensions.append(type)
            parseExtensionBody(type, body, into: &hello)
        }
    }

    private static func parseExtensionBody(_ type: UInt16, _ body: ByteReader,
                                           into hello: inout TLSClientHello) {
        var body = body
        switch type {
        case TLSExtensionIDs.serverName:
            if let name = try? parseServerName(&body) { hello.serverName = name }

        case TLSExtensionIDs.supportedGroups:
            guard let listLength = try? body.u16be(),
                  var list = try? body.sub(min(Int(listLength), body.remaining)) else { return }
            while list.remaining >= 2 && hello.supportedGroups.count < 128 {
                guard let value = try? list.u16be() else { return }
                hello.supportedGroups.append(value)
            }

        case TLSExtensionIDs.ecPointFormats:
            guard let listLength = try? body.u8(),
                  var list = try? body.sub(min(Int(listLength), body.remaining)) else { return }
            while list.remaining >= 1 && hello.ecPointFormats.count < 16 {
                guard let value = try? list.u8() else { return }
                hello.ecPointFormats.append(value)
            }

        case TLSExtensionIDs.signatureAlgorithms:
            guard let listLength = try? body.u16be(),
                  var list = try? body.sub(min(Int(listLength), body.remaining)) else { return }
            while list.remaining >= 2 && hello.signatureAlgorithms.count < 64 {
                guard let value = try? list.u16be() else { return }
                hello.signatureAlgorithms.append(value)
            }

        case TLSExtensionIDs.alpn:
            guard let listLength = try? body.u16be(),
                  var list = try? body.sub(min(Int(listLength), body.remaining)) else { return }
            while list.remaining >= 1 && hello.alpnProtocols.count < 16 {
                guard let nameLength = try? list.u8(), nameLength > 0,
                      Int(nameLength) <= list.remaining,
                      let bytes = try? list.bytes(Int(nameLength)) else { return }
                hello.alpnProtocols.append(String(decoding: bytes, as: UTF8.self))
            }

        case TLSExtensionIDs.supportedVersions:
            // The highest non-GREASE version offered is the one that matters;
            // the legacy field says 1.2 even for a 1.3 client.
            guard let listLength = try? body.u8(),
                  var list = try? body.sub(min(Int(listLength), body.remaining)) else { return }
            var highest: UInt16 = 0
            while list.remaining >= 2 {
                guard let version = try? list.u16be() else { break }
                if !isGREASE(version) && version > highest { highest = version }
            }
            if highest != 0 { hello.effectiveVersion = highest }

        case TLSExtensionIDs.encryptedClientHello:
            hello.hasEncryptedClientHello = true

        default:
            break
        }
    }

    private static func parseServerName(_ r: inout ByteReader) throws -> String {
        let listLength = Int(try r.u16be())
        var list = try r.sub(min(listLength, r.remaining))
        var entries = 0
        while list.remaining >= 3 && entries < 8 {
            entries += 1
            let nameType = try list.u8()
            let nameLength = Int(try list.u16be())
            guard nameLength <= list.remaining else { break }
            let bytes = try list.bytes(nameLength)
            // Type 0 is host_name; nothing else has ever been defined.
            if nameType == 0 { return sanitizeHostname(bytes) }
        }
        throw ParseError.malformed("no host_name in SNI")
    }

    /// SNI is attacker-controlled text that reaches the UI, the database and
    /// the hostname cache. A name containing control characters or a newline
    /// could corrupt a log line or impersonate another entry.
    private static func sanitizeHostname(_ bytes: UnsafeRawBufferPointer) -> String {
        var out = ""
        out.reserveCapacity(bytes.count)
        var count = 0
        for byte in bytes {
            if count >= Limits.maxDNSNameLength { break }
            count += 1
            switch byte {
            case 0x41...0x5A: out.append(Character(UnicodeScalar(byte + 0x20)))  // fold to lower
            case 0x61...0x7A, 0x30...0x39, UInt8(ascii: "-"), UInt8(ascii: "."),
                 UInt8(ascii: "_"), UInt8(ascii: "*"):
                out.append(Character(UnicodeScalar(byte)))
            default:
                out += "?"
            }
        }
        return out
    }

    /// Parses a ServerHello body.
    public static func parseServerHello(_ reader: ByteReader) throws -> TLSServerHello {
        var r = reader
        var hello = TLSServerHello()

        hello.legacyVersion = try r.u16be()
        hello.effectiveVersion = hello.legacyVersion
        try r.skip(32)                                        // random

        let sessionIDLength = Int(try r.u8())
        hello.sessionIDLength = sessionIDLength
        try r.skip(sessionIDLength)

        hello.cipherSuite = try r.u16be()
        try r.skip(1)                                         // compression method

        guard r.remaining >= 2 else { return hello }
        let extensionsLength = Int(try r.u16be())
        var extensions = try r.sub(min(extensionsLength, r.remaining))

        var count = 0
        while extensions.remaining >= 4 && count < Limits.maxTLSExtensions {
            count += 1
            let type = try extensions.u16be()
            let length = Int(try extensions.u16be())
            guard length <= extensions.remaining else { break }
            var body = try extensions.sub(length)
            hello.extensions.append(type)

            switch type {
            case TLSExtensionIDs.supportedVersions:
                // The server sends a single version here, not a list.
                if let version = try? body.u16be() { hello.effectiveVersion = version }

            case TLSExtensionIDs.keyShare:
                if let group = try? body.u16be() { hello.selectedGroup = group }

            case TLSExtensionIDs.alpn:
                let listLength = Int(try body.u16be())
                var list = try body.sub(min(listLength, body.remaining))
                if let nameLength = try? list.u8(), nameLength > 0,
                   Int(nameLength) <= list.remaining,
                   let bytes = try? list.bytes(Int(nameLength)) {
                    hello.alpnProtocol = String(decoding: bytes, as: UTF8.self)
                }

            default:
                break
            }
        }
        return hello
    }
}

/// Human-readable TLS version names.
public func tlsVersionName(_ version: UInt16) -> String {
    switch version {
    case 0x0304: return "TLS 1.3"
    case 0x0303: return "TLS 1.2"
    case 0x0302: return "TLS 1.1"
    case 0x0301: return "TLS 1.0"
    case 0x0300: return "SSL 3.0"
    case 0xFEFD: return "DTLS 1.2"
    case 0xFEFC: return "DTLS 1.3"
    default: return "0x" + String(version, radix: 16)
    }
}
