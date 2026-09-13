//
//  TLSFixture.swift
//
//  Builds TLS handshake messages, wrapped in records.
//
//  In the library for the same reason as the other fixtures: the analyzers must
//  be exercisable with no capture, no root and no network.
//

import NMCore

public struct TLSClientHelloBuilder {
    public var legacyVersion: UInt16 = 0x0303
    public var sessionIDLength = 32
    public var cipherSuites: [UInt16] = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F]
    /// Extensions in wire order. GREASE values belong here too, since stripping
    /// them is part of what is under test.
    public var extensions: [(type: UInt16, body: [UInt8])] = []
    public var serverName: String?
    public var alpn: [String] = ["h2", "http/1.1"]
    public var supportedVersions: [UInt16] = [0x0304, 0x0303]
    public var supportedGroups: [UInt16] = [0x001D, 0x0017, 0x0018]
    public var ecPointFormats: [UInt8] = [0]
    public var signatureAlgorithms: [UInt16] = [0x0403, 0x0804, 0x0401]
    public var includeGREASE = true
    public var encryptedClientHello = false
    /// Wrap the message in this many TLS records, to exercise deframing.
    public var recordSplits = 1

    public init() {}

    /// The extension list actually emitted, in wire order.
    private func buildExtensions() -> [(UInt16, [UInt8])] {
        var out: [(UInt16, [UInt8])] = []
        if includeGREASE { out.append((0x1A1A, [])) }
        if let serverName {
            var body = [UInt8]()
            let name = Array(serverName.utf8)
            append16(&body, UInt16(name.count + 3))
            body.append(0)                                   // host_name
            append16(&body, UInt16(name.count))
            body.append(contentsOf: name)
            out.append((TLSExtensionIDs.serverName, body))
        }
        if !supportedGroups.isEmpty {
            var body = [UInt8]()
            var list = [UInt8]()
            if includeGREASE { append16(&list, 0x2A2A) }
            for g in supportedGroups { append16(&list, g) }
            append16(&body, UInt16(list.count))
            body.append(contentsOf: list)
            out.append((TLSExtensionIDs.supportedGroups, body))
        }
        if !ecPointFormats.isEmpty {
            var body: [UInt8] = [UInt8(ecPointFormats.count)]
            body.append(contentsOf: ecPointFormats)
            out.append((TLSExtensionIDs.ecPointFormats, body))
        }
        if !signatureAlgorithms.isEmpty {
            var body = [UInt8]()
            var list = [UInt8]()
            for s in signatureAlgorithms { append16(&list, s) }
            append16(&body, UInt16(list.count))
            body.append(contentsOf: list)
            out.append((TLSExtensionIDs.signatureAlgorithms, body))
        }
        if !alpn.isEmpty {
            var list = [UInt8]()
            for protocolName in alpn {
                let bytes = Array(protocolName.utf8)
                list.append(UInt8(bytes.count))
                list.append(contentsOf: bytes)
            }
            var body = [UInt8]()
            append16(&body, UInt16(list.count))
            body.append(contentsOf: list)
            out.append((TLSExtensionIDs.alpn, body))
        }
        if !supportedVersions.isEmpty {
            var list = [UInt8]()
            if includeGREASE { append16(&list, 0x3A3A) }
            for v in supportedVersions { append16(&list, v) }
            var body: [UInt8] = [UInt8(list.count)]
            body.append(contentsOf: list)
            out.append((TLSExtensionIDs.supportedVersions, body))
        }
        if encryptedClientHello {
            out.append((TLSExtensionIDs.encryptedClientHello, [0x00, 0x01]))
        }
        out.append(contentsOf: extensions.map { ($0.type, $0.body) })
        return out
    }

    /// The handshake message body, without the 4-byte header.
    public func buildBody() -> [UInt8] {
        var out = [UInt8]()
        append16(&out, legacyVersion)
        out.append(contentsOf: [UInt8](repeating: 0x5A, count: 32))     // random
        out.append(UInt8(sessionIDLength))
        out.append(contentsOf: [UInt8](repeating: 0x11, count: sessionIDLength))

        var ciphers = [UInt8]()
        if includeGREASE { append16(&ciphers, 0x0A0A) }
        for suite in cipherSuites { append16(&ciphers, suite) }
        append16(&out, UInt16(ciphers.count))
        out.append(contentsOf: ciphers)

        out.append(1)                                        // compression methods
        out.append(0)                                        // null

        var extensionBytes = [UInt8]()
        for (type, body) in buildExtensions() {
            append16(&extensionBytes, type)
            append16(&extensionBytes, UInt16(body.count))
            extensionBytes.append(contentsOf: body)
        }
        append16(&out, UInt16(extensionBytes.count))
        out.append(contentsOf: extensionBytes)
        return out
    }

    /// The full handshake message wrapped in one or more TLS records.
    public func build() -> [UInt8] {
        let body = buildBody()
        var message: [UInt8] = [1]                           // client_hello
        append24(&message, UInt32(body.count))
        message.append(contentsOf: body)
        return TLSFixtureSupport.wrapInRecords(message, splits: recordSplits)
    }

    private func append16(_ out: inout [UInt8], _ v: UInt16) {
        out.append(UInt8(v >> 8)); out.append(UInt8(v & 0xFF))
    }
    private func append24(_ out: inout [UInt8], _ v: UInt32) {
        out.append(UInt8((v >> 16) & 0xFF)); out.append(UInt8((v >> 8) & 0xFF))
        out.append(UInt8(v & 0xFF))
    }
}

public struct TLSServerHelloBuilder {
    public var legacyVersion: UInt16 = 0x0303
    public var selectedVersion: UInt16? = 0x0304
    public var cipherSuite: UInt16 = 0x1301
    public var selectedGroup: UInt16? = 0x001D
    public var alpn: String?
    public var sessionIDLength = 32

    public init() {}

    public func build() -> [UInt8] {
        var body = [UInt8]()
        append16(&body, legacyVersion)
        body.append(contentsOf: [UInt8](repeating: 0xA5, count: 32))
        body.append(UInt8(sessionIDLength))
        body.append(contentsOf: [UInt8](repeating: 0x22, count: sessionIDLength))
        append16(&body, cipherSuite)
        body.append(0)                                       // compression

        var extensionBytes = [UInt8]()
        if let selectedVersion {
            append16(&extensionBytes, TLSExtensionIDs.supportedVersions)
            append16(&extensionBytes, 2)
            append16(&extensionBytes, selectedVersion)
        }
        if let selectedGroup {
            append16(&extensionBytes, TLSExtensionIDs.keyShare)
            append16(&extensionBytes, 4)
            append16(&extensionBytes, selectedGroup)
            append16(&extensionBytes, 0)
        }
        if let alpn {
            let bytes = Array(alpn.utf8)
            var body2 = [UInt8]()
            append16(&body2, UInt16(bytes.count + 1))
            body2.append(UInt8(bytes.count))
            body2.append(contentsOf: bytes)
            append16(&extensionBytes, TLSExtensionIDs.alpn)
            append16(&extensionBytes, UInt16(body2.count))
            extensionBytes.append(contentsOf: body2)
        }
        append16(&body, UInt16(extensionBytes.count))
        body.append(contentsOf: extensionBytes)

        var message: [UInt8] = [2]                           // server_hello
        message.append(UInt8((body.count >> 16) & 0xFF))
        message.append(UInt8((body.count >> 8) & 0xFF))
        message.append(UInt8(body.count & 0xFF))
        message.append(contentsOf: body)
        return TLSFixtureSupport.wrapInRecords(message, splits: 1)
    }

    private func append16(_ out: inout [UInt8], _ v: UInt16) {
        out.append(UInt8(v >> 8)); out.append(UInt8(v & 0xFF))
    }
}

public enum TLSFixtureSupport {
    /// Wraps a handshake message in `splits` TLS records, so deframing across
    /// record boundaries is exercised -- a real ClientHello often arrives that
    /// way, and a parser that assumes one record per message fails on it.
    public static func wrapInRecords(_ message: [UInt8], splits: Int) -> [UInt8] {
        let parts = max(1, splits)
        let chunkSize = max(1, (message.count + parts - 1) / parts)
        var out = [UInt8]()
        var index = 0
        while index < message.count {
            let end = min(index + chunkSize, message.count)
            let chunk = Array(message[index..<end])
            out.append(22)                                   // handshake
            out.append(0x03); out.append(0x01)               // legacy record version
            out.append(UInt8(chunk.count >> 8))
            out.append(UInt8(chunk.count & 0xFF))
            out.append(contentsOf: chunk)
            index = end
        }
        return out
    }
}
