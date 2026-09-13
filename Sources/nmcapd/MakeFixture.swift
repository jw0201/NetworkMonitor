//
//  MakeFixture.swift
//
//  Writes a synthetic PKTAP savefile.
//
//  Produced so `--replay` can be exercised end to end with no privileges at
//  all, and so CI has a stable input. It is NOT a substitute for verifying the
//  decoder against a real capture -- a fixture built by our own encoder can only
//  prove the decoder is self-consistent, never that it matches the kernel.
//  `Tools/verify-pktap.sh` is what settles that, and it needs root once.
//

import Foundation
import NMAnalyzers
import NMCapture
import NMCore
import NMFlow

func makeFixture(path: String, packets: Int) -> Int32 {
    // A believable mix: a plain app, delegated traffic, loopback, and a short
    // legacy header -- the shapes the decoder has to get right.
    let recipes: [(comm: String, pid: Int32, ecomm: String, epid: Int32,
                   iface: String, delegated: Bool, dlt: UInt32, pre: UInt32,
                   ifType: UInt16, hdrLen: UInt32)] = [
        ("Safari",        842, "Safari",        842, "en0",  false, 1,  14, 0x06, 156),
        ("nsurlsessiond", 130, "Mail",          904, "en0",  true,  1,  14, 0x06, 156),
        ("mDNSResponder",  77, "mDNSResponder",  77, "en0",  false, 1,  14, 0x06, 156),
        ("nc",           5120, "nc",           5120, "lo0",  false, 0,   4, 0x18, 156),
        ("curl",         6001, "curl",         6001, "utun0", false, 12,  0, 0x83, 156),
        ("legacyd",      4004, "legacyd",      4004, "en0",  false, 1,  14, 0x06, 108),
    ]

    // Names the synthetic traffic resolves, so a fixture exercises the whole
    // chain -- query, answer, then a connection to the address that was
    // returned -- rather than just the packet decoder.
    let resolvedHosts: [(name: String, address: IPAddress, process: String, pid: Int32)] = [
        ("www.apple.com", IPAddress("17.253.144.10")!, "Safari", 842),
        ("slack.com", IPAddress("99.86.4.17")!, "Slack", 1204),
        ("imap.mail.me.com", IPAddress("17.42.251.30")!, "Mail", 904),
    ]

    do {
        let writer = try PcapFileWriter(path: path, snaplen: 2048)
        var timestamp = Double(Int(Date().timeIntervalSince1970)) - Double(packets) * 0.01

        // A DNS lookup and its answer for each host, from the process that
        // wants it, followed later by that process connecting to the address.
        for (index, host) in resolvedHosts.enumerated() {
            let clientPort = UInt16(54000 + index)
            let query = DNSMessageBuilder.query(host.name,
                                                transactionID: UInt16(0x1000 + index)).build()
            let answer = DNSMessageBuilder.response(host.name, addresses: [host.address],
                                                    ttl: 300,
                                                    transactionID: UInt16(0x1000 + index)).build()

            try writeDNS(writer, at: &timestamp, payload: query, outbound: true,
                         clientPort: clientPort, process: host.process, pid: host.pid)
            try writeDNS(writer, at: &timestamp, payload: answer, outbound: false,
                         clientPort: clientPort, process: host.process, pid: host.pid)

            // The connection that follows, which enrichment should label,
            // carrying a real TLS handshake so the analyzer has something to
            // read. The last host uses ECH, so the "outer name" path is
            // exercised by a plain fixture rather than only by tests.
            let tlsPort = UInt16(49000 + index)
            for (flags, outbound) in [(TCPFlags([.syn]), true),
                                      (TCPFlags([.syn, .ack]), false)] {
                try writeTCP(writer, at: &timestamp, host: host, clientPort: tlsPort,
                             flags: flags, outbound: outbound, payload: [])
            }

            var hello = TLSClientHelloBuilder()
            hello.serverName = host.name
            hello.encryptedClientHello = (index == resolvedHosts.count - 1)
            // Split across records, which is how a real one usually arrives.
            hello.recordSplits = 2
            try writeTCP(writer, at: &timestamp, host: host, clientPort: tlsPort,
                         flags: [.psh, .ack], outbound: true, payload: hello.build())

            var serverHello = TLSServerHelloBuilder()
            // One host negotiates TLS 1.2, so the certificate path differs
            // visibly from the encrypted 1.3 case.
            serverHello.selectedVersion = index == 0 ? nil : 0x0304
            serverHello.cipherSuite = index == 0 ? 0xC02F : 0x1301
            serverHello.alpn = index == 0 ? "h2" : nil
            try writeTCP(writer, at: &timestamp, host: host, clientPort: tlsPort,
                         flags: [.psh, .ack], outbound: false, payload: serverHello.build())
        }

        for i in 0..<packets {
            let r = recipes[i % recipes.count]
            var b = PktapHeaderBuilder()
            b.headerLength = r.hdrLen
            b.comm = r.comm
            b.pid = r.pid
            b.ecomm = r.ecomm
            b.epid = r.epid
            b.ifname = r.iface
            b.dlt = r.dlt
            b.framePreLength = r.pre
            b.ifType = r.ifType
            // Alternate direction so the calibration report has both to work with.
            b.flags = (i % 2 == 0 ? 0x0002 : 0x0001) | (r.delegated ? 0x0004 : 0)

            // A real link header, so Apple's tcpdump dissects the fixture the
            // same way it would a live capture. All-zero headers produce
            // "AF Unknown" and "[|llc]", which makes a side-by-side comparison
            // against tcpdump useless.
            var linkHeader = [UInt8](repeating: 0, count: Int(r.pre))
            switch r.dlt {
            case 1 where r.pre >= 14:            // DLT_EN10MB: EtherType IPv4
                linkHeader[12] = 0x08
                linkHeader[13] = 0x00
            case 0 where r.pre >= 4:             // DLT_NULL: host-order AF_INET
                linkHeader[0] = 2
            default:                             // DLT_RAW has no link header
                break
            }
            var ip = [UInt8](repeating: 0, count: 20)
            ip[0] = 0x45                                 // IPv4, 5 words of header
            ip[2] = 0; ip[3] = 40                        // total length = 20 IP + 20 TCP
            ip[8] = 64                                   // TTL
            ip[9] = 6                                    // TCP
            // Outbound packets get a local source; inbound get a remote one, so
            // the direction calibration in --replay has real ground truth.
            if i % 2 == 0 {
                ip[12] = 192; ip[13] = 168; ip[14] = 0; ip[15] = 10
                ip[16] = 93;  ip[17] = 184; ip[18] = 216; ip[19] = 34
            } else {
                ip[12] = 93;  ip[13] = 184; ip[14] = 216; ip[15] = 34
                ip[16] = 192; ip[17] = 168; ip[18] = 0;  ip[19] = 10
            }
            var tcp = [UInt8](repeating: 0, count: 20)
            tcp[0] = 0xC0; tcp[1] = 0x00                 // src port 49152
            tcp[2] = 0x01; tcp[3] = 0xBB                 // dst port 443
            tcp[12] = 0x50                               // data offset = 5 words
            tcp[13] = 0x18                               // PSH | ACK
            let record = b.build(payload: linkHeader + ip + tcp)

            try record.withUnsafeBytes {
                try writer.write(timestamp: timestamp,
                                 originalLength: record.count, bytes: $0)
            }
            timestamp += 0.01
        }
        try writer.close()

        print("""
        wrote \(packets + resolvedHosts.count * 5) synthetic pktap packets to \(path)
        including \(resolvedHosts.count) DNS lookups, each followed by a connection
        to the address it returned
        link type 258 (LINKTYPE_PKTAP)

        Replay it with:
            .build/debug/nmcapd --replay \(path)

        Note this only proves the decoder agrees with our own encoder. Matching
        the kernel is a separate question, settled by Tools/verify-pktap.sh.
        """)
        return 0
    } catch {
        print("failed: \(error)")
        return 1
    }
}

/// Writes a UDP/53 packet carrying `payload`, wrapped in a pktap header.
private func writeDNS(_ writer: PcapFileWriter, at timestamp: inout Double,
                      payload: [UInt8], outbound: Bool, clientPort: UInt16,
                      process: String, pid: Int32) throws {
    let client = IPAddress("192.168.0.31")!
    let resolver = IPAddress("192.168.0.1")!
    let ip = outbound
        ? PacketFixture.ipv4UDP(source: client, sourcePort: clientPort,
                                destination: resolver, destinationPort: 53,
                                payload: payload)
        : PacketFixture.ipv4UDP(source: resolver, sourcePort: 53,
                                destination: client, destinationPort: clientPort,
                                payload: payload)
    try write(writer, at: &timestamp, ip: ip, outbound: outbound,
              process: process, pid: pid)
}

private func writeTCP(_ writer: PcapFileWriter, at timestamp: inout Double,
                      host: (name: String, address: IPAddress, process: String, pid: Int32),
                      clientPort: UInt16, flags: TCPFlags, outbound: Bool,
                      payload: [UInt8]) throws {
    let client = IPAddress("192.168.0.31")!
    // Sequence numbers must advance per direction, or the reassembler reads
    // every segment as a retransmission of the first and the handshake never
    // accumulates.
    let sequence = nextSequence(clientPort: clientPort, outbound: outbound,
                                length: payload.count)
    let ip = outbound
        ? PacketFixture.ipv4TCP(.init(source: client, sourcePort: clientPort,
                                      destination: host.address, destinationPort: 443,
                                      flags: flags, sequence: sequence, payload: payload))
        : PacketFixture.ipv4TCP(.init(source: host.address, sourcePort: 443,
                                      destination: client, destinationPort: clientPort,
                                      flags: flags, sequence: sequence, payload: payload))
    try write(writer, at: &timestamp, ip: ip, outbound: outbound,
              process: host.process, pid: host.pid)
}

private func write(_ writer: PcapFileWriter, at timestamp: inout Double,
                   ip: [UInt8], outbound: Bool, process: String, pid: Int32) throws {
    var b = PktapHeaderBuilder()
    b.comm = process
    b.pid = pid
    b.ecomm = process
    b.epid = pid
    b.ifname = "en0"
    b.dlt = 1
    b.framePreLength = 14
    b.ifType = 0x06
    // Verified against live kernel output: 0x2 is outbound, 0x1 inbound.
    b.flags = outbound ? 0x0002 : 0x0001

    var ethernet = [UInt8](repeating: 0, count: 14)
    ethernet[12] = 0x08
    ethernet[13] = 0x00
    let record = b.build(payload: ethernet + ip)
    try record.withUnsafeBytes {
        try writer.write(timestamp: timestamp, originalLength: record.count, bytes: $0)
    }
    timestamp += 0.005
}

/// Per-direction sequence counters for the fixture's TCP streams.
private nonisolated(unsafe) var sequenceCounters: [String: UInt32] = [:]

private func nextSequence(clientPort: UInt16, outbound: Bool, length: Int) -> UInt32 {
    let key = "\(clientPort)-\(outbound)"
    let current = sequenceCounters[key] ?? 1000
    sequenceCounters[key] = current &+ UInt32(length)
    return current
}
