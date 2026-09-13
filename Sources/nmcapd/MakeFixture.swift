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
import NMCapture

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

    do {
        let writer = try PcapFileWriter(path: path, snaplen: 2048)
        var timestamp = Double(Int(Date().timeIntervalSince1970)) - Double(packets) * 0.01

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
        wrote \(packets) synthetic pktap packets to \(path)
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
