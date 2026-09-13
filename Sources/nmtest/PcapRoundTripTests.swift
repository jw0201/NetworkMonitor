//
//  PcapRoundTripTests.swift
//
//  Writes a PKTAP savefile and reads it back through the same decoder a live
//  capture uses. This closes the loop on the capture layer without root:
//  writer -> file -> libpcap -> PktapDecoder.
//
//  It also pins the decision that matters most for the pcap ring: the file must
//  record link type 258, not the 149 a live handle reports. Get that wrong and
//  Wireshark shows "DLT_USER2 - unknown" instead of per-packet process names.
//

import Foundation
import NMCapture
import NMCore
import NMTestKit

private func tempPath(_ name: String) -> String {
    NSTemporaryDirectory() + "nmtest-\(getpid())-\(name)"
}

func runPcapRoundTripTests() {
    NMTest.suite("pcap writer / file format") {

        // Settled by experiment, not by reading dlt.h: Apple's tcpdump dissects
        // 149 fully and reports UNSUPPORTED for 258, while Wireshark's pktap
        // dissector is keyed on 258. The ring therefore writes 149 -- a capture
        // no tool on the machine can open would be worthless -- and export
        // rewrites four header bytes.
        NMTest.test("the ring writes 149, which Apple's tcpdump can dissect") {
            let path = tempPath("linktype.pcap")
            defer { try? FileManager.default.removeItem(atPath: path) }

            let w = try PcapFileWriter(path: path)
            try w.close()

            guard let data = FileManager.default.contents(atPath: path) else {
                return NMTest.expect(false, "no file written")
            }
            NMTest.equal(data.count, 24, "a pcap file header is exactly 24 bytes")

            let bytes = [UInt8](data)
            let magic = UInt32(bytes[0]) | UInt32(bytes[1]) << 8
                      | UInt32(bytes[2]) << 16 | UInt32(bytes[3]) << 24
            NMTest.equal(magic, 0xA1B2_C3D4, "little-endian microsecond magic")

            // The `network` field lives at byte offset 20.
            let network = UInt32(bytes[20]) | UInt32(bytes[21]) << 8
                        | UInt32(bytes[22]) << 16 | UInt32(bytes[23]) << 24
            NMTest.equal(network, 149, "default is the value Apple's tcpdump understands")
        }

        NMTest.test("export rewrites the link type in place for Wireshark") {
            let path = tempPath("convert.pcap")
            defer { try? FileManager.default.removeItem(atPath: path) }

            let w = try PcapFileWriter(path: path)
            let payload = [UInt8](repeating: 0xCD, count: 64)
            try payload.withUnsafeBytes {
                try w.write(timestamp: 1_757_000_000, originalLength: 64, bytes: $0)
            }
            try w.close()

            let before = [UInt8](FileManager.default.contents(atPath: path)!)
            try PcapFileWriter.rewriteLinkType(path: path, to: .wiresharkFile)
            let after = [UInt8](FileManager.default.contents(atPath: path)!)

            NMTest.equal(after.count, before.count, "conversion must not resize the file")
            NMTest.equal(UInt32(after[20]) | UInt32(after[21]) << 8, 258)
            NMTest.equal(Array(after[24...]), Array(before[24...]),
                         "packet records are identical between the two link types")
        }

        NMTest.test("packet offsets advance exactly by 16 + caplen") {
            let path = tempPath("offsets.pcap")
            defer { try? FileManager.default.removeItem(atPath: path) }

            let w = try PcapFileWriter(path: path)
            NMTest.equal(w.currentOffset, 24, "after the file header")

            let payload = [UInt8](repeating: 0xAB, count: 100)
            try payload.withUnsafeBytes {
                try w.write(timestamp: 1_757_000_000.5, originalLength: 100, bytes: $0)
            }
            NMTest.equal(w.currentOffset, 24 + 16 + 100,
                         "offsets are what the segment index records per flow")
            try w.close()
        }
    }

    NMTest.suite("pcap round trip / writer -> libpcap -> decoder") {

        NMTest.test("synthetic pktap packets survive a write/read cycle intact") {
            let path = tempPath("roundtrip.pcap")
            defer { try? FileManager.default.removeItem(atPath: path) }

            // Three packets with distinct, checkable metadata.
            var specs: [(pid: Int32, comm: String, epid: Int32, ecomm: String,
                         iface: String, delegated: Bool)] = [
                (501, "curl", 501, "curl", "en0", false),
                (130, "nsurlsessiond", 904, "Mail", "en0", true),
                (77, "mDNSResponder", 77, "mDNSResponder", "lo0", false),
            ]

            let writer = try PcapFileWriter(path: path)
            for spec in specs {
                var b = PktapHeaderBuilder()
                b.pid = spec.pid
                b.comm = spec.comm
                b.epid = spec.epid
                b.ecomm = spec.ecomm
                b.ifname = spec.iface
                b.flags = 0x0002 | (spec.delegated ? 0x0004 : 0)
                // A minimal IPv4 header so the address probe has something real.
                var ip = [UInt8](repeating: 0, count: 20)
                ip[0] = 0x45
                ip[9] = 6                                  // TCP
                ip[12...15] = [192, 168, 0, 10][0...3]     // src
                ip[16...19] = [93, 184, 216, 34][0...3]    // dst
                let ethernet = [UInt8](repeating: 0, count: 14)
                let record = b.build(payload: ethernet + ip)
                try record.withUnsafeBytes {
                    try writer.write(timestamp: 1_757_000_000.0,
                                     originalLength: record.count, bytes: $0)
                }
            }
            try writer.close()

            let replay = try PacketReplay(path: path)
            defer { replay.close() }
            NMTest.expect(replay.linkType == 149 || replay.linkType == 258,
                          "libpcap reported link type \(replay.linkType)")

            var decoded: [(Int32, String, Int32, String, String, Bool)] = []
            let result = replay.replayAll { meta, _, _ in
                decoded.append((meta.pid, meta.comm, meta.epid, meta.ecomm,
                                meta.ifname, meta.isProcessDelegated))
            }

            NMTest.equal(result.decodeFailures, 0, "every packet must decode")
            NMTest.equal(result.decoded, 3)
            NMTest.equal(decoded.count, 3)

            for (i, spec) in specs.enumerated() where i < decoded.count {
                let d = decoded[i]
                NMTest.equal(d.0, spec.pid, "pid of packet \(i)")
                NMTest.equal(d.1, spec.comm, "comm of packet \(i)")
                NMTest.equal(d.2, spec.epid, "epid of packet \(i)")
                NMTest.equal(d.3, spec.ecomm, "ecomm of packet \(i)")
                NMTest.equal(d.4, spec.iface, "iface of packet \(i)")
                NMTest.equal(d.5, spec.delegated, "delegation flag of packet \(i)")
            }

            // The delegated packet is the one that matters most: it must report
            // the application, not the proxy that carried the bytes.
            if decoded.count > 1 {
                NMTest.equal(decoded[1].3, "Mail",
                             "delegated traffic must surface the real owner")
                NMTest.equal(decoded[1].1, "nsurlsessiond",
                             "and must also preserve the proxy")
            }
            specs.removeAll()
        }

        NMTest.test("a truncated file is rejected rather than half-decoded") {
            let path = tempPath("truncated.pcap")
            defer { try? FileManager.default.removeItem(atPath: path) }
            try Data([0x01, 0x02, 0x03]).write(to: URL(fileURLWithPath: path))
            NMTest.throwsError({ _ = try PacketReplay(path: path) })
        }

        NMTest.test("a non-pktap capture is refused with a clear reason") {
            let path = tempPath("ethernet.pcap")
            defer { try? FileManager.default.removeItem(atPath: path) }
            // link type 1 = DLT_EN10MB: a normal Ethernet capture, no process metadata.
            let w = try PcapFileWriter(path: path, rawLinkType: 1)
            try w.close()
            NMTest.throwsError({ _ = try PacketReplay(path: path) }, validate: { err in
                if case ReplayError.unsupportedLinkType(let dlt) = err { return dlt == 1 }
                return false
            })
        }
    }
}
