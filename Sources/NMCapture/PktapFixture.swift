//
//  PktapFixture.swift
//
//  Construction of synthetic PKTAP records.
//
//  This lives in the library rather than in the test target because it is how
//  the capture layer is exercised WITHOUT root. Verifying the decoder against
//  a live capture needs privileges exactly once, to produce a sample file;
//  everything else -- tests, CI, benchmarks, crash reproduction -- runs against
//  synthesised or replayed records.
//

import Foundation

/// Builds a PKTAP v1 header. All multi-byte fields are HOST order, because this
/// is a kernel struct copied out verbatim -- not wire data.
public struct PktapHeaderBuilder {
    public var headerLength: UInt32 = 156
    public var typeNext: UInt32 = 1            // PTH_TYPE_PACKET
    public var dlt: UInt32 = 1                 // DLT_EN10MB
    public var ifname = "en0"
    public var flags: UInt32 = 0x0002          // candidate DIR_OUT
    public var protocolFamily: UInt32 = 2      // PF_INET
    public var framePreLength: UInt32 = 14     // Ethernet
    public var framePostLength: UInt32 = 0
    public var pid: Int32 = 501
    public var comm = "curl"
    public var svc: UInt32 = 0
    public var ifType: UInt16 = 0x6            // IFT_ETHER
    public var ifUnit: UInt16 = 0
    public var epid: Int32 = 501
    public var ecomm = "curl"
    public var flowID: UInt32 = 0xDEADBEEF
    public var ipProto: UInt32 = 6
    public var uuidHi: UInt64 = 0x0102030405060708
    public var uuidLo: UInt64 = 0x090A0B0C0D0E0F10

    public init() {}

    /// Serialises the header followed by `payload`, which stands in for the
    /// link-layer frame the kernel would have appended.
    public func build(payload: [UInt8] = []) -> [UInt8] {
        var b = [UInt8](repeating: 0, count: Int(max(headerLength, 108)))

        func putU32(_ v: UInt32, at off: Int) {
            guard off + 4 <= b.count else { return }
            b[off] = UInt8(v & 0xFF); b[off+1] = UInt8((v >> 8) & 0xFF)
            b[off+2] = UInt8((v >> 16) & 0xFF); b[off+3] = UInt8((v >> 24) & 0xFF)
        }
        func putU16(_ v: UInt16, at off: Int) {
            guard off + 2 <= b.count else { return }
            b[off] = UInt8(v & 0xFF); b[off+1] = UInt8((v >> 8) & 0xFF)
        }
        func putU64BE(_ v: UInt64, at off: Int) {
            guard off + 8 <= b.count else { return }
            for i in 0..<8 { b[off + i] = UInt8((v >> (56 - 8 * UInt64(i))) & 0xFF) }
        }
        func putStr(_ s: String, at off: Int, width: Int) {
            let u = Array(s.utf8).prefix(width - 1)
            for (i, c) in u.enumerated() where off + i < b.count { b[off + i] = c }
        }

        putU32(headerLength, at: 0)
        putU32(typeNext, at: 4)
        putU32(dlt, at: 8)
        putStr(ifname, at: 12, width: 24)
        putU32(flags, at: 36)
        putU32(protocolFamily, at: 40)
        putU32(framePreLength, at: 44)
        putU32(framePostLength, at: 48)
        putU32(UInt32(bitPattern: pid), at: 52)
        putStr(comm, at: 56, width: 17)
        putU32(svc, at: 76)
        putU16(ifType, at: 80)
        putU16(ifUnit, at: 82)
        putU32(UInt32(bitPattern: epid), at: 84)
        putStr(ecomm, at: 88, width: 17)
        putU32(flowID, at: 108)
        putU32(ipProto, at: 112)
        putU64BE(uuidHi, at: 124)
        putU64BE(uuidLo, at: 132)
        putU64BE(uuidHi, at: 140)
        putU64BE(uuidLo, at: 148)

        return b + payload
    }
}

