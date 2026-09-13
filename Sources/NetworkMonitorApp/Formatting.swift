//
//  Formatting.swift
//

import SwiftUI
import NMCore
import NMIPC

enum Format {
    static func bytes(_ n: Int64) -> String {
        if n < 1024 { return "\(n) B" }
        if n < 1024 * 1024 { return String(format: "%.1f KB", Double(n) / 1024) }
        if n < 1024 * 1024 * 1024 { return String(format: "%.1f MB", Double(n) / 1_048_576) }
        return String(format: "%.2f GB", Double(n) / 1_073_741_824)
    }

    static func rate(_ bytesPerSecond: Int64) -> String { bytes(bytesPerSecond) + "/s" }

    static func time(_ ts: Timestamp) -> String {
        let date = Date(timeIntervalSince1970: Double(ts) / 1_000_000)
        return date.formatted(date: .omitted, time: .standard)
    }

    static func duration(since ts: Timestamp) -> String {
        let seconds = Int(Date().timeIntervalSince1970 - Double(ts) / 1_000_000)
        if seconds < 60 { return "\(max(seconds, 0))s" }
        if seconds < 3600 { return "\(seconds / 60)m \(seconds % 60)s" }
        return "\(seconds / 3600)h \((seconds % 3600) / 60)m"
    }

    static func protocolName(_ proto: UInt8) -> String {
        switch proto {
        case 1: return "icmp"
        case 6: return "tcp"
        case 17: return "udp"
        case 58: return "icmp6"
        default: return String(proto)
        }
    }

    /// A one-line gloss on a connection state. The vocabulary is Zeek's and is
    /// worth keeping, but nobody should have to memorise it to use the app.
    static func stateDescription(_ state: String) -> String {
        switch state {
        case "SF": return "Completed normally"
        case "S0": return "No response — dead host, filtered port, or a scan"
        case "S1": return "Established, still open"
        case "REJ": return "Actively refused"
        case "RSTO": return "Reset by this machine"
        case "RSTR": return "Reset by the remote host"
        case "S2": return "This machine finished, the remote host did not"
        case "S3": return "The remote host finished, this machine did not"
        case "SH": return "SYN then FIN with no reply — stealth-scan shape"
        case "OTH": return "Picked up mid-stream, no handshake seen"
        default: return state
        }
    }

    /// How a hostname was determined, so the UI never presents an inference as
    /// a fact.
    static func hostnameProvenance(_ source: Int) -> (label: String, certain: Bool)? {
        switch HostnameSource(rawValue: source) {
        case .tlsSNI: return ("from the TLS handshake", true)
        case .httpHost: return ("from the HTTP Host header", true)
        case .dnsPerProcess: return ("this process looked it up", true)
        case .dnsWildcard: return ("another process looked it up — may be wrong", false)
        case .reversePTR: return ("reverse lookup", false)
        case .none: return nil
        case nil: return nil
        @unknown default: return nil
        }
    }
}

/// A stable colour per process.
///
/// Derived from a hash rather than from rank, because colours that reshuffle as
/// processes change places make a live chart feel broken -- and that one detail
/// carries a disproportionate amount of perceived quality.
enum ProcessPalette {
    private static let colors: [Color] = [
        .blue, .orange, .green, .purple, .pink, .teal,
        .indigo, .mint, .cyan, .brown, .yellow, .red,
    ]

    static func color(for name: String) -> Color {
        var hash: UInt64 = 5381
        for byte in name.utf8 { hash = hash &* 33 &+ UInt64(byte) }
        return colors[Int(hash % UInt64(colors.count))]
    }
}
