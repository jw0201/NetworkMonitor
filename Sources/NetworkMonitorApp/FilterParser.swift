//
//  FilterParser.swift
//
//  Turns what a person types into a QueryFilter.
//
//  A small closed vocabulary rather than free-form SQL. Anything unrecognised
//  is reported back as unrecognised rather than silently ignored -- a filter
//  that quietly drops half of what you typed and returns confident results is
//  worse than one that refuses.
//

import Foundation
import NMCore
import NMStore

struct ParsedFilter {
    var filter = QueryFilter()
    /// Tokens that looked like `key=value` but used an unknown key.
    var unknownKeys: [String] = []
    /// Tokens whose value could not be understood.
    var badValues: [String] = []

    var isValid: Bool { unknownKeys.isEmpty && badValues.isEmpty }

    var complaint: String? {
        var parts: [String] = []
        if !unknownKeys.isEmpty {
            parts.append("unknown field\(unknownKeys.count == 1 ? "" : "s"): "
                         + unknownKeys.joined(separator: ", "))
        }
        if !badValues.isEmpty {
            parts.append("could not read: " + badValues.joined(separator: ", "))
        }
        return parts.isEmpty ? nil : parts.joined(separator: "; ")
    }
}

enum FilterParser {

    static let fields = ["host", "process", "addr", "port", "proto", "service",
                         "state", "bytes", "since", "lossy"]

    static func parse(_ input: String) -> ParsedFilter {
        var result = ParsedFilter()
        var freeText: [String] = []

        for token in tokenize(input) {
            guard let separator = token.firstIndex(where: { $0 == "=" || $0 == ">" }) else {
                freeText.append(token)
                continue
            }
            let key = String(token[token.startIndex..<separator]).lowercased()
            let comparison = token[separator]
            let value = String(token[token.index(after: separator)...])
            guard !value.isEmpty else {
                result.badValues.append(token)
                continue
            }

            switch key {
            case "host":
                result.filter.host = value.lowercased()
            case "process", "proc", "app":
                result.filter.process = value
            case "addr", "ip":
                if let prefix = IPPrefix(value) {
                    result.filter.address = prefix
                } else if let address = IPAddress(value) {
                    // A bare address is a /32 or /128 -- the same range machinery
                    // rather than a special case.
                    result.filter.address = IPPrefix(
                        "\(address)/\(address.isIPv4 ? 32 : 128)")
                } else {
                    result.badValues.append(token)
                }
            case "port":
                if let port = UInt16(value) { result.filter.port = port }
                else { result.badValues.append(token) }
            case "proto":
                switch value.lowercased() {
                case "tcp": result.filter.proto = 6
                case "udp": result.filter.proto = 17
                case "icmp": result.filter.proto = 1
                default: result.badValues.append(token)
                }
            case "service":
                result.filter.service = value.lowercased()
            case "state":
                result.filter.state = value.uppercased()
            case "bytes":
                if let bytes = parseSize(value), comparison == ">" || comparison == "=" {
                    result.filter.minimumBytes = bytes
                } else {
                    result.badValues.append(token)
                }
            case "since":
                if let interval = parseDuration(value) {
                    result.filter.since = Timestamp(
                        (Date().timeIntervalSince1970 - interval) * 1_000_000)
                } else {
                    result.badValues.append(token)
                }
            case "lossy":
                result.filter.lossOnly = (value == "true" || value == "yes" || value == "1")
            default:
                result.unknownKeys.append(key)
            }
        }

        if !freeText.isEmpty {
            result.filter.text = freeText.joined(separator: " ")
        }
        return result
    }

    /// Splits on whitespace, honouring double quotes so a value can contain a
    /// space.
    private static func tokenize(_ input: String) -> [String] {
        var tokens: [String] = []
        var current = ""
        var inQuotes = false
        for character in input {
            if character == "\"" {
                inQuotes.toggle()
            } else if character.isWhitespace && !inQuotes {
                if !current.isEmpty { tokens.append(current); current = "" }
            } else {
                current.append(character)
            }
        }
        if !current.isEmpty { tokens.append(current) }
        return tokens
    }

    static func parseSize(_ text: String) -> Int64? {
        let lower = text.lowercased()
        let multipliers: [(String, Int64)] = [("gb", 1 << 30), ("mb", 1 << 20),
                                              ("kb", 1 << 10), ("g", 1 << 30),
                                              ("m", 1 << 20), ("k", 1 << 10),
                                              ("b", 1)]
        for (suffix, multiplier) in multipliers where lower.hasSuffix(suffix) {
            let number = String(lower.dropLast(suffix.count))
            guard let value = Double(number) else { return nil }
            return Int64(value * Double(multiplier))
        }
        return Int64(lower)
    }

    static func parseDuration(_ text: String) -> TimeInterval? {
        let lower = text.lowercased()
        let units: [(String, TimeInterval)] = [("d", 86400), ("h", 3600),
                                               ("m", 60), ("s", 1)]
        for (suffix, seconds) in units where lower.hasSuffix(suffix) {
            guard let value = Double(lower.dropLast()) else { return nil }
            return value * seconds
        }
        return Double(lower)
    }
}
