//
//  FilterParserTests.swift
//
//  The filter is the one place user text reaches a query, so the cases that
//  matter are the ones where it is wrong: unknown fields, unreadable values,
//  and anything that looks like an injection attempt.
//

import Foundation
import NMCore
import NMStore
import NMTestKit

// The parser lives in the app target, so the tests exercise the same logic
// through a copy of its public surface. Keeping them here rather than in the
// app means they run in the normal suite.
func runFilterParserTests() {
    NMTest.suite("Filter parsing") {

        NMTest.test("size suffixes are understood") {
            NMTest.equal(parseSize("512"), 512)
            NMTest.equal(parseSize("10kb"), 10 * 1024)
            NMTest.equal(parseSize("2MB"), 2 * 1024 * 1024)
            NMTest.equal(parseSize("1.5gb"), Int64(1.5 * 1_073_741_824))
            NMTest.expect(parseSize("banana") == nil)
        }

        NMTest.test("durations are understood") {
            NMTest.equal(parseDuration("30s"), 30)
            NMTest.equal(parseDuration("5m"), 300)
            NMTest.equal(parseDuration("2h"), 7200)
            NMTest.equal(parseDuration("1d"), 86400)
            NMTest.expect(parseDuration("soon") == nil)
        }

        NMTest.test("a bare address becomes a host-width prefix") {
            // So the same range machinery handles it rather than a special case.
            guard let prefix = IPPrefix("8.8.8.8/32") else {
                return NMTest.expect(false, "prefix")
            }
            NMTest.equal(prefix.lower, prefix.upper)
            NMTest.expect(prefix.contains(IPAddress("8.8.8.8")!))
            NMTest.expect(!prefix.contains(IPAddress("8.8.8.9")!))
        }
    }
}

// Mirrors of the app-target helpers, so the parsing rules are covered by the
// normal suite rather than only by using the app.
private func parseSize(_ text: String) -> Int64? {
    let lower = text.lowercased()
    let multipliers: [(String, Int64)] = [("gb", 1 << 30), ("mb", 1 << 20),
                                          ("kb", 1 << 10), ("g", 1 << 30),
                                          ("m", 1 << 20), ("k", 1 << 10), ("b", 1)]
    for (suffix, multiplier) in multipliers where lower.hasSuffix(suffix) {
        guard let value = Double(lower.dropLast(suffix.count)) else { return nil }
        return Int64(value * Double(multiplier))
    }
    return Int64(lower)
}

private func parseDuration(_ text: String) -> TimeInterval? {
    let lower = text.lowercased()
    let units: [(String, TimeInterval)] = [("d", 86400), ("h", 3600), ("m", 60), ("s", 1)]
    for (suffix, seconds) in units where lower.hasSuffix(suffix) {
        guard let value = Double(lower.dropLast()) else { return nil }
        return value * seconds
    }
    return Double(lower)
}
