//
//  NMTestKit.swift
//
//  A ~100-line test harness.
//
//  WHY NOT XCTest OR swift-testing: neither ships with the Command Line Tools.
//  XCTest.framework comes with Xcode; swift-testing comes with the Xcode
//  toolchain. This project builds with CLT only and takes no third-party
//  dependencies, so `swift test` is not available to us. Tests are therefore an
//  ordinary executable target (`swift run nmtest`) built on this harness.
//
//  If full Xcode is ever installed, this can be swapped for swift-testing with
//  a mechanical rename -- the assertion vocabulary is deliberately the same shape.
//

import Foundation

public struct TestFailure: Sendable {
    public let suite: String
    public let test: String
    public let message: String
    public let file: String
    public let line: Int
}

public enum NMTest {
    nonisolated(unsafe) private static var failures: [TestFailure] = []
    nonisolated(unsafe) private static var suiteName = ""
    nonisolated(unsafe) private static var testName = ""
    nonisolated(unsafe) private static var testCount = 0
    nonisolated(unsafe) private static var checkCount = 0
    nonisolated(unsafe) private static var failedThisTest = false

    public static func suite(_ name: String, _ body: () -> Void) {
        suiteName = name
        print("\n\u{001B}[1m\(name)\u{001B}[0m")
        body()
    }

    public static func test(_ name: String, _ body: () throws -> Void) {
        testName = name
        testCount += 1
        failedThisTest = false
        do {
            try body()
        } catch {
            record("threw unexpectedly: \(error)", file: #file, line: #line)
        }
        print(failedThisTest ? "  \u{001B}[31mFAIL\u{001B}[0m  \(name)"
                             : "  \u{001B}[32mok\u{001B}[0m    \(name)")
    }

    /// Async variant, for anything that has to await an actor.
    public static func test(_ name: String, _ body: () async throws -> Void) async {
        testName = name
        testCount += 1
        failedThisTest = false
        do {
            try await body()
        } catch {
            record("threw unexpectedly: \(error)", file: #file, line: #line)
        }
        print(failedThisTest ? "  \u{001B}[31mFAIL\u{001B}[0m  \(name)"
                             : "  \u{001B}[32mok\u{001B}[0m    \(name)")
    }

    public static func suite(_ name: String, _ body: () async -> Void) async {
        suiteName = name
        print("\n\u{001B}[1m\(name)\u{001B}[0m")
        await body()
    }

    private static func record(_ message: String, file: String, line: Int) {
        failedThisTest = true
        failures.append(TestFailure(suite: suiteName, test: testName,
                                    message: message,
                                    file: (file as NSString).lastPathComponent, line: line))
    }

    // MARK: - Assertions

    public static func expect(_ condition: Bool, _ message: @autoclosure () -> String = "",
                              file: String = #file, line: Int = #line) {
        checkCount += 1
        if !condition {
            let m = message()
            record(m.isEmpty ? "expected true" : m, file: file, line: line)
        }
    }

    public static func equal<T: Equatable>(_ actual: T, _ expected: T,
                                           _ message: @autoclosure () -> String = "",
                                           file: String = #file, line: Int = #line) {
        checkCount += 1
        if actual != expected {
            let extra = message()
            record("expected \(expected), got \(actual)" + (extra.isEmpty ? "" : " -- \(extra)"),
                   file: file, line: line)
        }
    }

    /// Asserts that `body` throws. Optionally validates the thrown error.
    public static func throwsError(_ body: () throws -> Void,
                                   _ message: @autoclosure () -> String = "",
                                   file: String = #file, line: Int = #line,
                                   validate: ((Error) -> Bool)? = nil) {
        checkCount += 1
        do {
            try body()
            let extra = message()
            record("expected a thrown error, none was thrown"
                   + (extra.isEmpty ? "" : " -- \(extra)"), file: file, line: line)
        } catch {
            if let validate, !validate(error) {
                record("thrown error did not match expectation: \(error)", file: file, line: line)
            }
        }
    }

    public static func noThrow(_ body: () throws -> Void,
                               file: String = #file, line: Int = #line) {
        checkCount += 1
        do { try body() } catch { record("unexpected throw: \(error)", file: file, line: line) }
    }

    // MARK: - Reporting

    /// Prints a summary and returns a process exit code.
    public static func finish() -> Int32 {
        print("")
        if failures.isEmpty {
            print("\u{001B}[32m\(testCount) tests, \(checkCount) checks, all passed\u{001B}[0m")
            return 0
        }
        print("\u{001B}[31m\(failures.count) failure(s) in \(testCount) tests "
              + "(\(checkCount) checks)\u{001B}[0m")
        for f in failures {
            print("  \u{001B}[31m*\u{001B}[0m \(f.suite) / \(f.test)")
            print("      \(f.message)")
            print("      \(f.file):\(f.line)")
        }
        return 1
    }
}
