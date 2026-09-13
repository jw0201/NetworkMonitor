//
//  SQLite.swift
//
//  A thin wrapper over the system libsqlite3. No third-party dependency, and
//  no ORM: the schema and the queries are the design, and hiding them behind a
//  layer of abstraction would obscure exactly the decisions that matter here
//  (which index a query uses, how many rows a page touches).
//
//  THREADING. This build reports SQLITE_THREADSAFE=2, i.e. multi-thread, NOT
//  serialized. A connection must be touched by one thread at a time. We model
//  that structurally: each connection is owned by exactly one actor and a
//  `sqlite3*` never crosses an isolation boundary. SQLITE_OPEN_NOMUTEX is then
//  safe and skips a per-call mutex.
//

import Foundation
import SQLite3

/// SQLite's "the caller's buffer is temporary, copy it" destructor.
let SQLITE_TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

public struct SQLiteError: Error, CustomStringConvertible {
    public let code: Int32
    public let message: String
    public let context: String

    public var description: String { "sqlite error \(code) (\(context)): \(message)" }

    /// The one error code the GUI must special-case.
    ///
    /// A read-only connection cannot run WAL recovery. If the daemon is killed
    /// with a hot WAL, readers get this until a writer recovers the file. The
    /// UI shows "daemon recovering" and falls back to the XPC query path rather
    /// than presenting a corruption-shaped error to the user.
    public var isReadOnlyRecovery: Bool { code == 516 }   // SQLITE_READONLY_RECOVERY
}

public final class SQLiteConnection {
    var db: OpaquePointer?
    public let path: String
    public let isReadOnly: Bool
    private var statementCache: [String: OpaquePointer] = [:]

    public init(path: String, readOnly: Bool = false, create: Bool = true) throws {
        self.path = path
        self.isReadOnly = readOnly

        var flags = readOnly ? SQLITE_OPEN_READONLY
                             : (SQLITE_OPEN_READWRITE | (create ? SQLITE_OPEN_CREATE : 0))
        flags |= SQLITE_OPEN_NOMUTEX        // safe: one owner per connection, by construction
        flags |= SQLITE_OPEN_URI

        var handle: OpaquePointer?
        let rc = sqlite3_open_v2(path, &handle, flags, nil)
        guard rc == SQLITE_OK, let handle else {
            let msg = handle.map { String(cString: sqlite3_errmsg($0)) } ?? "cannot open"
            sqlite3_close_v2(handle)
            throw SQLiteError(code: rc, message: msg, context: "open \(path)")
        }
        self.db = handle
    }

    deinit { close() }

    public func close() {
        for (_, stmt) in statementCache { sqlite3_finalize(stmt) }
        statementCache.removeAll()
        if let db { sqlite3_close_v2(db) }
        db = nil
    }

    // MARK: - Errors

    private func fail(_ rc: Int32, _ context: String) -> SQLiteError {
        SQLiteError(code: rc,
                    message: db.map { String(cString: sqlite3_errmsg($0)) } ?? "",
                    context: context)
    }

    // MARK: - Execution

    /// Runs one or more statements with no results and no parameters.
    public func exec(_ sql: String) throws {
        guard let db else { throw SQLiteError(code: SQLITE_MISUSE, message: "closed", context: "exec") }
        var err: UnsafeMutablePointer<CChar>?
        let rc = sqlite3_exec(db, sql, nil, nil, &err)
        if rc != SQLITE_OK {
            let msg = err.map { String(cString: $0) } ?? String(cString: sqlite3_errmsg(db))
            sqlite3_free(err)
            throw SQLiteError(code: rc, message: msg, context: "exec")
        }
    }

    /// Prepares and caches a statement. Reused statements are reset, never
    /// re-prepared: at thousands of inserts per second, re-preparing is pure
    /// waste and shows up clearly in a profile.
    public func prepare(_ sql: String) throws -> Statement {
        if let cached = statementCache[sql] {
            sqlite3_reset(cached)
            sqlite3_clear_bindings(cached)
            return Statement(stmt: cached, connection: self)
        }
        guard let db else { throw SQLiteError(code: SQLITE_MISUSE, message: "closed", context: "prepare") }
        var stmt: OpaquePointer?
        let rc = sqlite3_prepare_v3(db, sql, -1, UInt32(SQLITE_PREPARE_PERSISTENT), &stmt, nil)
        guard rc == SQLITE_OK, let stmt else { throw fail(rc, "prepare: \(sql.prefix(120))") }
        statementCache[sql] = stmt
        return Statement(stmt: stmt, connection: self)
    }

    // MARK: - Transactions

    /// Runs `body` inside a transaction, rolling back on any error.
    ///
    /// BEGIN IMMEDIATE, not the default deferred BEGIN: the writer always
    /// intends to write, and taking the write lock up front converts a
    /// mid-transaction SQLITE_BUSY -- which would force a retry of work already
    /// done -- into a clean wait at the start.
    public func transaction<T>(_ body: () throws -> T) throws -> T {
        try exec("BEGIN IMMEDIATE")
        do {
            let result = try body()
            try exec("COMMIT")
            return result
        } catch {
            try? exec("ROLLBACK")
            throw error
        }
    }

    // MARK: - Introspection

    public var lastInsertRowID: Int64 { db.map { sqlite3_last_insert_rowid($0) } ?? 0 }
    public var changes: Int32 { db.map { sqlite3_changes($0) } ?? 0 }

    public func scalarInt(_ sql: String) throws -> Int64? {
        let s = try prepare(sql)
        defer { s.reset() }
        return try s.step() ? s.int64(0) : nil
    }

    public func scalarText(_ sql: String) throws -> String? {
        let s = try prepare(sql)
        defer { s.reset() }
        return try s.step() ? s.text(0) : nil
    }

    /// Applies a pragma and returns whatever it reports back. Pragmas that
    /// return a value (journal_mode, for example) silently do nothing if you
    /// use `exec` and never check, so this reads the result.
    @discardableResult
    public func pragma(_ text: String) throws -> String? {
        try scalarText("PRAGMA \(text)")
    }
}

public struct Statement {
    let stmt: OpaquePointer
    unowned let connection: SQLiteConnection

    // MARK: - Binding
    //
    // Parameters are 1-indexed. Everything user-supplied binds as a parameter;
    // nothing is ever interpolated into SQL text. That rule is absolute here --
    // the filter DSL feeds user input into queries run by a root process.

    public func bind(_ index: Int32, _ value: Int64?) {
        if let value { sqlite3_bind_int64(stmt, index, value) }
        else { sqlite3_bind_null(stmt, index) }
    }

    public func bind(_ index: Int32, _ value: Int?) { bind(index, value.map(Int64.init)) }
    public func bind(_ index: Int32, _ value: Int32?) { bind(index, value.map(Int64.init)) }
    public func bind(_ index: Int32, _ value: UInt16?) { bind(index, value.map(Int64.init)) }
    public func bind(_ index: Int32, _ value: UInt32?) { bind(index, value.map(Int64.init)) }
    public func bind(_ index: Int32, _ value: UInt8?) { bind(index, value.map(Int64.init)) }
    public func bind(_ index: Int32, _ value: Bool?) { bind(index, value.map { $0 ? Int64(1) : Int64(0) }) }
    public func bind(_ index: Int32, _ value: Double?) {
        if let value { sqlite3_bind_double(stmt, index, value) } else { sqlite3_bind_null(stmt, index) }
    }

    public func bind(_ index: Int32, _ value: String?) {
        if let value { sqlite3_bind_text(stmt, index, value, -1, SQLITE_TRANSIENT) }
        else { sqlite3_bind_null(stmt, index) }
    }

    public func bind(_ index: Int32, _ value: [UInt8]?) {
        guard let value else {
            sqlite3_bind_null(stmt, index)
            return
        }
        value.withUnsafeBytes { buf in
            _ = sqlite3_bind_blob(stmt, index, buf.baseAddress, Int32(buf.count), SQLITE_TRANSIENT)
        }
    }

    // MARK: - Stepping

    /// Advances the cursor. Returns true if a row is available.
    ///
    /// Resets automatically on SQLITE_DONE. That matters more than it looks:
    /// a statement left un-reset is still "in progress", and SQLite then
    /// refuses to COMMIT with error 5, "SQL statements in progress" -- an error
    /// that surfaces far from the statement that actually caused it. Resetting
    /// here makes the whole class of bug impossible rather than a thing to
    /// remember.
    @discardableResult
    public func step() throws -> Bool {
        let rc = sqlite3_step(stmt)
        switch rc {
        case SQLITE_ROW: return true
        case SQLITE_DONE:
            sqlite3_reset(stmt)
            return false
        default:
            sqlite3_reset(stmt)
            throw SQLiteError(code: rc,
                              message: String(cString: sqlite3_errmsg(connection.db)),
                              context: "step")
        }
    }

    /// Runs a statement that returns no rows.
    public func run() throws {
        _ = try step()
        sqlite3_reset(stmt)
        sqlite3_clear_bindings(stmt)
    }

    public func reset() {
        sqlite3_reset(stmt)
        sqlite3_clear_bindings(stmt)
    }

    // MARK: - Column access

    public func isNull(_ column: Int32) -> Bool {
        sqlite3_column_type(stmt, column) == SQLITE_NULL
    }

    public func int64(_ column: Int32) -> Int64 { sqlite3_column_int64(stmt, column) }
    public func int(_ column: Int32) -> Int { Int(sqlite3_column_int64(stmt, column)) }
    public func int64OrNil(_ column: Int32) -> Int64? { isNull(column) ? nil : int64(column) }
    public func bool(_ column: Int32) -> Bool { sqlite3_column_int64(stmt, column) != 0 }
    public func double(_ column: Int32) -> Double { sqlite3_column_double(stmt, column) }

    public func text(_ column: Int32) -> String? {
        guard let c = sqlite3_column_text(stmt, column) else { return nil }
        return String(cString: c)
    }

    public func blob(_ column: Int32) -> [UInt8]? {
        guard let p = sqlite3_column_blob(stmt, column) else { return nil }
        let n = Int(sqlite3_column_bytes(stmt, column))
        guard n > 0 else { return [] }
        return Array(UnsafeRawBufferPointer(start: p, count: n))
    }
}
