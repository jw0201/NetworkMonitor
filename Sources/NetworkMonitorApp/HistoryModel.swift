//
//  HistoryModel.swift
//
//  Paged access to the logs.
//
//  History comes from the databases directly rather than over XPC, which is
//  the hybrid split the architecture settles on: proxying a large scan would
//  make the capture daemon spend its CPU serialising rows instead of draining
//  the BPF buffer.
//
//  When there is no store -- demo mode -- it invents rows with the same shape,
//  so the screens are developable and the empty state is not the only thing
//  anyone ever sees.
//

import Foundation
import Observation
import NMCore
import NMIPC
import NMStore

@MainActor
@Observable
final class HistoryModel {

    private(set) var connections: [ConnRow] = []
    private(set) var dnsQueries: [DNSRow] = []
    private(set) var tlsSessions: [SSLRow] = []

    private(set) var isLoading = false
    private(set) var reachedEnd = false
    /// Set when the store could not be read. Shown rather than swallowed: an
    /// empty table and a broken query look identical otherwise.
    private(set) var loadError: String?

    var filterText = "" {
        didSet { parsed = FilterParser.parse(filterText) }
    }
    private(set) var parsed = ParsedFilter()

    private var reader: StoreReader?
    private var demo: DemoHistory?
    private var cursor: PageCursor?
    private var currentKind: LogKind = .conn

    init(storeDirectory: String?) {
        if let storeDirectory,
           FileManager.default.fileExists(atPath: storeDirectory + "/live.db") {
            // The directory the daemon reported. Read-only, and the app never
            // writes to it.
            reader = StoreReader(paths: Paths(root: URL(fileURLWithPath: storeDirectory)
                .deletingLastPathComponent().path))
        } else {
            demo = DemoHistory()
        }
    }

    var isDemo: Bool { demo != nil }

    // MARK: - Loading

    func reload(_ kind: LogKind) async {
        currentKind = kind
        cursor = nil
        reachedEnd = false
        loadError = nil
        switch kind {
        case .conn: connections = []
        case .dns: dnsQueries = []
        case .ssl: tlsSessions = []
        }
        await loadMore(kind)
    }

    func loadMore(_ kind: LogKind) async {
        guard !isLoading, !reachedEnd else { return }
        isLoading = true
        defer { isLoading = false }

        let spec = QuerySpec(kind: kind, filter: parsed.filter, limit: 200, cursor: cursor)

        if let demo {
            let page = demo.page(spec)
            append(page: page, kind: kind)
            return
        }
        guard let reader else { return }

        do {
            switch kind {
            case .conn:
                let page = try await reader.connectionRows(spec)
                connections.append(contentsOf: page.rows)
                finish(page.next)
            case .dns:
                let page = try await reader.dnsQueries(spec)
                dnsQueries.append(contentsOf: page.rows)
                finish(page.next)
            case .ssl:
                let page = try await reader.tlsSessions(spec)
                tlsSessions.append(contentsOf: page.rows)
                finish(page.next)
            }
        } catch let error as SQLiteError where error.isReadOnlyRecovery {
            loadError = "The monitoring service is recovering its database. "
                + "History will be available again shortly."
            reachedEnd = true
        } catch {
            loadError = "Could not read the log: \(error)"
            reachedEnd = true
        }
    }

    private func finish(_ next: PageCursor?) {
        cursor = next
        reachedEnd = next == nil
    }

    private func append(page: DemoHistory.AnyPage, kind: LogKind) {
        switch kind {
        case .conn: connections.append(contentsOf: page.conns)
        case .dns: dnsQueries.append(contentsOf: page.dns)
        case .ssl: tlsSessions.append(contentsOf: page.ssl)
        }
        finish(page.next)
    }

    /// True when the visible rows end short of the data, so a view can ask for
    /// more as the user approaches the bottom.
    func shouldLoadMore(currentIndex: Int, total: Int) -> Bool {
        !reachedEnd && !isLoading && currentIndex >= total - 50
    }

    func close() async {
        await reader?.close()
    }
}
