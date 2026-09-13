//
//  LogViews.swift
//
//  The three history screens, and the filter bar they share.
//

import SwiftUI
import NMCore
import NMStore

// MARK: - Filter bar

/// The filter field.
///
/// Unrecognised input is reported rather than ignored. A filter that quietly
/// drops half of what was typed and then returns confident-looking results is
/// worse than one that says it did not understand.
struct FilterBar: View {
    @Bindable var history: HistoryModel
    let kind: LogKind
    var examples: [String] = []

    @State private var showHelp = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 8) {
                Image(systemName: "line.3.horizontal.decrease.circle")
                    .foregroundStyle(.secondary)

                TextField("Filter", text: $history.filterText)
                    .textFieldStyle(.plain)
                    .onSubmit { Task { await history.reload(kind) } }

                if !history.filterText.isEmpty {
                    Button {
                        history.filterText = ""
                        Task { await history.reload(kind) }
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(.secondary)
                }

                Button { showHelp.toggle() } label: {
                    Image(systemName: "questionmark.circle")
                }
                .buttonStyle(.plain)
                .foregroundStyle(.secondary)
                .popover(isPresented: $showHelp) { FilterHelp(examples: examples) }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 7)
            .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 7))

            if let complaint = history.parsed.complaint {
                Label(complaint, systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .padding(.top, 5)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
    }
}

private struct FilterHelp: View {
    let examples: [String]

    var body: some View {
        VStack(alignment: .leading, spacing: 9) {
            Text("Filtering").font(.headline)
            Text("Type words to search, or use fields:")
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(FilterParser.fields.joined(separator: "  "))
                .font(.system(.caption, design: .monospaced))
            if !examples.isEmpty {
                Divider()
                ForEach(examples, id: \.self) { example in
                    Text(example).font(.system(.caption, design: .monospaced))
                }
            }
        }
        .padding(14)
        .frame(width: 320)
    }
}

/// Shown at the bottom of every log, so "nothing here" and "still loading" and
/// "the query failed" never look the same.
struct LogFooter: View {
    let count: Int
    let isLoading: Bool
    let reachedEnd: Bool
    let error: String?
    let isDemo: Bool

    var body: some View {
        HStack(spacing: 8) {
            if let error {
                Label(error, systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
            } else if isLoading {
                ProgressView().controlSize(.small)
                Text("Loading…")
            } else if count == 0 {
                Text("No matching records.")
            } else {
                Text("\(count) record\(count == 1 ? "" : "s")"
                     + (reachedEnd ? "" : " — scroll for more"))
            }
            Spacer()
            if isDemo {
                Label("Demo data", systemImage: "info.circle")
                    .foregroundStyle(.secondary)
            }
        }
        .font(.caption)
        .foregroundStyle(.secondary)
        .padding(.horizontal, 14)
        .padding(.vertical, 7)
    }
}

// MARK: - DNS

struct DNSView: View {
    @Environment(AppModel.self) private var app
    @State private var history: HistoryModel?
    @State private var selection: Int64?

    var body: some View {
        VStack(spacing: 0) {
            if let history {
                FilterBar(history: history, kind: .dns,
                          examples: ["host=github.com",
                                     "process=Safari",
                                     "since=1h  apple"])
                Divider()

                Table(history.dnsQueries, selection: $selection) {
                    TableColumn("Time") { row in
                        Text(Format.time(row.ts)).monospacedDigit()
                    }
                    .width(88)

                    TableColumn("Query") { row in
                        Text(row.query)
                            .foregroundStyle(row.isProblem ? .secondary : .primary)
                            .textSelection(.enabled)
                    }
                    .width(min: 180, ideal: 280)

                    TableColumn("Type") { row in
                        Text(row.qtypeName).foregroundStyle(.secondary)
                    }
                    .width(56)

                    TableColumn("Result") { row in DNSResultCell(row: row) }
                        .width(110)

                    TableColumn("Time taken") { row in
                        if let rtt = row.rttUs {
                            Text(String(format: "%.1f ms", Double(rtt) / 1000))
                                .monospacedDigit()
                        } else {
                            Text("—").foregroundStyle(.secondary)
                        }
                    }
                    .width(88)

                    TableColumn("Answers") { row in
                        Text(row.answers.isEmpty ? "—"
                             : row.answers.prefix(2).joined(separator: ", "))
                            .foregroundStyle(.secondary)
                            .help(row.answers.joined(separator: "\n"))
                    }
                    .width(min: 120, ideal: 180)

                    TableColumn("Process") { row in
                        Text(row.processName ?? "—")
                    }
                    .width(120)
                }
                .onAppear { Task { await history.reload(.dns) } }

                Divider()
                LogFooter(count: history.dnsQueries.count, isLoading: history.isLoading,
                          reachedEnd: history.reachedEnd, error: history.loadError,
                          isDemo: history.isDemo)
            } else {
                ProgressView()
            }
        }
        .navigationTitle("DNS")
        .task { if history == nil { history = makeHistory(app) } }
    }
}

/// A DNS result. Failures and non-answers are given weight rather than being a
/// quiet code in a column: an unanswered lookup is what a blocked resolver or a
/// captive portal looks like, which is exactly what someone opens this screen
/// to find.
private struct DNSResultCell: View {
    let row: DNSRow

    var body: some View {
        if row.rejected {
            Label("No reply", systemImage: "clock.badge.exclamationmark")
                .foregroundStyle(.orange)
                .help("The query was sent but nothing came back — a blocked "
                      + "resolver, a captive portal, or a dropped packet.")
        } else if row.rcode != 0 {
            Label(row.rcodeName, systemImage: "xmark.circle")
                .foregroundStyle(.red)
                .help(explanation)
        } else {
            Text("OK").foregroundStyle(.secondary)
        }
    }

    private var explanation: String {
        switch row.rcode {
        case 3: return "The name does not exist."
        case 2: return "The resolver failed to answer."
        case 5: return "The resolver refused to answer."
        default: return row.rcodeName
        }
    }
}

// MARK: - TLS

struct TLSView: View {
    @Environment(AppModel.self) private var app
    @State private var history: HistoryModel?
    @State private var selection: Int64?

    var body: some View {
        VStack(spacing: 0) {
            if let history {
                FilterBar(history: history, kind: .ssl,
                          examples: ["host=github.com",
                                     "process=Slack",
                                     "t13d  (searches the JA4 fingerprint)"])
                Divider()

                HSplitView {
                    Table(history.tlsSessions, selection: $selection) {
                        TableColumn("Time") { row in
                            Text(Format.time(row.ts)).monospacedDigit()
                        }
                        .width(88)

                        TableColumn("Server name") { row in TLSNameCell(row: row) }
                            .width(min: 180, ideal: 240)

                        TableColumn("Version") { row in
                            HStack(spacing: 4) {
                                Text(row.versionName)
                                if row.isWeakVersion {
                                    Image(systemName: "exclamationmark.triangle.fill")
                                        .font(.caption2)
                                        .foregroundStyle(.orange)
                                        .help("Deprecated protocol version.")
                                }
                            }
                        }
                        .width(90)

                        TableColumn("Certificate") { row in TLSCertificateCell(row: row) }
                            .width(min: 130, ideal: 180)

                        TableColumn("Process") { row in Text(row.processName ?? "—") }
                            .width(110)
                    }
                    .onAppear { Task { await history.reload(.ssl) } }

                    if let selection,
                       let row = history.tlsSessions.first(where: { $0.id == selection }) {
                        TLSDetail(row: row).frame(minWidth: 280, idealWidth: 320)
                    }
                }

                Divider()
                LogFooter(count: history.tlsSessions.count, isLoading: history.isLoading,
                          reachedEnd: history.reachedEnd, error: history.loadError,
                          isDemo: history.isDemo)
            } else {
                ProgressView()
            }
        }
        .navigationTitle("TLS")
        .task { if history == nil { history = makeHistory(app) } }
    }
}

/// With Encrypted Client Hello the visible name is the public outer one, not
/// the destination. Presenting it as the destination would be confidently
/// wrong, so it is labelled instead.
private struct TLSNameCell: View {
    let row: SSLRow

    var body: some View {
        if row.sniIsOuter {
            HStack(spacing: 5) {
                Image(systemName: "eye.slash")
                    .font(.caption2)
                    .foregroundStyle(.purple)
                Text(row.sni ?? "—").foregroundStyle(.secondary)
            }
            .help("Encrypted Client Hello: \(row.sni ?? "this name") is the public "
                  + "outer name. The real destination is not visible.")
        } else {
            Text(row.sni ?? row.serverAddress)
                .textSelection(.enabled)
        }
    }
}

/// "Encrypted" is a fact with a reason; "unknown" is a shrug. The UI has to
/// tell them apart, because under TLS 1.3 the first is the normal case.
private struct TLSCertificateCell: View {
    let row: SSLRow

    var body: some View {
        if !row.established {
            Text("No server reply").foregroundStyle(.orange)
        } else if row.certsEncrypted {
            Label("Encrypted", systemImage: "lock.doc")
                .foregroundStyle(.secondary)
                .help("TLS 1.3 encrypts the certificate, so it cannot be read "
                      + "by observing the connection. This is normal.")
        } else if let subject = row.subject {
            Text(subject).foregroundStyle(.secondary).help(row.issuer ?? "")
        } else {
            Text("—").foregroundStyle(.secondary)
        }
    }
}

private struct TLSDetail: View {
    let row: SSLRow

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text(row.sni ?? row.serverAddress).font(.title3).textSelection(.enabled)

                if row.sniIsOuter {
                    Label("This connection used Encrypted Client Hello. The name "
                          + "above is the public outer name; where it actually went "
                          + "is not observable.",
                          systemImage: "eye.slash")
                        .font(.caption)
                        .foregroundStyle(.purple)
                        .fixedSize(horizontal: false, vertical: true)
                }

                DetailRow("Server", "\(row.serverAddress):\(row.serverPort)")
                DetailRow("Version", row.versionName)
                DetailRow("Cipher", "0x" + String(row.cipher, radix: 16))
                DetailRow("ALPN", row.alpn ?? "not visible",
                          note: row.alpn == nil && row.version == 0x0304
                              ? "Under TLS 1.3 the server's choice is encrypted."
                              : nil)
                DetailRow("Process", row.processName ?? "—")

                if let ja4 = row.ja4 {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Client fingerprint")
                            .font(.caption).fontWeight(.semibold)
                            .foregroundStyle(.secondary)
                        Text(ja4)
                            .font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled)
                        if let ja3 = row.ja3 {
                            Text("JA3 \(ja3)")
                                .font(.system(.caption2, design: .monospaced))
                                .foregroundStyle(.secondary)
                                .textSelection(.enabled)
                        }
                    }
                }

                if row.certsEncrypted {
                    Label("The certificate is encrypted under TLS 1.3 and cannot be "
                          + "read from the connection itself.",
                          systemImage: "lock.doc")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                } else if let subject = row.subject {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Certificate").font(.caption).fontWeight(.semibold)
                            .foregroundStyle(.secondary)
                        Text(subject).font(.caption).textSelection(.enabled)
                        if let issuer = row.issuer {
                            Text("Issued by \(issuer)")
                                .font(.caption2).foregroundStyle(.secondary)
                        }
                        if let notAfter = row.notAfter {
                            Text("Expires \(Date(timeIntervalSince1970: Double(notAfter) / 1_000_000).formatted(date: .abbreviated, time: .omitted))")
                                .font(.caption2).foregroundStyle(.secondary)
                        }
                    }
                }
            }
            .padding(16)
        }
    }
}

private struct DetailRow: View {
    let label: String
    let value: String
    var note: String?

    init(_ label: String, _ value: String, note: String? = nil) {
        self.label = label
        self.value = value
        self.note = note
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 1) {
            HStack(alignment: .firstTextBaseline) {
                Text(label).font(.caption).foregroundStyle(.secondary)
                    .frame(width: 76, alignment: .leading)
                Text(value).font(.callout).textSelection(.enabled)
                Spacer()
            }
            if let note {
                Text(note).font(.caption2).foregroundStyle(.secondary)
                    .padding(.leading, 76)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

// MARK: - Raw browser

struct BrowserView: View {
    @Environment(AppModel.self) private var app
    @State private var history: HistoryModel?
    @State private var selection: Int64?

    var body: some View {
        VStack(spacing: 0) {
            if let history {
                FilterBar(history: history, kind: .conn,
                          examples: ["process=Safari  state=S0",
                                     "addr=10.0.0.0/8  port=443",
                                     "bytes>10MB  since=2h",
                                     "lossy=true  (counts known to be approximate)"])
                Divider()

                Table(history.connections, selection: $selection) {
                    TableColumn("Time") { row in
                        Text(Format.time(row.ts)).monospacedDigit()
                    }
                    .width(88)

                    TableColumn("Process") { row in
                        HStack(spacing: 5) {
                            Circle()
                                .fill(ProcessPalette.color(for: row.processName ?? "?"))
                                .frame(width: 7, height: 7)
                            Text(row.processName ?? "—")
                            if row.proxyName != nil {
                                Image(systemName: "arrow.triangle.branch")
                                    .font(.caption2).foregroundStyle(.secondary)
                                    .help("Carried by \(row.proxyName ?? "")")
                            }
                        }
                    }
                    .width(min: 110, ideal: 140)

                    TableColumn("Destination") { row in
                        HStack(spacing: 5) {
                            Text(row.hostname ?? row.remoteAddress)
                            if row.hostnameAmbiguous {
                                Image(systemName: "questionmark.circle")
                                    .font(.caption2).foregroundStyle(.orange)
                                    .help("Another process resolved this address; "
                                          + "the name may not be the one this "
                                          + "connection asked for.")
                            }
                        }
                        .help(row.remoteAddress)
                    }
                    .width(min: 160, ideal: 230)

                    TableColumn("Port") { row in
                        Text("\(row.remotePort)").monospacedDigit()
                    }
                    .width(48)

                    TableColumn("State") { row in
                        Text(row.state).help(Format.stateDescription(row.state))
                    }
                    .width(52)

                    TableColumn("Sent") { row in
                        Text(Format.bytes(row.bytesOut)).monospacedDigit()
                    }
                    .width(74)

                    TableColumn("Received") { row in
                        HStack(spacing: 4) {
                            Text(Format.bytes(row.bytesIn)).monospacedDigit()
                            if row.lossSuspected {
                                Image(systemName: "exclamationmark.triangle")
                                    .font(.caption2).foregroundStyle(.orange)
                                    .help("Packets were dropped during this "
                                          + "connection, so these counts are "
                                          + "approximate.")
                            }
                        }
                    }
                    .width(86)
                }
                .onAppear { Task { await history.reload(.conn) } }

                Divider()
                LogFooter(count: history.connections.count, isLoading: history.isLoading,
                          reachedEnd: history.reachedEnd, error: history.loadError,
                          isDemo: history.isDemo)
            } else {
                ProgressView()
            }
        }
        .navigationTitle("Connections log")
        .task { if history == nil { history = makeHistory(app) } }
    }
}

@MainActor
private func makeHistory(_ app: AppModel) -> HistoryModel {
    HistoryModel(storeDirectory: app.status?.databaseDirectory)
}
