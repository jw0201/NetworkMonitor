//
//  ConnectionsView.swift
//

import SwiftUI
import NMCore
import NMIPC

struct ConnectionsView: View {
    @Environment(AppModel.self) private var model
    @State private var selection: UInt64?
    @State private var search = ""
    @State private var sortOrder = [KeyPathComparator(\LiveFlow.totalBytes, order: .reverse)]

    var body: some View {
        HSplitView {
            Table(filtered, selection: $selection, sortOrder: $sortOrder) {
                TableColumn("Process") { flow in
                    HStack(spacing: 6) {
                        Circle()
                            .fill(ProcessPalette.color(for: flow.processName ?? "?"))
                            .frame(width: 7, height: 7)
                        Text(flow.processName ?? "—")
                        if flow.proxyName != nil {
                            Image(systemName: "arrow.triangle.branch")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                                .help("Carried by \(flow.proxyName ?? "") on this app's behalf")
                        }
                    }
                }
                .width(min: 130, ideal: 160)

                TableColumn("Destination") { flow in
                    DestinationCell(flow: flow)
                }
                .width(min: 180, ideal: 260)

                TableColumn("Port") { flow in
                    Text("\(flow.remotePort)").monospacedDigit()
                }
                .width(50)

                TableColumn("Proto") { flow in
                    Text(flow.service ?? Format.protocolName(flow.proto))
                        .foregroundStyle(.secondary)
                }
                .width(60)

                TableColumn("State") { flow in
                    Text(flow.state)
                        .help(Format.stateDescription(flow.state))
                }
                .width(56)

                TableColumn("Sent", value: \.bytesOut) { flow in
                    Text(Format.bytes(flow.bytesOut)).monospacedDigit()
                }
                .width(80)

                TableColumn("Received", value: \.bytesIn) { flow in
                    Text(Format.bytes(flow.bytesIn)).monospacedDigit()
                }
                .width(80)
            }
            .searchable(text: $search, prompt: "Process, host or address")

            if let selection, let flow = model.flows.first(where: { $0.uid == selection }) {
                ConnectionDetail(flow: flow)
                    .frame(minWidth: 260, idealWidth: 300)
            }
        }
        .navigationTitle("Connections")
        .navigationSubtitle("\(model.flows.count) open")
    }

    private var filtered: [LiveFlow] {
        let rows = search.isEmpty ? model.flows : model.flows.filter { flow in
            let haystack = [flow.processName, flow.hostname, flow.remoteAddress]
                .compactMap { $0 }.joined(separator: " ")
            return haystack.localizedCaseInsensitiveContains(search)
        }
        return rows.sorted(using: sortOrder)
    }
}

/// The destination cell, which is where provenance matters most.
///
/// A hostname can be a fact (the client asked for it in the TLS handshake) or
/// an inference (some other process resolved this address earlier). Presenting
/// both identically would make the weaker one look certain.
private struct DestinationCell: View {
    let flow: LiveFlow

    var body: some View {
        if let hostname = flow.hostname {
            HStack(spacing: 5) {
                Text(hostname)
                if let provenance = Format.hostnameProvenance(flow.hostnameSource),
                   !provenance.certain {
                    Image(systemName: "questionmark.circle")
                        .font(.caption2)
                        .foregroundStyle(.orange)
                        .help(provenance.label)
                }
            }
            .help(flow.remoteAddress)
        } else {
            Text(flow.remoteAddress)
                .foregroundStyle(.secondary)
                .monospacedDigit()
        }
    }
}

private struct ConnectionDetail: View {
    let flow: LiveFlow

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text(flow.hostname ?? flow.remoteAddress)
                    .font(.title3)
                    .textSelection(.enabled)

                if let provenance = Format.hostnameProvenance(flow.hostnameSource) {
                    Label(provenance.label,
                          systemImage: provenance.certain ? "checkmark.seal" : "questionmark.circle")
                        .font(.caption)
                        .foregroundStyle(provenance.certain ? AnyShapeStyle(.secondary)
                                                            : AnyShapeStyle(Color.orange))
                }

                Section("Connection") {
                    Row("State", flow.state, note: Format.stateDescription(flow.state))
                    Row("Protocol", flow.service ?? Format.protocolName(flow.proto))
                    Row("Local", "\(flow.localAddress):\(flow.localPort)")
                    Row("Remote", "\(flow.remoteAddress):\(flow.remotePort)")
                    Row("Open for", Format.duration(since: flow.startedAt))
                }

                Section("Traffic") {
                    Row("Sent", Format.bytes(flow.bytesOut))
                    Row("Received", Format.bytes(flow.bytesIn))
                }

                if let process = flow.processName {
                    Section("Process") {
                        Row("Application", process)
                        if let proxy = flow.proxyName {
                            Row("Carried by", proxy,
                                note: "The kernel attributes this traffic to \(proxy), "
                                    + "acting on \(process)'s behalf.")
                        }
                    }
                }
            }
            .padding(16)
        }
    }

    private struct Row: View {
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
                    Text(label)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .frame(width: 82, alignment: .leading)
                    Text(value)
                        .font(.callout)
                        .textSelection(.enabled)
                    Spacer()
                }
                if let note {
                    Text(note)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .padding(.leading, 82)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    private struct Section<Content: View>: View {
        let title: String
        @ViewBuilder let content: Content

        init(_ title: String, @ViewBuilder content: () -> Content) {
            self.title = title
            self.content = content()
        }

        var body: some View {
            VStack(alignment: .leading, spacing: 5) {
                Text(title)
                    .font(.caption)
                    .fontWeight(.semibold)
                    .foregroundStyle(.secondary)
                content
            }
        }
    }
}

/// `LiveFlow` is a wire type shared with the daemon, so it deliberately does
/// not conform to UI protocols. The conformance belongs to the app.
extension LiveFlow: Identifiable {
    public var id: UInt64 { uid }
}

extension LiveFlow {
    var totalBytes: Int64 { bytesIn + bytesOut }
}
