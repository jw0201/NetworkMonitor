//
//  SettingsView.swift
//
//  The split here is the product decision made visible: settings that change
//  WHAT IS COLLECTED or HOW LONG IT IS KEPT affect every user of the machine
//  and need administrator approval; settings that change WHAT YOU SEE are
//  yours alone and need no privilege at all.
//
//  The lock rendered here is a convenience. The daemon re-checks every change
//  regardless, because this process is one a user can replace.
//

import SwiftUI
import NMCore
import NMIPC

struct SettingsView: View {
    var body: some View {
        TabView {
            DisplaySettings()
                .tabItem { Label("Display", systemImage: "eye") }
            CollectionSettings()
                .tabItem { Label("Collection", systemImage: "antenna.radiowaves.left.and.right") }
            RetentionSettings()
                .tabItem { Label("Storage", systemImage: "internaldrive") }
            AboutPane()
                .tabItem { Label("About", systemImage: "info.circle") }
        }
        .frame(width: 520, height: 380)
    }
}

// MARK: - Per-user

/// No privilege required: these change only what this user sees.
private struct DisplaySettings: View {
    @AppStorage("chartWindowSeconds") private var chartWindow = 120
    @AppStorage("refreshHertz") private var refreshHertz = 2.0
    @AppStorage("showMenuBarExtra") private var showMenuBar = true
    @AppStorage("hidePlatformProcesses") private var hidePlatform = false

    var body: some View {
        Form {
            Picker("Chart window", selection: $chartWindow) {
                Text("1 minute").tag(60)
                Text("2 minutes").tag(120)
                Text("5 minutes").tag(300)
            }

            Picker("Refresh", selection: $refreshHertz) {
                Text("Twice a second").tag(2.0)
                Text("Once a second").tag(1.0)
                Text("Every 5 seconds").tag(0.2)
            }
            Text("A slower refresh uses less power. The monitoring service stops "
                 + "sending entirely when no window is showing.")
                .font(.caption)
                .foregroundStyle(.secondary)

            Toggle("Show in the menu bar", isOn: $showMenuBar)
            Toggle("Hide Apple system processes", isOn: $hidePlatform)
        }
        .formStyle(.grouped)
        .padding()
    }
}

// MARK: - System-wide

private struct CollectionSettings: View {
    @Environment(AppModel.self) private var model
    @State private var config = SystemConfig()
    @State private var canEdit = false
    @State private var message: String?

    var body: some View {
        Form {
            Section {
                Toggle("Capture network traffic", isOn: .constant(config.captureEnabled))
                    .disabled(!canEdit)
                LabeledContent("Snapshot length", value: "\(config.snaplen) bytes")
            } footer: {
                Text("A longer snapshot length captures more of each packet, which "
                     + "is needed to identify protocols, at the cost of more memory "
                     + "and a higher chance of dropping packets under load.")
                    .font(.caption)
            }

            Section {
                Toggle("Record the first bytes of each connection",
                       isOn: .constant(config.payloadCaptureEnabled))
                    .disabled(!canEdit)
            } header: {
                Text("Payload")
            } footer: {
                // This is the most sensitive switch in the product, so it is
                // described honestly rather than as a feature.
                Label("For connections that are not encrypted, this stores the "
                      + "actual content — including passwords sent in the clear. "
                      + "It is off by default and kept for the shortest time of "
                      + "anything recorded.",
                      systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }

            LockNotice(canEdit: canEdit, message: message)
        }
        .formStyle(.grouped)
        .padding()
        .task { await load() }
    }

    private func load() async {
        config = model.currentConfig ?? SystemConfig()
        canEdit = await model.callerIsAdministrator()
        if model.isDemo { message = "Demo mode — no monitoring service to configure." }
    }
}

private struct RetentionSettings: View {
    @Environment(AppModel.self) private var model
    @State private var config = SystemConfig()
    @State private var canEdit = false

    var body: some View {
        Form {
            Section {
                LabeledContent("Connections", value: "\(config.retention.connDays) days")
                LabeledContent("DNS lookups", value: "\(config.retention.dnsDays) days")
                LabeledContent("TLS handshakes", value: "\(config.retention.sslDays) days")
                LabeledContent("Payload", value: "\(config.retention.payloadDays) days")
            } header: {
                Text("Keep for")
            } footer: {
                // Retention should be chosen against a measured figure, not a
                // guess: at a heavy rate a flat 30-day retention needs more
                // space than a laptop has.
                VStack(alignment: .leading, spacing: 4) {
                    Text("Summaries are kept far longer than the individual records "
                         + "they came from, so long-term charts survive even after "
                         + "the detail expires.")
                    if let status = model.status {
                        Text("Currently using \(Format.bytes(status.databaseBytes)) "
                             + "with \(Format.bytes(status.freeSpaceBytes)) free.")
                    }
                }
                .font(.caption)
            }

            LockNotice(canEdit: canEdit, message: model.isDemo
                       ? "Demo mode — nothing is being stored." : nil)
        }
        .formStyle(.grouped)
        .padding()
        .task {
            config = model.currentConfig ?? SystemConfig()
            canEdit = await model.callerIsAdministrator()
        }
    }
}

/// Explains why a control is disabled, rather than leaving it greyed out with
/// no reason given.
private struct LockNotice: View {
    let canEdit: Bool
    var message: String?

    var body: some View {
        if let message {
            Label(message, systemImage: "info.circle")
                .font(.caption)
                .foregroundStyle(.secondary)
        } else if !canEdit {
            Label("These settings change what is recorded for everyone who uses "
                  + "this Mac, so an administrator has to approve them.",
                  systemImage: "lock")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}

private struct AboutPane: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("NetworkMonitor").font(.title2)
            if let status = model.status {
                LabeledContent("Service", value: status.version)
                LabeledContent("Capturing", value: status.capturing ? "Yes" : "No")
                LabeledContent("Interfaces", value: status.interfaces.joined(separator: ", "))
                LabeledContent("Store", value: status.databaseDirectory)
                LabeledContent("Direct database access", value:
                                status.callerCanReadStore ? "Allowed" : "Through the service")
            }
            Spacer()
        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
