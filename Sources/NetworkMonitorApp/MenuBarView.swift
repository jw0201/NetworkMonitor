//
//  MenuBarView.swift
//
//  A network monitor's value is proportional to how often you glance at it, and
//  a windowed app you have to cmd-tab to gets glanced at approximately never.
//  This is about eighty lines and it is what makes the thing useful.
//

import SwiftUI
import NMIPC

struct MenuBarLabel: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        HStack(spacing: 3) {
            Image(systemName: symbol)
            Text(Format.rate(model.currentInRate + model.currentOutRate))
                .font(.system(size: 11, design: .rounded))
                .monospacedDigit()
        }
    }

    private var symbol: String {
        switch model.health.level {
        case .healthy: return "waveform.path.ecg"
        case .degraded, .failing: return "exclamationmark.triangle.fill"
        }
    }
}

struct MenuBarView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("NetworkMonitor").font(.headline)
                    Text(model.linkDescription)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Circle().fill(model.health.tint).frame(width: 8, height: 8)
            }

            HStack(spacing: 18) {
                VStack(alignment: .leading, spacing: 1) {
                    Label("Down", systemImage: "arrow.down")
                        .font(.caption2).foregroundStyle(.secondary)
                    Text(Format.rate(model.currentInRate))
                        .font(.system(.body, design: .rounded)).monospacedDigit()
                }
                VStack(alignment: .leading, spacing: 1) {
                    Label("Up", systemImage: "arrow.up")
                        .font(.caption2).foregroundStyle(.secondary)
                    Text(Format.rate(model.currentOutRate))
                        .font(.system(.body, design: .rounded)).monospacedDigit()
                }
                Spacer()
            }

            Sparkline(values: model.samples.suffix(60).map(\.totalBytes))
                .frame(height: 28)

            if !model.topProcesses.isEmpty {
                Divider()
                VStack(alignment: .leading, spacing: 5) {
                    ForEach(model.topProcesses.prefix(4), id: \.execID) { process in
                        HStack(spacing: 6) {
                            Circle()
                                .fill(ProcessPalette.color(for: process.name))
                                .frame(width: 6, height: 6)
                            Text(process.name).font(.caption)
                            Spacer()
                            Text(Format.bytes(process.totalBytes))
                                .font(.caption).monospacedDigit()
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }

            if model.health.level != .healthy {
                Divider()
                Text(model.health.explanation)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Divider()
            HStack {
                Button("Open Window") {
                    openWindow(id: "main")
                    NSApp.activate(ignoringOtherApps: true)
                }
                Spacer()
                Button("Quit") { NSApp.terminate(nil) }
            }
            .buttonStyle(.link)
            .font(.caption)
        }
        .padding(14)
        .frame(width: 280)
    }
}

/// A minimal sparkline. Drawn directly rather than through Charts: at this size
/// the axis machinery costs more than the line.
struct Sparkline: View {
    let values: [Int64]

    var body: some View {
        GeometryReader { geometry in
            let maximum = max(values.max() ?? 1, 1)
            Path { path in
                guard values.count > 1 else { return }
                let step = geometry.size.width / CGFloat(values.count - 1)
                for (index, value) in values.enumerated() {
                    let x = CGFloat(index) * step
                    let y = geometry.size.height
                        * (1 - CGFloat(value) / CGFloat(maximum))
                    if index == 0 {
                        path.move(to: CGPoint(x: x, y: y))
                    } else {
                        path.addLine(to: CGPoint(x: x, y: y))
                    }
                }
            }
            .stroke(.tint, lineWidth: 1.5)
        }
    }
}
