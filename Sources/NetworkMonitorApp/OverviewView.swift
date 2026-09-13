//
//  OverviewView.swift
//

import Charts
import SwiftUI
import NMCore
import NMIPC

struct OverviewView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                if model.isDemo { DemoBanner() }
                RateHeader()
                ThroughputChart()
                ProcessBreakdown()
            }
            .padding(20)
        }
        .navigationTitle("Overview")
    }
}

private struct DemoBanner: View {
    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "info.circle.fill")
            VStack(alignment: .leading, spacing: 2) {
                Text("Showing demo data")
                    .fontWeight(.medium)
                Text("The monitoring service is not installed, so this is "
                     + "synthetic traffic rather than what is on the wire.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(12)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))
    }
}

private struct RateHeader: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        HStack(spacing: 28) {
            Stat(title: "Down", value: Format.rate(model.currentInRate),
                 symbol: "arrow.down", tint: .blue)
            Stat(title: "Up", value: Format.rate(model.currentOutRate),
                 symbol: "arrow.up", tint: .orange)
            Stat(title: "Connections", value: "\(model.activeFlowCount)",
                 symbol: "arrow.left.arrow.right", tint: .secondary)
            Spacer()
            if model.health.totalDropped > 0 {
                Stat(title: "Dropped", value: "\(model.health.totalDropped)",
                     symbol: "exclamationmark.triangle", tint: model.health.tint)
            }
        }
    }

    private struct Stat: View {
        let title: String
        let value: String
        let symbol: String
        let tint: Color

        var body: some View {
            VStack(alignment: .leading, spacing: 3) {
                Label(title, systemImage: symbol)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(value)
                    .font(.system(.title2, design: .rounded, weight: .medium))
                    .foregroundStyle(tint == .secondary ? .primary : tint)
                    .monospacedDigit()
                    .contentTransition(.numericText())
            }
        }
    }
}

private struct ThroughputChart: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Throughput").font(.headline)
                Spacer()
                Picker("", selection: Binding(
                    get: { model.chartWindowSeconds },
                    set: { model.chartWindowSeconds = $0 })) {
                    Text("1 min").tag(60)
                    Text("2 min").tag(120)
                    Text("5 min").tag(300)
                }
                .pickerStyle(.segmented)
                .frame(width: 200)
                .labelsHidden()
            }

            Chart {
                ForEach(model.samples, id: \.second) { sample in
                    AreaMark(x: .value("t", sample.second),
                             y: .value("in", sample.bytesIn),
                             series: .value("dir", "Down"))
                        .foregroundStyle(.blue.opacity(0.5))
                    AreaMark(x: .value("t", sample.second),
                             y: .value("out", sample.bytesOut),
                             series: .value("dir", "Up"))
                        .foregroundStyle(.orange.opacity(0.5))
                }
            }
            // Pinned rather than inferred. A y-axis that rescales every second
            // is both ugly and expensive, and an x-domain recomputed per frame
            // makes the whole chart re-layout.
            .chartYScale(domain: 0...niceMaximum)
            .chartXScale(domain: xDomain)
            .chartXAxis {
                AxisMarks(values: .automatic(desiredCount: 5)) { value in
                    AxisGridLine()
                    AxisValueLabel {
                        if let second = value.as(Int64.self) {
                            Text(Format.time(second * 1_000_000))
                                .font(.caption2)
                        }
                    }
                }
            }
            .chartYAxis {
                AxisMarks { value in
                    AxisGridLine()
                    AxisValueLabel {
                        if let bytes = value.as(Int64.self) {
                            Text(Format.bytes(bytes)).font(.caption2)
                        }
                    }
                }
            }
            .frame(height: 190)
            // SwiftUI will otherwise try to interpolate every mark at 60fps on
            // each update, which is what makes live charts jank.
            .animation(nil, value: model.samples.count)

            if model.lossEpoch > 0 {
                Label("Some packets were dropped during this window, so these "
                      + "figures are approximate.",
                      systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    /// Steps in coarse 1-2-5 increments so the axis does not twitch on every
    /// sample.
    private var niceMaximum: Int64 {
        let peak = model.peakRate
        var step: Int64 = 1024
        while step < peak {
            if step * 2 >= peak { return step * 2 }
            if step * 5 >= peak { return step * 5 }
            step *= 10
        }
        return max(step, 1024)
    }

    private var xDomain: ClosedRange<Int64> {
        let last = model.samples.last?.second ?? 0
        return (last - Int64(model.chartWindowSeconds))...max(last, 1)
    }
}

private struct ProcessBreakdown: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Traffic by process").font(.headline)

            if model.topProcesses.isEmpty {
                Text("No traffic yet.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .padding(.vertical, 8)
            } else {
                Chart(model.topProcesses.prefix(8), id: \.execID) { process in
                    BarMark(x: .value("bytes", process.totalBytes),
                            y: .value("process", process.name))
                        .foregroundStyle(ProcessPalette.color(for: process.name))
                        .annotation(position: .trailing) {
                            Text(Format.bytes(process.totalBytes))
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                }
                .chartXAxis(.hidden)
                .frame(height: CGFloat(min(model.topProcesses.count, 8)) * 28 + 20)
                .animation(nil, value: model.topProcesses.count)

                // Delegated traffic is shown as the application, so the proxy
                // that actually carried the bytes is worth naming somewhere.
                ForEach(model.topProcesses.prefix(8).filter { $0.viaProxy != nil },
                        id: \.execID) { process in
                    Text("\(process.name) — carried by \(process.viaProxy ?? "")")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }
}
