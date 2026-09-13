import SwiftUI

enum Screen: String, CaseIterable, Identifiable {
    case overview = "Overview"
    case connections = "Connections"
    case dns = "DNS"
    case tls = "TLS"
    case browser = "Raw"

    var id: String { rawValue }

    var symbol: String {
        switch self {
        case .overview: return "chart.line.uptrend.xyaxis"
        case .connections: return "arrow.left.arrow.right"
        case .dns: return "globe"
        case .tls: return "lock"
        case .browser: return "list.bullet.rectangle"
        }
    }
}

struct RootView: View {
    @Environment(AppModel.self) private var model
    @State private var screen: Screen = .overview

    var body: some View {
        NavigationSplitView {
            List(Screen.allCases, selection: $screen) { item in
                Label(item.rawValue, systemImage: item.symbol)
                    .tag(item)
            }
            .navigationSplitViewColumnWidth(min: 170, ideal: 190, max: 240)
            .safeAreaInset(edge: .bottom) {
                LinkStatusBar()
            }
        } detail: {
            Group {
                switch screen {
                case .overview: OverviewView()
                case .connections: ConnectionsView()
                case .dns: DNSView()
                case .tls: TLSView()
                case .browser: BrowserView()
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }
}

/// Connection state and capture health, always visible.
///
/// Deliberately not tucked away: a monitor that is quietly dropping packets
/// still produces plausible-looking numbers, so the one place a user should
/// never have to go looking is "is this actually working".
struct LinkStatusBar: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Divider()
            HStack(spacing: 6) {
                Circle()
                    .fill(model.health.tint)
                    .frame(width: 8, height: 8)
                Text(model.linkDescription)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            if model.health.level != .healthy {
                Text(model.health.explanation)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.horizontal, 12)
        .padding(.bottom, 10)
    }
}

