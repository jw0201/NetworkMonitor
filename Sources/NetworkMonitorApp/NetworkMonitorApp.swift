//
//  NetworkMonitorApp.swift
//
//  The app entry point.
//
//  NOTE: this file must NOT be called main.swift. Swift treats a file of that
//  name as top-level code, and `@main` cannot be used in a module that contains
//  any -- the error ("'main' attribute cannot be used in a module that contains
//  top-level code") does not mention the filename, which makes it a genuinely
//  confusing half hour.
//

import SwiftUI

@main
struct NetworkMonitorApp: App {

    @State private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(model)
                .frame(minWidth: 900, minHeight: 560)
                .task { await model.start() }
        }
        .defaultSize(width: 1100, height: 700)
        .commands {
            CommandGroup(replacing: .newItem) {}
        }

        // A network monitor's value is proportional to how often you glance at
        // it, and a windowed app you have to cmd-tab to gets glanced at
        // approximately never. This also lets the app stay useful with every
        // window closed.
        MenuBarExtra {
            MenuBarView()
                .environment(model)
        } label: {
            MenuBarLabel()
                .environment(model)
        }
        .menuBarExtraStyle(.window)

        Settings {
            SettingsView()
                .environment(model)
        }
    }
}
