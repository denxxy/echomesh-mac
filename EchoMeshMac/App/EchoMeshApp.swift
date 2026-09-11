import SwiftUI

@main
struct EchoMeshApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    @State private var appState = AppState.shared

    var body: some Scene {
        // Main Application Window
        WindowGroup("EchoMesh", id: "mainWindow") {
            MainSplitView()
                .environment(appState)
        }
        .windowStyle(.titleBar)
        .windowToolbarStyle(.unified(showsTitle: true))
        .defaultSize(width: 960, height: 620)

        // Menu Bar Extra Item (macOS Status Item)
        MenuBarExtra("EchoMesh", systemImage: "shield.checkered") {
            MenuBarStatusView(appState: appState)
        }
        .menuBarExtraStyle(.menu)
    }
}
