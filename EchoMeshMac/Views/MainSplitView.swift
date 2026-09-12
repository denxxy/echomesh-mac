import SwiftUI

public struct MainSplitView: View {
    @State private var appState = AppState.shared
    @State private var chatVM = ChatViewModel.shared
    @State private var columnVisibility: NavigationSplitViewVisibility = .all

    public init() {}

    public var body: some View {
        NavigationSplitView(columnVisibility: $columnVisibility) {
            SidebarView(chatVM: chatVM, appState: appState)
                .navigationSplitViewColumnWidth(min: 240, ideal: 280, max: 360)
        } detail: {
            ChatView(chatVM: chatVM, appState: appState)
        }
        .frame(minWidth: 800, minHeight: 520)
        .toolbar {
            ToolbarItemGroup(placement: .navigation) {
                Button(action: toggleSidebar) {
                    Image(systemName: "sidebar.leading")
                }
                .help("Toggle Sidebar")
            }

            ToolbarItemGroup(placement: .automatic) {
                // Relay Status Pill
                HStack(spacing: 6) {
                    Circle()
                        .fill(appState.statusColor)
                        .frame(width: 8, height: 8)
                    Text(appState.statusDescription())
                        .font(.system(size: 11, weight: .medium))
                    if appState.pingMs > 0 {
                        Text("\(appState.pingMs) ms")
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundColor(.secondary)
                    }
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(Color(NSColor.controlBackgroundColor).opacity(0.6))
                .cornerRadius(12)

                // Copy Identity Key Button
                if let identity = appState.identity {
                    Button(action: {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(identity.publicKeyBase58, forType: .string)
                    }) {
                        Label("Copy Key", systemImage: "key.viewfinder")
                    }
                    .help("Copy your Base58 Identity Key to clipboard")
                }

                // Settings Button
                Button(action: { appState.isSettingsPresented = true }) {
                    Image(systemName: "gearshape")
                }
                .help("Open Settings")
            }
        }
        .sheet(isPresented: $appState.isSettingsPresented) {
            SettingsView(appState: appState)
        }
    }

    private func toggleSidebar() {
        NSApp.keyWindow?.firstResponder?.tryToPerform(#selector(NSSplitViewController.toggleSidebar(_:)), with: nil)
    }
}
