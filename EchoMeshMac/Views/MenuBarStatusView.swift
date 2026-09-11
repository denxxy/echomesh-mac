import SwiftUI
import AppKit

public struct MenuBarStatusView: View {
    var appState: AppState
    @State private var isPulsing: Bool = false
    @State private var isErrorExpanded: Bool = false

    public init(appState: AppState) {
        self.appState = appState
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Node Status Section
            HStack(spacing: 8) {
                ZStack {
                    if appState.networkState == .connectedRealityRelay {
                        Circle()
                            .fill(Color.green.opacity(isPulsing ? 0.3 : 0.0))
                            .frame(width: 16, height: 16)
                            .scaleEffect(isPulsing ? 1.3 : 0.8)
                            .animation(.easeInOut(duration: 1.2).repeatForever(autoreverses: true), value: isPulsing)
                    }

                    Circle()
                        .fill(appState.statusColor)
                        .frame(width: 8, height: 8)
                }
                .frame(width: 16, height: 16)
                .onAppear {
                    isPulsing = true
                }

                VStack(alignment: .leading, spacing: 2) {
                    Text(statusHeading)
                        .font(.system(size: 12, weight: .semibold))
                    Text(appState.currentEndpoint.formattedAddress)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.secondary)
                }

                Spacer()

                if appState.pingMs > 0 {
                    Text("\(appState.pingMs) ms")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(.secondary)
                }
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 8)

            // If in error state, show clickable error banner
            if appState.networkState == .offline, let err = appState.lastConnectionError {
                VStack(alignment: .leading, spacing: 4) {
                    HStack(alignment: .top, spacing: 6) {
                        Image(systemName: "exclamationmark.circle.fill")
                            .foregroundColor(.red)
                            .font(.caption)
                        Text(err)
                            .font(.system(size: 10))
                            .foregroundColor(.red)
                            .lineLimit(isErrorExpanded ? nil : 2)
                    }

                    HStack {
                        Button("Повторить") {
                            appState.connectCurrentRelay()
                        }
                        .font(.system(size: 10, weight: .semibold))

                        Spacer()

                        Button(isErrorExpanded ? "Свернуть" : "Подробнее") {
                            isErrorExpanded.toggle()
                        }
                        .font(.system(size: 10))
                    }
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 6)
                .background(Color.red.opacity(0.1))
            }

            Divider()

            // Quick Relay Switcher Section
            Text("Переключить релей:")
                .font(.caption)
                .foregroundColor(.secondary)
                .padding(.horizontal, 14)
                .padding(.top, 6)
                .padding(.bottom, 2)

            ForEach(appState.configManager.endpoints) { endpoint in
                let isActive = appState.configManager.activeEndpointId == endpoint.id
                Button(action: {
                    appState.switchEndpoint(endpoint)
                }) {
                    HStack {
                        Image(systemName: isActive ? "checkmark.circle.fill" : "circle")
                            .foregroundColor(isActive ? .accentColor : .secondary)
                        VStack(alignment: .leading, spacing: 1) {
                            HStack(spacing: 4) {
                                Text(endpoint.name)
                                    .font(.system(size: 12, weight: isActive ? .semibold : .regular))
                                if endpoint.isDefault {
                                    Text("def")
                                        .font(.system(size: 8, weight: .bold))
                                        .foregroundColor(.secondary)
                                }
                            }
                            Text(endpoint.formattedAddress)
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundColor(.secondary)
                        }
                        Spacer()
                    }
                }
                .buttonStyle(.plain)
                .padding(.horizontal, 14)
                .padding(.vertical, 3)
            }

            Divider()
                .padding(.top, 4)

            // Window management & App Quit
            Button(action: openMainWindow) {
                Label("Открыть EchoMesh", systemImage: "macwindow")
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 4)

            Button(action: {
                openMainWindow()
                appState.isSettingsPresented = true
            }) {
                Label("Настройки...", systemImage: "gearshape")
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 4)

            Divider()

            Button(role: .destructive, action: {
                NSApplication.shared.terminate(nil)
            }) {
                Label("Выйти из EchoMesh", systemImage: "power")
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 4)
        }
        .padding(.vertical, 4)
        .frame(width: 260)
    }

    private var statusHeading: String {
        switch appState.networkState {
        case .connectedRealityRelay:
            return "Connected"
        case .connectedBleMeshFallback:
            return "Mesh Fallback"
        case .connecting:
            return "Connecting..."
        case .offline:
            return appState.lastConnectionError != nil ? "Handshake Failed" : "Offline"
        }
    }

    private func openMainWindow() {
        NSApp.activate(ignoringOtherApps: true)
        if let window = NSApp.windows.first(where: { $0.canBecomeMain }) {
            window.makeKeyAndOrderFront(nil as Any?)
        }
    }
}
