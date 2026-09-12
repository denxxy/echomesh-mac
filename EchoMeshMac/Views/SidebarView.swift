import SwiftUI

public struct SidebarView: View {
    @Bindable var chatVM: ChatViewModel
    @Bindable var appState: AppState
    @State private var isErrorPopoverPresented: Bool = false
    @State private var isPulsingScale: Bool = false

    public init(chatVM: ChatViewModel, appState: AppState) {
        self.chatVM = chatVM
        self.appState = appState
    }

    private var isConnected: Bool {
        appState.networkState == .connectedRealityRelay || appState.networkState == .connectedBleMeshFallback
    }

    public var body: some View {
        VStack(spacing: 0) {
            // Single Pinned Echo Relay Chat Item
            VStack(alignment: .leading, spacing: 6) {
                Text("ПОДКЛЮЧЕННЫЙ ШЛЮЗ")
                    .font(.system(size: 10, weight: .bold))
                    .foregroundColor(.secondary)
                    .padding(.horizontal, 14)
                    .padding(.top, 14)

                // The single pinned Echo Relay Chat row
                HStack(spacing: 12) {
                    // Avatar / Indicator
                    ZStack(alignment: .bottomTrailing) {
                        Circle()
                            .fill(
                                LinearGradient(
                                    colors: [Color.blue.opacity(0.8), Color.purple.opacity(0.8)],
                                    startPoint: .topLeading,
                                    endPoint: .bottomTrailing
                                )
                            )
                            .frame(width: 40, height: 40)
                            .overlay {
                                Image(systemName: "antenna.radiowaves.left.and.right")
                                    .font(.system(size: 17, weight: .semibold))
                                    .foregroundColor(.white)
                            }

                        // Status dot with pulsing effect
                        ZStack {
                            if isConnected {
                                Circle()
                                    .fill(Color.green.opacity(isPulsingScale ? 0.35 : 0.0))
                                    .frame(width: 18, height: 18)
                                    .scaleEffect(isPulsingScale ? 1.4 : 0.8)
                                    .animation(
                                        .easeInOut(duration: 1.2).repeatForever(autoreverses: true),
                                        value: isPulsingScale
                                    )
                            }

                            Circle()
                                .fill(isConnected ? Color.green : Color.red)
                                .frame(width: 10, height: 10)
                                .overlay(Circle().stroke(Color(NSColor.windowBackgroundColor), lineWidth: 2))
                                .shadow(color: (isConnected ? Color.green : Color.red).opacity(0.5), radius: 2)
                        }
                        .frame(width: 14, height: 14)
                        .offset(x: 2, y: 2)
                    }

                    VStack(alignment: .leading, spacing: 3) {
                        Text("Echo Relay Node")
                            .font(.system(size: 13, weight: .semibold))
                            .foregroundColor(.primary)

                        Text("77.81.5.109:8443 • Noise_NK")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(.secondary)
                            .lineLimit(1)
                    }

                    Spacer()

                    Image(systemName: "shield.checkered")
                        .font(.system(size: 13))
                        .foregroundColor(isConnected ? .green : .secondary)
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 10)
                .background(
                    RoundedRectangle(cornerRadius: 10)
                        .fill(Color.accentColor.opacity(0.12))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 10)
                        .stroke(Color.accentColor.opacity(0.3), lineWidth: 1)
                )
                .padding(.horizontal, 10)
                .padding(.top, 4)
            }
            .onAppear {
                isPulsingScale = true
            }

            Spacer()

            Divider()

            // Bottom Status Bar
            HStack(spacing: 8) {
                Button(action: {
                    if appState.networkState == .offline && appState.lastConnectionError != nil {
                        isErrorPopoverPresented.toggle()
                    }
                }) {
                    Circle()
                        .fill(isConnected ? Color.green : Color.red)
                        .frame(width: 9, height: 9)
                        .shadow(color: (isConnected ? Color.green : Color.red).opacity(0.6), radius: 3)
                }
                .buttonStyle(.plain)
                .popover(isPresented: $isErrorPopoverPresented, arrowEdge: .top) {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundColor(.red)
                            Text("Ошибка соединения")
                                .font(.headline)
                        }
                        Text(appState.lastConnectionError ?? "Connection Refused / Handshake Failed")
                            .font(.caption)
                            .foregroundColor(.secondary)
                            .textSelection(.enabled)
                        Divider()
                        HStack {
                            Button("Повторить") {
                                isErrorPopoverPresented = false
                                appState.connectCurrentRelay()
                            }
                            .buttonStyle(.borderedProminent)

                            Button("Настройки...") {
                                isErrorPopoverPresented = false
                                appState.isSettingsPresented = true
                            }
                        }
                    }
                    .padding(14)
                    .frame(width: 280)
                }

                VStack(alignment: .leading, spacing: 2) {
                    Text(isConnected ? "Сессия активна" : "Офлайн")
                        .font(.system(size: 11, weight: .medium))
                        .lineLimit(1)
                    Text(statusText)
                        .font(.system(size: 10))
                        .foregroundColor(appState.networkState == .offline && appState.lastConnectionError != nil ? .red : .secondary)
                        .lineLimit(1)
                }

                Spacer()

                Button(action: { appState.isSettingsPresented = true }) {
                    Image(systemName: "gearshape")
                        .font(.system(size: 13))
                        .foregroundColor(.secondary)
                }
                .buttonStyle(.plain)
                .help("Настройки и сеть")
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 10)
            .background(.ultraThinMaterial)
        }
    }

    private var statusText: String {
        switch appState.networkState {
        case .connectedRealityRelay:
            let pingPart = appState.pingMs > 0 ? " • \(appState.pingMs) ms" : ""
            return "77.81.5.109:8443\(pingPart)"
        case .connectedBleMeshFallback:
            return "Mesh Fallback"
        case .connecting:
            return "Подключение к 77.81.5.109:8443..."
        case .offline:
            if appState.lastConnectionError != nil {
                return "Ошибка подключения"
            }
            return "Офлайн"
        }
    }
}
