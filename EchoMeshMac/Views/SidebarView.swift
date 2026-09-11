import SwiftUI

public struct SidebarView: View {
    @Bindable var chatVM: ChatViewModel
    @Bindable var appState: AppState
    @State private var searchText: String = ""
    @State private var isErrorPopoverPresented: Bool = false
    @State private var isPulsingScale: Bool = false

    public init(chatVM: ChatViewModel, appState: AppState) {
        self.chatVM = chatVM
        self.appState = appState
    }

    public var filteredConversations: [ChatConversation] {
        if searchText.isEmpty {
            return chatVM.conversations
        } else {
            return chatVM.conversations.filter {
                $0.name.localizedCaseInsensitiveContains(searchText) ||
                $0.publicKeyBase58.localizedCaseInsensitiveContains(searchText)
            }
        }
    }

    public var body: some View {
        VStack(spacing: 0) {
            // Search Bar
            HStack {
                Image(systemName: "magnifyingglass")
                    .foregroundColor(.secondary)
                TextField("Поиск узлов или ключей...", text: $searchText)
                    .textFieldStyle(.plain)
                if !searchText.isEmpty {
                    Button(action: { searchText = "" }) {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundColor(.secondary)
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(8)
            .background(Color(NSColor.controlBackgroundColor).opacity(0.6))
            .cornerRadius(8)
            .padding([.horizontal, .top], 10)
            .padding(.bottom, 6)

            // Conversations List
            List(selection: $chatVM.selectedConversationId) {
                Section("Защищенные диалоги") {
                    ForEach(filteredConversations) { conv in
                        NavigationLink(value: conv.id) {
                            ConversationRow(conversation: conv)
                        }
                    }
                }
            }
            .listStyle(.sidebar)

            Divider()

            // Bottom Relay Status Bar
            HStack(spacing: 8) {
                // Live Status Indicator Dot
                Button(action: {
                    if appState.networkState == .offline && appState.lastConnectionError != nil {
                        isErrorPopoverPresented.toggle()
                    }
                }) {
                    ZStack {
                        if appState.networkState == .connectedRealityRelay {
                            // Pulsing halo effect
                            Circle()
                                .fill(Color.green.opacity(isPulsingScale ? 0.3 : 0.0))
                                .frame(width: 18, height: 18)
                                .scaleEffect(isPulsingScale ? 1.4 : 0.8)
                                .animation(
                                    .easeInOut(duration: 1.2).repeatForever(autoreverses: true),
                                    value: isPulsingScale
                                )
                        }

                        Circle()
                            .fill(appState.statusColor)
                            .frame(width: 9, height: 9)
                            .shadow(color: appState.statusColor.opacity(0.6), radius: 3)
                    }
                    .frame(width: 18, height: 18)
                }
                .buttonStyle(.plain)
                .onAppear {
                    isPulsingScale = true
                }
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
                    Text(appState.currentEndpoint.name)
                        .font(.system(size: 11, weight: .medium))
                        .lineLimit(1)
                    Text(statusTextWithPing)
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

    private var statusTextWithPing: String {
        switch appState.networkState {
        case .connectedRealityRelay:
            let pingPart = appState.pingMs > 0 ? " • \(appState.pingMs) ms" : ""
            return "Connected to \(appState.currentEndpoint.formattedAddress)\(pingPart)"
        case .connectedBleMeshFallback:
            return "Mesh Fallback Active"
        case .connecting:
            return "Connecting to \(appState.currentEndpoint.formattedAddress)..."
        case .offline:
            if appState.lastConnectionError != nil {
                return "Connection Failed (кликните)"
            }
            return "Offline"
        }
    }
}

struct ConversationRow: View {
    let conversation: ChatConversation

    var body: some View {
        HStack(spacing: 10) {
            // Avatar with Network Status Indicator
            ZStack(alignment: .bottomTrailing) {
                Circle()
                    .fill(LinearGradient(
                        colors: [Color.accentColor.opacity(0.8), Color.purple.opacity(0.8)],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    ))
                    .frame(width: 38, height: 38)
                    .overlay {
                        Text(String(conversation.name.prefix(1)))
                            .font(.system(size: 16, weight: .bold))
                            .foregroundColor(.white)
                    }

                // Network indicator dot
                Circle()
                    .fill(statusIndicatorColor(for: conversation.status))
                    .frame(width: 11, height: 11)
                    .overlay(Circle().stroke(Color(NSColor.windowBackgroundColor), lineWidth: 2))
            }

            VStack(alignment: .leading, spacing: 3) {
                HStack {
                    Text(conversation.name)
                        .font(.system(size: 13, weight: .semibold))
                        .lineLimit(1)
                    Spacer()
                    Text(conversation.lastTimestamp, style: .time)
                        .font(.system(size: 10))
                        .foregroundColor(.secondary)
                }

                Text(conversation.lastMessage)
                    .font(.system(size: 11))
                    .foregroundColor(.secondary)
                    .lineLimit(1)
            }
        }
        .padding(.vertical, 4)
    }

    private func statusIndicatorColor(for status: NetworkState) -> Color {
        switch status {
        case .connectedRealityRelay:
            return .green
        case .connectedBleMeshFallback:
            return .orange
        case .connecting:
            return .yellow
        case .offline:
            return .red
        }
    }
}
