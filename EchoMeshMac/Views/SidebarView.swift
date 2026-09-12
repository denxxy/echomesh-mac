import SwiftUI

public struct SidebarView: View {
    @Bindable var chatListVM: ChatListViewModel
    @Bindable var chatVM: ChatViewModel
    @Bindable var appState: AppState

    @State private var isErrorPopoverPresented: Bool = false
    @State private var isPulsingScale: Bool = false

    public init(chatListVM: ChatListViewModel, chatVM: ChatViewModel, appState: AppState) {
        self.chatListVM = chatListVM
        self.chatVM = chatVM
        self.appState = appState
    }

    private var isConnected: Bool {
        appState.networkState == .connectedRealityRelay || appState.networkState == .connectedBleMeshFallback
    }

    public var body: some View {
        VStack(spacing: 0) {
            // Header Bar: "ДИАЛОГИ" + New Chat "+" Button
            HStack {
                Text("ДИАЛОГИ")
                    .font(.system(size: 11, weight: .bold))
                    .foregroundColor(.secondary)

                Spacer()

                Button(action: {
                    chatListVM.isNewContactSheetPresented = true
                }) {
                    Image(systemName: "plus.circle.fill")
                        .font(.system(size: 15))
                        .foregroundColor(.accentColor)
                }
                .buttonStyle(.plain)
                .help("Добавить новый контакт / диалог")
            }
            .padding(.horizontal, 14)
            .padding(.top, 14)
            .padding(.bottom, 8)

            // Search Bar
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass")
                    .font(.system(size: 11))
                    .foregroundColor(.secondary)
                TextField("Поиск...", text: $chatListVM.searchText)
                    .textFieldStyle(.plain)
                    .font(.system(size: 12))
                if !chatListVM.searchText.isEmpty {
                    Button(action: { chatListVM.searchText = "" }) {
                        Image(systemName: "xmark.circle.fill")
                            .font(.system(size: 11))
                            .foregroundColor(.secondary)
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 5)
            .background(Color(NSColor.controlBackgroundColor).opacity(0.5))
            .cornerRadius(8)
            .padding(.horizontal, 12)
            .padding(.bottom, 8)

            Divider()

            // Conversations List
            ScrollView {
                LazyVStack(spacing: 4) {
                    if chatListVM.filteredConversations.isEmpty {
                        VStack(spacing: 8) {
                            Image(systemName: "person.2.slash")
                                .font(.system(size: 28))
                                .foregroundColor(.secondary.opacity(0.6))
                            Text("Нет диалогов")
                                .font(.system(size: 12, weight: .medium))
                                .foregroundColor(.secondary)
                            Button("Добавить контакт") {
                                chatListVM.isNewContactSheetPresented = true
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.small)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.top, 40)
                    } else {
                        ForEach(chatListVM.filteredConversations) { conv in
                            conversationRow(conv)
                        }
                    }
                }
                .padding(.vertical, 6)
                .padding(.horizontal, 8)
            }

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
        .sheet(isPresented: $chatListVM.isNewContactSheetPresented) {
            NewContactSheet(chatListVM: chatListVM)
        }
        .onAppear {
            isPulsingScale = true
        }
    }

    @ViewBuilder
    private func conversationRow(_ conv: ConversationSummary) -> some View {
        let isSelected = chatListVM.selectedPeerIdHex == conv.peerIdHex

        Button(action: {
            chatListVM.selectConversation(conv)
            chatVM.loadMessages(for: conv.peerIdHex, title: conv.displayTitle)
        }) {
            HStack(spacing: 10) {
                // Avatar
                ZStack(alignment: .bottomTrailing) {
                    if conv.isEchoNode {
                        Circle()
                            .fill(
                                LinearGradient(
                                    colors: [Color.blue.opacity(0.85), Color.purple.opacity(0.85)],
                                    startPoint: .topLeading,
                                    endPoint: .bottomTrailing
                                )
                            )
                            .frame(width: 38, height: 38)
                            .overlay {
                                Image(systemName: "antenna.radiowaves.left.and.right")
                                    .font(.system(size: 16, weight: .semibold))
                                    .foregroundColor(.white)
                            }
                    } else {
                        Circle()
                            .fill(
                                LinearGradient(
                                    colors: [Color.teal.opacity(0.8), Color.indigo.opacity(0.8)],
                                    startPoint: .topLeading,
                                    endPoint: .bottomTrailing
                                )
                            )
                            .frame(width: 38, height: 38)
                            .overlay {
                                Text(conv.initials)
                                    .font(.system(size: 13, weight: .bold))
                                    .foregroundColor(.white)
                            }
                    }

                    // Online indicator on Echo Node
                    if conv.isEchoNode {
                        ZStack {
                            if isConnected {
                                Circle()
                                    .fill(Color.green.opacity(isPulsingScale ? 0.35 : 0.0))
                                    .frame(width: 14, height: 14)
                                    .scaleEffect(isPulsingScale ? 1.4 : 0.8)
                                    .animation(
                                        .easeInOut(duration: 1.2).repeatForever(autoreverses: true),
                                        value: isPulsingScale
                                    )
                            }

                            Circle()
                                .fill(isConnected ? Color.green : Color.red)
                                .frame(width: 9, height: 9)
                                .overlay(Circle().stroke(Color(NSColor.windowBackgroundColor), lineWidth: 1.5))
                        }
                        .frame(width: 12, height: 12)
                        .offset(x: 2, y: 2)
                    }
                }

                // Title + Last Message Preview
                VStack(alignment: .leading, spacing: 3) {
                    HStack {
                        Text(conv.displayTitle)
                            .font(.system(size: 13, weight: isSelected ? .bold : .medium))
                            .foregroundColor(.primary)
                            .lineLimit(1)

                        Spacer()

                        if !conv.formattedTime.isEmpty {
                            Text(conv.formattedTime)
                                .font(.system(size: 10))
                                .foregroundColor(.secondary)
                        }
                    }

                    HStack {
                        Text(conv.lastMessage ?? (conv.isEchoNode ? "Stateless Wire Echo Mode" : "Нет сообщений"))
                            .font(.system(size: 11))
                            .foregroundColor(isSelected ? .primary.opacity(0.85) : .secondary)
                            .lineLimit(1)

                        Spacer()

                        if conv.unreadCount > 0 {
                            Text("\(conv.unreadCount)")
                                .font(.system(size: 9, weight: .bold))
                                .padding(.horizontal, 5)
                                .padding(.vertical, 2)
                                .background(Color.accentColor)
                                .foregroundColor(.white)
                                .clipShape(Capsule())
                        }
                    }
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 8)
            .background(
                RoundedRectangle(cornerRadius: 10)
                    .fill(isSelected ? Color.accentColor.opacity(0.16) : Color.clear)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 10)
                    .stroke(isSelected ? Color.accentColor.opacity(0.35) : Color.clear, lineWidth: 1)
            )
        }
        .buttonStyle(.plain)
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
