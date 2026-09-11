import SwiftUI

public struct ChatDetailView: View {
    @Bindable var chatVM: ChatViewModel
    var appState: AppState

    public init(chatVM: ChatViewModel, appState: AppState) {
        self.chatVM = chatVM
        self.appState = appState
    }

    private var isConnected: Bool {
        appState.networkState == .connectedRealityRelay || appState.networkState == .connectedBleMeshFallback
    }

    public var body: some View {
        if let conversation = chatVM.selectedConversation {
            VStack(spacing: 0) {
                // Conversation Header
                HStack(spacing: 12) {
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 6) {
                            Text(conversation.name)
                                .font(.system(size: 15, weight: .bold))

                            // Relay / Mesh Badge
                            Text(peerBadgeTitle(conversation.status))
                                .font(.system(size: 10, weight: .semibold))
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(peerBadgeColor(conversation.status).opacity(0.15))
                                .foregroundColor(peerBadgeColor(conversation.status))
                                .cornerRadius(4)
                        }

                        // Identity Key snippet
                        HStack(spacing: 4) {
                            Image(systemName: "key.horizontal")
                                .font(.system(size: 10))
                                .foregroundColor(.secondary)
                            Text(conversation.publicKeyBase58)
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundColor(.secondary)
                                .lineLimit(1)
                            Button(action: {
                                NSPasteboard.general.clearContents()
                                NSPasteboard.general.setString(conversation.publicKeyBase58, forType: .string)
                            }) {
                                Image(systemName: "doc.on.doc")
                                    .font(.system(size: 9))
                                    .foregroundColor(.secondary)
                            }
                            .buttonStyle(.plain)
                            .help("Copy peer Identity Key")
                        }
                    }

                    Spacer()

                    // Direct connection details
                    VStack(alignment: .trailing, spacing: 2) {
                        Text("Wire: 1420B MTU")
                            .font(.system(size: 10, weight: .medium, design: .monospaced))
                            .foregroundColor(.secondary)
                        Text("Zero-Knowledge E2EE")
                            .font(.system(size: 10))
                            .foregroundColor(.secondary)
                    }
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
                .background(.ultraThinMaterial)

                Divider()

                // Messages ScrollView
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(spacing: 10) {
                            ForEach(chatVM.currentMessages, id: \.id) { message in
                                MessageBubbleView(message: message)
                                    .id(message.id)
                            }
                        }
                        .padding(16)
                    }
                    .onChange(of: chatVM.currentMessages.count) { _, _ in
                        if let lastMessage = chatVM.currentMessages.last {
                            withAnimation(.easeOut(duration: 0.2)) {
                                proxy.scrollTo(lastMessage.id, anchor: .bottom)
                            }
                        }
                    }
                }

                // Disconnection Warning Banner if not connected
                if !isConnected {
                    HStack(spacing: 8) {
                        Image(systemName: "wifi.slash")
                            .font(.caption)
                            .foregroundColor(.orange)
                        Text("Ожидание подключения к релею...")
                            .font(.system(size: 11, weight: .medium))
                            .foregroundColor(.secondary)
                        Spacer()
                        Button("Подключить") {
                            appState.connectCurrentRelay()
                        }
                        .font(.system(size: 11, weight: .semibold))
                        .buttonStyle(.plain)
                        .foregroundColor(.accentColor)
                    }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 8)
                    .background(Color.orange.opacity(0.1))
                }

                Divider()

                // Input Composer Bar
                HStack(alignment: .bottom, spacing: 10) {
                    TextField(
                        isConnected ? "Send an end-to-end encrypted message..." : "Ожидание подключения к релею...",
                        text: $chatVM.inputText,
                        axis: .vertical
                    )
                    .textFieldStyle(.plain)
                    .lineLimit(1...4)
                    .padding(10)
                    .background(Color(NSColor.controlBackgroundColor).opacity(isConnected ? 0.7 : 0.3))
                    .cornerRadius(10)
                    .disabled(!isConnected)
                    .onSubmit {
                        if isConnected {
                            chatVM.sendMessage()
                        }
                    }

                    Button(action: {
                        if isConnected {
                            chatVM.sendMessage()
                        }
                    }) {
                        Image(systemName: "arrow.up.circle.fill")
                            .font(.system(size: 28))
                            .foregroundColor(!isConnected || chatVM.inputText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? .secondary : .accentColor)
                    }
                    .buttonStyle(.plain)
                    .disabled(!isConnected || chatVM.inputText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    .keyboardShortcut(.return, modifiers: [])
                    .help(isConnected ? "Send Message (Return)" : "Ожидание подключения к релею...")
                }
                .padding(12)
                .background(.ultraThinMaterial)
            }
        } else {
            VStack(spacing: 12) {
                Image(systemName: "bubble.left.and.bubble.right")
                    .font(.system(size: 48))
                    .foregroundColor(.secondary)
                Text("Select a conversation")
                    .font(.headline)
                    .foregroundColor(.secondary)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private func peerBadgeTitle(_ status: NetworkState) -> String {
        switch status {
        case .connectedRealityRelay:
            return "Reality Relay"
        case .connectedBleMeshFallback:
            return "BLE Mesh"
        case .connecting:
            return "Connecting"
        case .offline:
            return "Offline"
        }
    }

    private func peerBadgeColor(_ status: NetworkState) -> Color {
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

struct MessageBubbleView: View {
    let message: MessagePayload

    var isFromMe: Bool {
        message.sender == "me"
    }

    var body: some View {
        HStack {
            if isFromMe { Spacer(minLength: 40) }

            VStack(alignment: isFromMe ? .trailing : .leading, spacing: 4) {
                Text(message.content)
                    .font(.system(size: 13))
                    .foregroundColor(isFromMe ? .white : .primary)
                    .textSelection(.enabled)

                HStack(spacing: 4) {
                    Text(formatTimestamp(message.timestamp))
                        .font(.system(size: 10))
                        .foregroundColor(isFromMe ? .white.opacity(0.7) : .secondary)

                    if isFromMe {
                        deliveryStatusIcon(message.status)
                    }
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(
                isFromMe
                ? AnyShapeStyle(LinearGradient(colors: [Color.accentColor, Color.accentColor.opacity(0.85)], startPoint: .top, endPoint: .bottom))
                : AnyShapeStyle(Color(NSColor.controlBackgroundColor))
            )
            .cornerRadius(14)
            .overlay(
                RoundedRectangle(cornerRadius: 14)
                    .stroke(isFromMe ? Color.clear : Color(NSColor.separatorColor).opacity(0.3), lineWidth: 0.5)
            )

            if !isFromMe { Spacer(minLength: 40) }
        }
    }

    @ViewBuilder
    private func deliveryStatusIcon(_ status: DeliveryStatus) -> some View {
        switch status {
        case .sent:
            Image(systemName: "checkmark")
                .font(.system(size: 9, weight: .bold))
                .foregroundColor(.white.opacity(0.8))
                .help("Sent to Relay")
        case .relayed:
            Image(systemName: "checkmark.circle")
                .font(.system(size: 9, weight: .bold))
                .foregroundColor(.white.opacity(0.9))
                .help("Relayed via Zero-Knowledge Wire")
        case .delivered:
            Image(systemName: "checkmark.circle.fill")
                .font(.system(size: 9, weight: .bold))
                .foregroundColor(.green.opacity(0.95))
                .help("Delivered & Acknowledged")
        case .failed:
            Image(systemName: "exclamationmark.circle.fill")
                .font(.system(size: 9, weight: .bold))
                .foregroundColor(.red)
                .help("Delivery Failed")
        }
    }

    private func formatTimestamp(_ timestampMs: UInt64) -> String {
        let date = Date(timeIntervalSince1970: TimeInterval(timestampMs) / 1000.0)
        let formatter = DateFormatter()
        formatter.timeStyle = .short
        return formatter.string(from: date)
    }
}
