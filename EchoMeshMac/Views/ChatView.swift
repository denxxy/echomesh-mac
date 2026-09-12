import SwiftUI

public struct ChatView: View {
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
        VStack(spacing: 0) {
            // Header
            HStack(spacing: 12) {
                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 8) {
                        Text("Echo Relay Node")
                            .font(.system(size: 15, weight: .bold))

                        // Protocol Badge
                        Text("1420b Frame Masking • ChaCha20-Poly1305")
                            .font(.system(size: 10, weight: .semibold, design: .monospaced))
                            .padding(.horizontal, 7)
                            .padding(.vertical, 2.5)
                            .background(Color.blue.opacity(0.12))
                            .foregroundColor(.blue)
                            .cornerRadius(4)
                    }

                    Text("77.81.5.109:8443 • Stateless Wire Echo Mode")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(.secondary)
                }

                Spacer()

                // Trash Button to clear chat history
                Button(action: {
                    withAnimation(.easeOut(duration: 0.2)) {
                        chatVM.clearMessages()
                    }
                }) {
                    Image(systemName: "trash")
                        .font(.system(size: 13))
                        .foregroundColor(.secondary)
                        .padding(6)
                        .background(Color(NSColor.controlBackgroundColor).opacity(0.6))
                        .clipShape(Circle())
                }
                .buttonStyle(.plain)
                .help("Очистить историю диалога (перезапуск демо)")
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
            .background(.ultraThinMaterial)

            Divider()

            // Messages ScrollView
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(spacing: 12) {
                        if chatVM.messages.isEmpty {
                            VStack(spacing: 10) {
                                Image(systemName: "network")
                                    .font(.system(size: 38))
                                    .foregroundColor(.secondary.opacity(0.6))
                                Text("Нажмите быстрый чип внизу или введите текст для проверки эхо-ответа релея")
                                    .font(.system(size: 12))
                                    .foregroundColor(.secondary)
                                    .multilineTextAlignment(.center)
                            }
                            .frame(maxWidth: .infinity)
                            .padding(.top, 60)
                        } else {
                            ForEach(chatVM.messages) { message in
                                MessageBubbleView(message: message)
                                    .id(message.id)
                            }
                        }
                    }
                    .padding(16)
                }
                .onChange(of: chatVM.messages.count) { _, _ in
                    if let lastMessage = chatVM.messages.last {
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
                    Text("Ожидание соединения с релеем...")
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

            // Input Composer & Quick Action Chips
            VStack(spacing: 8) {
                // Input Bar
                HStack(alignment: .bottom, spacing: 10) {
                    TextField(
                        isConnected ? "Введите сообщение для релея..." : "Ожидание соединения с релеем...",
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
                    .help(isConnected ? "Отправить сообщение (Return)" : "Ожидание соединения с релеем...")
                }

                // Quick Action Chips
                HStack(spacing: 8) {
                    // [Ping]
                    Button(action: {
                        if isConnected {
                            chatVM.sendMessage(text: "Ping")
                        }
                    }) {
                        HStack(spacing: 4) {
                            Image(systemName: "bolt.fill")
                                .font(.system(size: 10))
                            Text("Ping")
                                .font(.system(size: 11, weight: .medium))
                        }
                        .padding(.horizontal, 10)
                        .padding(.vertical, 5)
                        .background(Color.blue.opacity(isConnected ? 0.15 : 0.05))
                        .foregroundColor(isConnected ? .blue : .secondary)
                        .cornerRadius(6)
                    }
                    .buttonStyle(.plain)
                    .disabled(!isConnected)
                    .help("Отправить Ping")

                    // [Noise Payload]
                    Button(action: {
                        if isConnected {
                            chatVM.sendMessage(text: "Noise Payload")
                        }
                    }) {
                        HStack(spacing: 4) {
                            Image(systemName: "lock.shield.fill")
                                .font(.system(size: 10))
                            Text("Noise Payload")
                                .font(.system(size: 11, weight: .medium))
                        }
                        .padding(.horizontal, 10)
                        .padding(.vertical, 5)
                        .background(Color.purple.opacity(isConnected ? 0.15 : 0.05))
                        .foregroundColor(isConnected ? .purple : .secondary)
                        .cornerRadius(6)
                    }
                    .buttonStyle(.plain)
                    .disabled(!isConnected)
                    .help("Отправить Noise Payload")

                    // [1420b Frame Test]
                    Button(action: {
                        if isConnected {
                            let test1300 = String(repeating: "ECHO_1420_PAD_", count: 92) + String(repeating: "X", count: 12)
                            chatVM.sendMessage(text: test1300)
                        }
                    }) {
                        HStack(spacing: 4) {
                            Image(systemName: "doc.plaintext.fill")
                                .font(.system(size: 10))
                            Text("1420b Frame Test")
                                .font(.system(size: 11, weight: .medium))
                        }
                        .padding(.horizontal, 10)
                        .padding(.vertical, 5)
                        .background(Color.green.opacity(isConnected ? 0.15 : 0.05))
                        .foregroundColor(isConnected ? .green : .secondary)
                        .cornerRadius(6)
                    }
                    .buttonStyle(.plain)
                    .disabled(!isConnected)
                    .help("Отправить тестовую строку длиной 1300 байт для проверки 1420b Wire Frame")

                    Spacer()
                }
            }
            .padding(12)
            .background(.ultraThinMaterial)
        }
    }
}

public struct MessageBubbleView: View {
    public let message: ChatMessage

    public var body: some View {
        HStack {
            if message.isOutgoing {
                Spacer(minLength: 40)
            }

            VStack(alignment: message.isOutgoing ? .trailing : .leading, spacing: 4) {
                if !message.isOutgoing {
                    HStack(spacing: 4) {
                        Image(systemName: "server.rack")
                            .font(.system(size: 9))
                        Text("Echo Node")
                            .font(.system(size: 10, weight: .bold))
                    }
                    .foregroundColor(.purple)
                }

                Text(message.text)
                    .font(.system(size: 13))
                    .foregroundColor(message.isOutgoing ? .white : .primary)
                    .textSelection(.enabled)

                HStack(spacing: 4) {
                    Text(message.timestamp, style: .time)
                        .font(.system(size: 10))
                        .foregroundColor(message.isOutgoing ? .white.opacity(0.7) : .secondary)

                    if message.isOutgoing {
                        deliveryStatusView(message.status)
                    }
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(
                message.isOutgoing
                ? AnyShapeStyle(LinearGradient(colors: [Color.blue, Color.blue.opacity(0.85)], startPoint: .top, endPoint: .bottom))
                : AnyShapeStyle(Color(NSColor.controlBackgroundColor))
            )
            .cornerRadius(14)
            .overlay(
                RoundedRectangle(cornerRadius: 14)
                    .stroke(
                        message.isOutgoing
                            ? Color.clear
                            : Color.purple.opacity(0.3),
                        lineWidth: message.isOutgoing ? 0 : 1
                    )
            )

            if !message.isOutgoing {
                Spacer(minLength: 40)
            }
        }
    }

    @ViewBuilder
    private func deliveryStatusView(_ status: MessageDeliveryStatus) -> some View {
        switch status {
        case .sending:
            Image(systemName: "clock")
                .font(.system(size: 9))
                .foregroundColor(.white.opacity(0.8))
                .help("Sending frame...")

        case .sent:
            Image(systemName: "checkmark")
                .font(.system(size: 9, weight: .bold))
                .foregroundColor(.white.opacity(0.8))
                .help("Sent to Relay")

        case .echoed(let rttMs):
            HStack(spacing: 2) {
                // Double checkmarks
                Image(systemName: "checkmark")
                    .font(.system(size: 8, weight: .bold))
                Image(systemName: "checkmark")
                    .font(.system(size: 8, weight: .bold))
                    .offset(x: -3)

                Text("\(rttMs) ms")
                    .font(.system(size: 9, weight: .bold, design: .monospaced))
                    .padding(.horizontal, 4)
                    .padding(.vertical, 1)
                    .background(Color.black.opacity(0.25))
                    .cornerRadius(3)
            }
            .foregroundColor(.green.opacity(0.95))
            .help("Echoed back from relay in \(rttMs)ms")

        case .failed(let reason):
            Image(systemName: "exclamationmark.circle.fill")
                .font(.system(size: 9, weight: .bold))
                .foregroundColor(.red)
                .help("Delivery failed: \(reason)")
        }
    }
}
