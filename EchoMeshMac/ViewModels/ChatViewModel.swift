import Foundation
import SwiftUI
import Observation

public struct ChatConversation: Identifiable, Hashable, Sendable {
    public let id: String
    public var name: String
    public var publicKeyBase58: String
    public var status: NetworkState
    public var lastMessage: String
    public var lastTimestamp: Date
    public var unreadCount: Int

    public init(
        id: String,
        name: String,
        publicKeyBase58: String,
        status: NetworkState,
        lastMessage: String,
        lastTimestamp: Date = Date(),
        unreadCount: Int = 0
    ) {
        self.id = id
        self.name = name
        self.publicKeyBase58 = publicKeyBase58
        self.status = status
        self.lastMessage = lastMessage
        self.lastTimestamp = lastTimestamp
        self.unreadCount = unreadCount
    }
}

@Observable
@MainActor
public final class ChatViewModel {
    public static let shared = ChatViewModel()

    public var conversations: [ChatConversation] = [
        ChatConversation(
            id: "peer_alice",
            name: "Alice (Reality Node)",
            publicKeyBase58: "7YtGfC3Lq9M2XvH1nP4sR8wD6eKbTaJ5",
            status: .connectedRealityRelay,
            lastMessage: "Relay tunnel active via Tokyo Reality endpoint",
            lastTimestamp: Date().addingTimeInterval(-120)
        ),
        ChatConversation(
            id: "peer_bob",
            name: "Bob (Mesh Peer)",
            publicKeyBase58: "4KjLmN9P2vW3rT5xY7zB1qC8sE0fGhJ4",
            status: .connectedBleMeshFallback,
            lastMessage: "BLE mesh routing hopped through 2 local nodes",
            lastTimestamp: Date().addingTimeInterval(-900)
        ),
        ChatConversation(
            id: "peer_charlie",
            name: "Charlie (Offline)",
            publicKeyBase58: "9XvW2rT5yZ1qB8sE0fGhJ4kLmN3p7YtG",
            status: .offline,
            lastMessage: "Last seen 2 hours ago",
            lastTimestamp: Date().addingTimeInterval(-7200)
        )
    ]

    public var selectedConversationId: String? = "peer_alice"
    public var messages: [String: [MessagePayload]] = [:]
    public var inputText: String = ""
    public var isSending: Bool = false

    private let bridge: CoreBridgeService
    private let notifications: NotificationManager
    private var eventTask: Task<Void, Never>?

    public init(
        bridge: CoreBridgeService = .shared,
        notifications: NotificationManager = .shared
    ) {
        self.bridge = bridge
        self.notifications = notifications
        seedInitialMessages()
        startEventListener()
    }

    public var selectedConversation: ChatConversation? {
        conversations.first { $0.id == selectedConversationId }
    }

    public var currentMessages: [MessagePayload] {
        guard let id = selectedConversationId else { return [] }
        return messages[id] ?? []
    }

    private func seedInitialMessages() {
        let now = Date().timeIntervalSince1970 * 1000
        messages["peer_alice"] = [
            MessagePayload(
                id: "seed_1",
                sender: "peer_alice",
                recipient: "me",
                content: "Zero-knowledge Reality handshake established.",
                timestamp: UInt64(now - 60000),
                status: .delivered
            ),
            MessagePayload(
                id: "seed_2",
                sender: "me",
                recipient: "peer_alice",
                content: "All wire traffic is padded to 1420-byte MTU frames.",
                timestamp: UInt64(now - 30000),
                status: .delivered
            )
        ]

        messages["peer_bob"] = [
            MessagePayload(
                id: "seed_3",
                sender: "peer_bob",
                recipient: "me",
                content: "Direct mesh fallback ping is ~48ms.",
                timestamp: UInt64(now - 120000),
                status: .delivered
            )
        ]
    }

    public func startEventListener() {
        eventTask?.cancel()
        let stream = bridge.listener.eventStream
        eventTask = Task { [weak self] in
            guard let self = self else { return }
            for await event in stream {
                guard !Task.isCancelled else { break }
                switch event {
                case .messageReceived(let message):
                    self.handleIncomingMessage(message)
                case .messageStatusUpdated(let messageId, let status):
                    self.handleStatusUpdated(messageId: messageId, status: status)
                case .stateChanged:
                    break
                }
            }
        }
    }

    public func sendMessage() {
        guard let conversationId = selectedConversationId, !inputText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return
        }

        let textToSend = inputText.trimmingCharacters(in: .whitespacesAndNewlines)
        inputText = ""
        isSending = true

        Task {
            do {
                let sentPayload = try await bridge.sendMessage(to: conversationId, text: textToSend)
                appendMessage(sentPayload, to: conversationId)
                updateLastMessage(textToSend, for: conversationId)
            } catch {
                let localErrorPayload = MessagePayload(
                    id: UUID().uuidString,
                    sender: "me",
                    recipient: conversationId,
                    content: textToSend,
                    timestamp: UInt64(Date().timeIntervalSince1970 * 1000),
                    status: .failed
                )
                appendMessage(localErrorPayload, to: conversationId)
            }
            self.isSending = false
        }
    }

    private func appendMessage(_ message: MessagePayload, to conversationId: String) {
        if messages[conversationId] == nil {
            messages[conversationId] = []
        }
        messages[conversationId]?.append(message)
    }

    private func updateLastMessage(_ text: String, for conversationId: String) {
        if let idx = conversations.firstIndex(where: { $0.id == conversationId }) {
            conversations[idx].lastMessage = text
            conversations[idx].lastTimestamp = Date()
        }
    }

    private func handleIncomingMessage(_ message: MessagePayload) {
        let conversationId = message.sender
        appendMessage(message, to: conversationId)
        updateLastMessage(message.content, for: conversationId)

        let senderName = conversations.first { $0.id == conversationId }?.name ?? conversationId
        notifications.showIncomingMessageNotification(
            from: senderName,
            content: message.content,
            chatId: conversationId
        )
    }

    private func handleStatusUpdated(messageId: String, status: DeliveryStatus) {
        for (convId, msgList) in messages {
            if let idx = msgList.firstIndex(where: { $0.id == messageId }) {
                var updated = msgList[idx]
                updated.status = status
                messages[convId]?[idx] = updated
                break
            }
        }
    }
}
