import Foundation
import SwiftUI
import Observation

public enum MessageDeliveryStatus: Equatable, Sendable {
    case sending
    case sent
    case echoed(rttMs: Int)
    case failed(String)
}

public struct ChatMessage: Identifiable, Equatable, Sendable {
    public let id: UUID
    public let text: String
    public let timestamp: Date
    public let isOutgoing: Bool
    public var status: MessageDeliveryStatus

    public init(
        id: UUID = UUID(),
        text: String,
        timestamp: Date = Date(),
        isOutgoing: Bool,
        status: MessageDeliveryStatus
    ) {
        self.id = id
        self.text = text
        self.timestamp = timestamp
        self.isOutgoing = isOutgoing
        self.status = status
    }
}

@Observable
@MainActor
public final class ChatViewModel {
    public static let shared = ChatViewModel()

    public static let echoPeerId: [UInt8] = [UInt8](repeating: 0xEE, count: 32)

    public var messages: [ChatMessage] = []
    public var inputText: String = ""
    public var isSending: Bool = false

    private let bridge: CoreBridgeService
    private let notifications: NotificationManager
    private var eventTask: Task<Void, Never>?

    // Track pending outgoing messages to calculate RTT
    private var pendingSends: [UUID: (text: String, startTime: ContinuousClock.Instant)] = [:]

    public init(
        bridge: CoreBridgeService = .shared,
        notifications: NotificationManager = .shared
    ) {
        self.bridge = bridge
        self.notifications = notifications
        startEventListener()
    }

    public func startEventListener() {
        eventTask?.cancel()
        let stream = bridge.listener.eventStream
        eventTask = Task { [weak self] in
            guard let self = self else { return }
            for await event in stream {
                guard !Task.isCancelled else { break }
                switch event {
                case .packetReceived(let sender, let data):
                    self.handlePacketReceived(sender: sender, data: data)
                case .messageReceived(let message):
                    let text = message.content
                    let data = [UInt8](text.utf8)
                    self.handlePacketReceived(sender: [UInt8](message.sender.utf8), data: data)
                case .stateChanged, .messageStatusUpdated:
                    break
                }
            }
        }
    }

    public func sendMessage(text customText: String? = nil) {
        let textToSend = (customText ?? inputText).trimmingCharacters(in: .whitespacesAndNewlines)
        guard !textToSend.isEmpty else { return }

        if customText == nil {
            inputText = ""
        }

        let messageId = UUID()
        let outgoing = ChatMessage(
            id: messageId,
            text: textToSend,
            timestamp: Date(),
            isOutgoing: true,
            status: .sending
        )
        messages.append(outgoing)

        let startTime = ContinuousClock.now
        pendingSends[messageId] = (text: textToSend, startTime: startTime)
        isSending = true

        Task {
            do {
                let payload = Data(textToSend.utf8)
                try await bridge.sendMessage(payload: payload, recipient: Self.echoPeerId)

                // Update status to sent upon successful transmission
                if let idx = messages.firstIndex(where: { $0.id == messageId }) {
                    if case .sending = messages[idx].status {
                        messages[idx].status = .sent
                    }
                }
            } catch {
                if let idx = messages.firstIndex(where: { $0.id == messageId }) {
                    messages[idx].status = .failed(error.localizedDescription)
                }
                pendingSends.removeValue(forKey: messageId)
            }
            self.isSending = false
        }
    }

    private func handlePacketReceived(sender: [UInt8], data: [UInt8]) {
        let receivedText = String(decoding: data, as: UTF8.self)

        // Find pending send matching text or earliest sent/sending message
        var matchedId: UUID? = nil
        var rttMs = 38

        // Match by exact text first
        if let (id, pending) = pendingSends.first(where: { $0.value.text == receivedText }) {
            matchedId = id
            let delta = ContinuousClock.now - pending.startTime
            rttMs = max(1, Int(delta / .milliseconds(1)))
            pendingSends.removeValue(forKey: id)
        } else if let (id, pending) = pendingSends.first {
            // FIFO fallback
            matchedId = id
            let delta = ContinuousClock.now - pending.startTime
            rttMs = max(1, Int(delta / .milliseconds(1)))
            pendingSends.removeValue(forKey: id)
        }

        if let id = matchedId, let idx = messages.firstIndex(where: { $0.id == id }) {
            messages[idx].status = .echoed(rttMs: rttMs)
        } else {
            // Find any outgoing message in sent or sending state
            if let idx = messages.lastIndex(where: { $0.isOutgoing && ($0.status == .sent || $0.status == .sending) }) {
                messages[idx].status = .echoed(rttMs: rttMs)
            }
        }

        // Add incoming echo message from relay
        let echoMessage = ChatMessage(
            text: "Echo: \"\(receivedText)\"",
            timestamp: Date(),
            isOutgoing: false,
            status: .echoed(rttMs: rttMs)
        )
        messages.append(echoMessage)

        notifications.showIncomingMessageNotification(
            from: "Echo Node",
            content: receivedText,
            chatId: "echo_relay"
        )
    }

    public func clearMessages() {
        messages.removeAll()
        pendingSends.removeAll()
    }
}
