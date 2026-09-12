import Foundation
import SwiftUI
import Observation

@Observable
@MainActor
public final class ChatViewModel {
    public static let shared = ChatViewModel()

    public static let echoPeerIdHex = String(repeating: "ee", count: 32)
    public static let echoPeerId: [UInt8] = [UInt8](repeating: 0xEE, count: 32)

    public var currentPeerIdHex: String = echoPeerIdHex
    public var currentTitle: String = "Echo Relay Node"
    public var messages: [MessageRecord] = []
    public var inputText: String = ""
    public var isSending: Bool = false
    public var rttMsMap: [String: Int] = [:]

    private let bridge: CoreBridgeService
    private let notifications: NotificationManager
    private var eventTask: Task<Void, Never>?

    // Track pending sends for RTT calculation
    private var pendingSendTimes: [String: ContinuousClock.Instant] = [:]

    public init(
        bridge: CoreBridgeService = .shared,
        notifications: NotificationManager = .shared
    ) {
        self.bridge = bridge
        self.notifications = notifications
        startEventListener()
        loadMessages(for: currentPeerIdHex, title: currentTitle)
    }

    public func loadMessages(for peerIdHex: String, title: String? = nil) {
        self.currentPeerIdHex = peerIdHex
        if let title = title {
            self.currentTitle = title
        }

        Task {
            do {
                let records = try await bridge.getMessages(peerIdHex: peerIdHex, limit: 100)
                self.messages = records
            } catch {
                print("[ChatViewModel] Failed to load messages: \(error)")
            }
        }
    }

    public func startEventListener() {
        eventTask?.cancel()
        let stream = bridge.listener.eventStream
        eventTask = Task { [weak self] in
            guard let self = self else { return }
            for await event in stream {
                guard !Task.isCancelled else { break }
                switch event {
                case .messageReceived(let record):
                    self.handleIncomingRecord(record)

                case .messageStatusUpdated(let messageId, let status):
                    self.handleStatusUpdated(messageId: messageId, status: status)

                case .packetReceived(let sender, _):
                    // Fallback for packet events
                    let senderHex = Data(sender).hexString
                    if self.currentPeerIdHex.lowercased().hasPrefix(senderHex.lowercased()) ||
                       senderHex.lowercased().hasPrefix(self.currentPeerIdHex.lowercased()) {
                        // Handled via messageReceived from core
                    }

                case .stateChanged:
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

        let tempId = "msg_\(UInt64(Date().timeIntervalSince1970 * 1000))"
        let peerData = Data(hexString: currentPeerIdHex) ?? Data(repeating: 0xEE, count: 32)
        let optimisticRecord = MessageRecord(
            id: tempId,
            conversationPeerId: peerData,
            senderPeerId: Data(repeating: 0, count: 32),
            text: textToSend,
            timestamp: UInt64(Date().timeIntervalSince1970 * 1000),
            isOutgoing: true,
            status: 0 // Sending
        )
        messages.append(optimisticRecord)

        let startTime = ContinuousClock.now
        pendingSendTimes[tempId] = startTime
        isSending = true

        let targetPeerHex = currentPeerIdHex
        Task {
            do {
                let sentRecord = try await bridge.sendChatMessage(
                    recipientPeerIdHex: targetPeerHex,
                    text: textToSend
                )

                // Update optimistic record with confirmed record from core
                if let idx = messages.firstIndex(where: { $0.id == tempId }) {
                    messages[idx] = sentRecord
                    pendingSendTimes[sentRecord.id] = startTime
                    pendingSendTimes.removeValue(forKey: tempId)
                }
            } catch {
                if let idx = messages.firstIndex(where: { $0.id == tempId }) {
                    messages[idx].status = 2 // Failed
                }
                pendingSendTimes.removeValue(forKey: tempId)
            }
            self.isSending = false
        }
    }

    private func handleIncomingRecord(_ record: MessageRecord) {
        let convHex = record.conversationPeerIdHex.lowercased()
        let currentHex = currentPeerIdHex.lowercased()

        // Match either full 32 bytes or 16-byte session prefix
        let isCurrentConv = convHex == currentHex ||
            (convHex.count >= 32 && currentHex.count >= 32 && convHex.prefix(32) == currentHex.prefix(32))

        if isCurrentConv {
            // Check if already in messages
            if !messages.contains(where: { $0.id == record.id }) {
                messages.append(record)

                // Calculate RTT if this was an echo response to a pending send
                if let (pendingId, startTime) = pendingSendTimes.first {
                    let delta = ContinuousClock.now - startTime
                    let ms = max(1, Int(delta / .milliseconds(1)))
                    rttMsMap[record.id] = ms
                    rttMsMap[pendingId] = ms
                    pendingSendTimes.removeValue(forKey: pendingId)

                    // Update outgoing message status to 1 (Delivered / Echoed)
                    if let outIdx = messages.firstIndex(where: { $0.id == pendingId }) {
                        messages[outIdx].status = 1
                    }
                }
            }
        }

        if !record.isOutgoing {
            notifications.showIncomingMessageNotification(
                from: record.isEchoSender ? "Echo Relay Node" : currentTitle,
                content: record.text,
                chatId: record.conversationPeerIdHex
            )
        }
    }

    private func handleStatusUpdated(messageId: String, status: DeliveryStatus) {
        if let idx = messages.firstIndex(where: { $0.id == messageId }) {
            switch status {
            case .sent: messages[idx].status = 1
            case .delivered, .relayed: messages[idx].status = 1
            case .failed: messages[idx].status = 2
            }
        }
    }

    public func clearMessages() {
        messages.removeAll()
        pendingSendTimes.removeAll()
        rttMsMap.removeAll()
    }
}

// Helper init for Data from Hex string
private extension Data {
    init?(hexString: String) {
        let clean = hexString.trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "0x"))
        var data = Data()
        var temp = ""
        for char in clean {
            temp.append(char)
            if temp.count == 2 {
                guard let byte = UInt8(temp, radix: 16) else { return nil }
                data.append(byte)
                temp = ""
            }
        }
        self = data
    }
}
