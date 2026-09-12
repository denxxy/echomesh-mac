import Foundation
import SwiftUI
import Observation

@Observable
@MainActor
public final class ChatListViewModel {
    public static let shared = ChatListViewModel()

    public var conversations: [ConversationSummary] = []
    public var selectedPeerIdHex: String? = nil
    public var searchText: String = ""
    public var isNewContactSheetPresented: Bool = false
    public var isLoading: Bool = false
    public var errorMessage: String? = nil

    private let bridge: CoreBridgeService
    private var eventTask: Task<Void, Never>?

    public init(bridge: CoreBridgeService = .shared) {
        self.bridge = bridge
        startListening()
        loadConversations()
    }

    public var filteredConversations: [ConversationSummary] {
        let trimmed = searchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if trimmed.isEmpty {
            return conversations
        }
        return conversations.filter { conv in
            conv.displayTitle.lowercased().contains(trimmed) ||
            conv.peerIdHex.lowercased().contains(trimmed) ||
            (conv.lastMessage?.lowercased().contains(trimmed) ?? false)
        }
    }

    public func startListening() {
        eventTask?.cancel()
        let stream = bridge.listener.eventStream
        eventTask = Task { [weak self] in
            guard let self = self else { return }
            for await event in stream {
                guard !Task.isCancelled else { break }
                switch event {
                case .messageReceived, .messageStatusUpdated:
                    Task { @MainActor [weak self] in
                        self?.loadConversations()
                    }
                case .stateChanged(let state):
                    if state == .connectedRealityRelay || state == .connectedBleMeshFallback {
                        Task { @MainActor [weak self] in
                            self?.loadConversations()
                        }
                    }
                case .packetReceived:
                    break
                }
            }
        }
    }

    public func loadConversations() {
        Task {
            do {
                let convs = try await bridge.getConversations()
                self.conversations = convs
                // Default selection to first conversation if none selected
                if self.selectedPeerIdHex == nil, let first = convs.first {
                    self.selectedPeerIdHex = first.peerIdHex
                }
            } catch {
                self.errorMessage = error.localizedDescription
            }
        }
    }

    public func selectConversation(_ conv: ConversationSummary) {
        self.selectedPeerIdHex = conv.peerIdHex
    }

    public func addContact(key: String, name: String) async throws {
        let validation = KeyValidator.validate(key)
        guard validation.isValid, let hex = validation.hexString else {
            throw CoreBridgeError.invalidPublicKey(validation.errorMessage ?? "Неверный ключ")
        }

        let contactName = name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            ? "0x\(hex.prefix(4))...\(hex.suffix(4))"
            : name.trimmingCharacters(in: .whitespacesAndNewlines)

        try await bridge.addContact(peerIdHex: hex, name: contactName)
        self.selectedPeerIdHex = hex
        loadConversations()
    }
}
