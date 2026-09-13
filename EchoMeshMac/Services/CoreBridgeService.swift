import Foundation
import Network
import os.log

/// Errors encountered by the core bridge service.
public enum CoreBridgeError: LocalizedError, Equatable, Sendable {
    case invalidPublicKey(String)
    case invalidEndpoint(String)
    case clientNotInitialized
    case connectionFailed(String)
    case handshakeTimeout(String)
    case handshakeUnexpectedEof(String)
    case noiseError(String)
    case notReady

    public static var notInitialized: CoreBridgeError { .clientNotInitialized }

    public var errorDescription: String? {
        switch self {
        case .invalidPublicKey(let msg):
            return "Invalid Public Key: \(msg)"
        case .invalidEndpoint(let msg):
            return "Invalid Endpoint: \(msg)"
        case .clientNotInitialized:
            return "EchoMesh Core Client is not initialized"
        case .connectionFailed(let msg):
            return "Connection Failed: \(msg)"
        case .handshakeTimeout(let msg):
            return "Handshake Timeout: \(msg)"
        case .handshakeUnexpectedEof(let msg):
            return "Handshake Unexpected EOF: \(msg)"
        case .noiseError(let msg):
            return "Noise Handshake Error: \(msg)"
        case .notReady:
            return "EchoMesh Core Client is not in transport state"
        }
    }
}

public struct HealthCheckError: LocalizedError, Equatable, Sendable {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var errorDescription: String? { message }
}

/// Unified event enum emitted by the Rust core engine.
public enum CoreEngineEvent: Sendable {
    case stateChanged(NetworkState)
    case messageReceived(MessageRecord)
    case messageStatusUpdated(messageId: String, status: DeliveryStatus)
    case packetReceived(sender: [UInt8], data: [UInt8])
}

/// Thread-safe event listener implementation conforming to UniFFI `CoreEventsListener`.
/// Dispatches callbacks across Swift Concurrency using `AsyncStream` and `NotificationCenter`.
public final class ClientEventListener: CoreEventsListener, @unchecked Sendable {
    private let eventContinuation: AsyncStream<CoreEngineEvent>.Continuation
    public let eventStream: AsyncStream<CoreEngineEvent>
    public var onStateChangeCallback: (@Sendable (NetworkState) -> Void)?

    public init() {
        var continuation: AsyncStream<CoreEngineEvent>.Continuation!
        self.eventStream = AsyncStream { cont in
            continuation = cont
        }
        self.eventContinuation = continuation
    }

    public func onStateChanged(state: NetworkState) {
        eventContinuation.yield(.stateChanged(state))
        onStateChangeCallback?(state)
        NotificationCenter.default.post(
            name: .echoMeshStateChanged,
            object: nil,
            userInfo: ["state": state]
        )
    }

    public func onMessageReceived(message: MessageRecord) {
        eventContinuation.yield(.messageReceived(message))
        NotificationCenter.default.post(
            name: .echoMeshMessageReceived,
            object: nil,
            userInfo: ["message": message]
        )
    }

    public func onMessageStatusUpdated(messageId: String, status: DeliveryStatus) {
        eventContinuation.yield(.messageStatusUpdated(messageId: messageId, status: status))
        NotificationCenter.default.post(
            name: .echoMeshMessageStatusUpdated,
            object: nil,
            userInfo: ["messageId": messageId, "status": status]
        )
    }

    public func onPacketReceived(sender: Data, data: Data) {
        let senderBytes = [UInt8](sender)
        let dataBytes = [UInt8](data)
        eventContinuation.yield(.packetReceived(sender: senderBytes, data: dataBytes))
        NotificationCenter.default.post(
            name: .echoMeshPacketReceived,
            object: nil,
            userInfo: ["sender": senderBytes, "data": dataBytes]
        )
    }

    deinit {
        eventContinuation.finish()
    }
}

public extension Notification.Name {
    static let echoMeshStateChanged = Notification.Name("echoMeshStateChanged")
    static let echoMeshMessageReceived = Notification.Name("echoMeshMessageReceived")
    static let echoMeshMessageStatusUpdated = Notification.Name("echoMeshMessageStatusUpdated")
    static let echoMeshPacketReceived = Notification.Name("echoMeshPacketReceived")
}

/// Swift Actor managing the lifecycle of the underlying Rust `EchoMeshClient` and Tokio runtime,
/// including automatic reconnect with exponential backoff.
public actor CoreBridgeService {
    public static let shared = CoreBridgeService()

    private var clientInstance: EchoMeshClient?
    public var client: EchoMeshClient? { clientInstance }
    public let listener: ClientEventListener
    public let storagePath: String

    private let systemLogger = os.Logger(subsystem: "com.echomesh.mac", category: "CoreBridge")

    // Reconnection and endpoint state
    private var activeEndpoint: RelayEndpoint?
    private var isManualDisconnect: Bool = false
    private var connectionTask: Task<Void, Never>?
    private var reconnectTask: Task<Void, Never>?
    private var reconnectAttempt: Int = 0
    private var currentConnectionState: NetworkState = .offline
    private var lastErrorMessage: String?

    public init(
        storagePath: String? = nil,
        listener: ClientEventListener = ClientEventListener()
    ) {
        self.listener = listener
        if let customPath = storagePath {
            self.storagePath = customPath
        } else {
            let appSupport = FileManager.default.urls(
                for: .applicationSupportDirectory,
                in: .userDomainMask
            ).first ?? URL(fileURLWithPath: NSTemporaryDirectory())
            self.storagePath = appSupport.appendingPathComponent("EchoMesh", isDirectory: true).path
        }

        listener.onStateChangeCallback = { [weak self] state in
            Task { [weak self] in
                await self?.handleStateTransition(state)
            }
        }
    }

    /// Records diagnostics without publishing raw FFI text, filesystem paths,
    /// endpoint data, peer identifiers, or stack frames to the unified system log.
    private func logFfiError(_ error: Error, context: String) {
        let rawErrorText = String(describing: error)
        systemLogger.error(
            "[CoreBridge] FFI exception in \(context, privacy: .private): \(rawErrorText, privacy: .private)"
        )
        self.lastErrorMessage = "\(context): operation failed"
    }

    /// Initializes the Rust client with persistent storage in Application Support/EchoMesh.
    public func start() throws {
        guard clientInstance == nil else { return }
        do {
            clientInstance = try EchoMeshClient(storagePath: storagePath, listener: listener)
        } catch {
            logFfiError(error, context: "start")
            throw error
        }
    }

    /// Connects to a relay given its address string and raw 32-byte public key.
    public func connect(relayAddress: String, relayPublicKey: [UInt8], secretTokenHex: String? = nil) throws {
        if clientInstance == nil {
            try start()
        }
        guard relayPublicKey.count == 32 else {
            let desc = "Expected 32 bytes, got \(relayPublicKey.count)"
            throw CoreBridgeError.invalidPublicKey(desc)
        }
        let initLog = "[CoreBridge] Initiating connection to \(relayAddress) with key: <32 bytes verified>"
        print(initLog)
        systemLogger.info("\(initLog, privacy: .private)")
        Task { @MainActor in
            NetworkLogService.shared.log(initLog, level: .info)
        }
        do {
            try clientInstance?.connect(relayAddress: relayAddress, relayPublicKey: Data(relayPublicKey), secretTokenHex: secretTokenHex)
        } catch let error as EchoMeshError {
            logFfiError(error, context: "connect")
            throw mapEchoMeshError(error)
        } catch {
            logFfiError(error, context: "connect")
            throw CoreBridgeError.connectionFailed(error.localizedDescription)
        }
    }

    /// Connects to a remote relay endpoint, decoding and validating configuration.
    public func connectToRelay(endpoint: RelayEndpoint) async throws {
        do {
            try endpoint.validateHost()
            try endpoint.validatePort()
        } catch {
            let desc = error.localizedDescription
            logFfiError(error, context: "endpoint validation")
            Task { @MainActor in
                NetworkLogService.shared.log("Invalid relay endpoint", level: .error)
            }
            throw CoreBridgeError.invalidEndpoint(desc)
        }

        let rawBase64Key = endpoint.publicKeyBase64
        let cleanedKey = rawBase64Key.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let keyData = Data(base64Encoded: cleanedKey), keyData.count == 32 else {
            let errString = "Неверный формат ключа: ожидается 32 байта Base64"
            self.lastErrorMessage = errString
            logFfiError(CoreBridgeError.invalidPublicKey(errString), context: "public key validation")
            Task { @MainActor in
                NetworkLogService.shared.log("Invalid relay public key", level: .error)
            }
            throw CoreBridgeError.invalidPublicKey(errString)
        }
        let keyBytes = [UInt8](keyData)

        self.isManualDisconnect = false
        self.activeEndpoint = endpoint
        self.reconnectTask?.cancel()
        self.reconnectTask = nil
        self.reconnectAttempt = 0
        self.lastErrorMessage = nil

        let address = endpoint.formattedAddress
        let initLog = "[CoreBridge] Initiating relay connection with verified 32-byte key"
        print(initLog)
        systemLogger.info("\(initLog, privacy: .public)")
        Task { @MainActor in
            NetworkLogService.shared.log(initLog, level: .info)
        }

        let rawToken = endpoint.secretTokenHex.trimmingCharacters(in: .whitespacesAndNewlines)
        let tokenParam: String? = rawToken.isEmpty ? nil : rawToken

        print("[CoreBridge] Starting relay connection session...")
        systemLogger.info("[CoreBridge] Starting relay connection session...")
        Task { @MainActor in
            NetworkLogService.shared.log("[CoreBridge] Starting relay connection session...", level: .info)
        }

        do {
            if clientInstance == nil {
                try start()
            }
            guard let client = clientInstance else {
                throw CoreBridgeError.clientNotInitialized
            }
            try client.connect(relayAddress: address, relayPublicKey: Data(keyBytes), secretTokenHex: tokenParam)
            print("[CoreBridge] Relay session established successfully")
            systemLogger.info("[CoreBridge] Relay session established successfully")
            Task { @MainActor in
                NetworkLogService.shared.log("[CoreBridge] Relay session established successfully", level: .info)
            }
        } catch let error as EchoMeshError {
            print("[CoreBridge] Relay session terminated with an error")
            logFfiError(error, context: "connectToRelay")
            let mapped = mapEchoMeshError(error)
            let errString = mapped.localizedDescription
            self.lastErrorMessage = errString
            Task { @MainActor in
                NetworkLogService.shared.log("[CoreBridge] Relay session terminated with an error", level: .error)
            }
            scheduleAutoReconnect()
            throw mapped
        } catch {
            print("[CoreBridge] Relay session terminated with an error")
            logFfiError(error, context: "connectToRelay")
            let errString = error.localizedDescription
            self.lastErrorMessage = errString
            Task { @MainActor in
                NetworkLogService.shared.log("[CoreBridge] Relay session terminated with an error", level: .error)
            }
            scheduleAutoReconnect()
            throw CoreBridgeError.connectionFailed(errString)
        }
    }

    /// Connects to a remote Reality Relay or local Mesh peer via raw URL and Data.
    public func connect(relayUrl: String, relayKey: Data, secretTokenHex: String? = nil) throws {
        if clientInstance == nil {
            try start()
        }
        guard relayKey.count == 32 else {
            let desc = "Expected 32 bytes, got \(relayKey.count)"
            throw CoreBridgeError.invalidPublicKey(desc)
        }
        let initLog = "[CoreBridge] Initiating relay connection with verified 32-byte key"
        print(initLog)
        systemLogger.info("\(initLog, privacy: .public)")
        Task { @MainActor in
            NetworkLogService.shared.log(initLog, level: .info)
        }
        do {
            try clientInstance?.connect(relayAddress: relayUrl, relayPublicKey: relayKey, secretTokenHex: secretTokenHex)
        } catch let error as EchoMeshError {
            logFfiError(error, context: "connect")
            throw mapEchoMeshError(error)
        } catch {
            logFfiError(error, context: "connect")
            throw CoreBridgeError.connectionFailed(error.localizedDescription)
        }
    }

    private func mapEchoMeshError(_ error: EchoMeshError) -> CoreBridgeError {
        switch error {
        case .InvalidKeyLength(let expected, let actual):
            return .invalidPublicKey("Expected \(expected) bytes, got \(actual)")
        case .HandshakeTimeout(let msg):
            return .handshakeTimeout(msg)
        case .HandshakeUnexpectedEof(let msg):
            return .handshakeUnexpectedEof(msg)
        case .NoiseError(let msg):
            return .noiseError(msg)
        case .ConnectionError(let msg):
            return .connectionFailed(msg)
        case .RuntimeError(let msg):
            return .connectionFailed("Runtime error: \(msg)")
        case .StorageError(let msg):
            return .connectionFailed("Storage error: \(msg)")
        case .NotReady:
            return .notReady
        }
    }

    public var connectionState: ConnectionUIState {
        switch currentConnectionState {
        case .connectedRealityRelay, .connectedBleMeshFallback:
            return .connected
        case .connecting:
            return .connecting
        case .offline:
            return .disconnected
        }
    }

    public func sendMessage(payload: Data, recipient: [UInt8]) async throws {
        guard let client = self.clientInstance else {
            systemLogger.error("[CoreBridge] sendMessage failed: clientInstance is nil")
            throw CoreBridgeError.notInitialized
        }
        guard connectionState == .connected else {
            systemLogger.error("[CoreBridge] sendMessage failed: not connected")
            throw CoreBridgeError.notReady
        }
        let byteCount = payload.count
        let logMsg = "[CoreBridge] Sending \(byteCount) encrypted bytes"
        print(logMsg)
        systemLogger.info("\(logMsg, privacy: .public)")
        Task { @MainActor in
            NetworkLogService.shared.log(logMsg, level: .info)
        }
        try await Task.detached {
            try client.sendPacket(recipient: recipient, data: [UInt8](payload))
        }.value
    }

    public func addContact(peerIdHex: String, name: String) throws {
        if clientInstance == nil {
            try start()
        }
        guard let client = clientInstance else {
            throw CoreBridgeError.clientNotInitialized
        }
        do {
            try client.addContact(peerIdHex: peerIdHex, name: name)
        } catch {
            logFfiError(error, context: "addContact")
            throw error
        }
    }

    public func getContacts() throws -> [Contact] {
        if clientInstance == nil {
            try start()
        }
        guard let client = clientInstance else {
            throw CoreBridgeError.clientNotInitialized
        }
        do {
            return try client.getContacts()
        } catch {
            logFfiError(error, context: "getContacts")
            throw error
        }
    }

    public func getConversations() throws -> [ConversationSummary] {
        if clientInstance == nil {
            try start()
        }
        guard let client = clientInstance else {
            throw CoreBridgeError.clientNotInitialized
        }
        do {
            return try client.getConversations()
        } catch {
            logFfiError(error, context: "getConversations")
            throw error
        }
    }

    public func getMessages(peerIdHex: String, limit: UInt32 = 100) throws -> [MessageRecord] {
        if clientInstance == nil {
            try start()
        }
        guard let client = clientInstance else {
            throw CoreBridgeError.clientNotInitialized
        }
        do {
            return try client.getMessages(peerIdHex: peerIdHex, limit: limit)
        } catch {
            logFfiError(error, context: "getMessages")
            throw error
        }
    }

    public func sendChatMessage(recipientPeerIdHex: String, text: String) throws -> MessageRecord {
        if clientInstance == nil {
            try start()
        }
        guard let client = clientInstance else {
            throw CoreBridgeError.clientNotInitialized
        }
        do {
            return try client.sendChatMessage(recipientPeerIdHex: recipientPeerIdHex, text: text)
        } catch {
            logFfiError(error, context: "sendChatMessage")
            throw error
        }
    }

    public func sendMessage(to: String, text: String) throws -> MessagePayload {
        if clientInstance == nil {
            try start()
        }
        guard let client = clientInstance else {
            throw EchoMeshError.RuntimeError("Client initialization failed")
        }
        do {
            return try client.sendMessage(to: to, text: text)
        } catch {
            logFfiError(error, context: "sendMessage")
            throw error
        }
    }

    public func disconnect() throws {
        isManualDisconnect = true
        connectionTask?.cancel()
        connectionTask = nil
        reconnectTask?.cancel()
        reconnectTask = nil
        reconnectAttempt = 0
        lastErrorMessage = nil

        do {
            try clientInstance?.disconnect()
        } catch {
            logFfiError(error, context: "disconnect")
            throw error
        }
        Task { @MainActor in
            NetworkLogService.shared.log("Disconnected manually from relay.", level: .info)
        }
    }

    public func shutdown() {
        isManualDisconnect = true
        connectionTask?.cancel()
        connectionTask = nil
        reconnectTask?.cancel()
        reconnectTask = nil

        do {
            try clientInstance?.shutdown()
        } catch {
            logFfiError(error, context: "shutdown")
            print("[CoreBridgeService] Error during shutdown")
        }
        clientInstance = nil
    }

    public func currentState() -> NetworkState {
        return clientInstance?.currentState() ?? .offline
    }

    public func pingMs() -> UInt32 {
        return clientInstance?.pingMs() ?? 0
    }

    public func getActiveEndpoint() -> RelayEndpoint? {
        return activeEndpoint
    }

    public func getLastErrorMessage() -> String? {
        return lastErrorMessage
    }

    private func handleStateTransition(_ state: NetworkState) {
        currentConnectionState = state

        Task { @MainActor in
            let desc: String
            switch state {
            case .offline: desc = "Network state: Offline"
            case .connecting: desc = "Network state: Connecting / Handshake in progress"
            case .connectedRealityRelay: desc = "Network state: Connected to Reality Relay"
            case .connectedBleMeshFallback: desc = "Network state: Connected via BLE Mesh Fallback"
            }
            NetworkLogService.shared.log(desc, level: state == .offline ? .warning : .info)
        }

        switch state {
        case .connectedRealityRelay, .connectedBleMeshFallback:
            reconnectAttempt = 0
            reconnectTask?.cancel()
            reconnectTask = nil
            lastErrorMessage = nil

        case .offline:
            if !isManualDisconnect && activeEndpoint != nil {
                scheduleAutoReconnect()
            }

        case .connecting:
            break
        }
    }

    private func scheduleAutoReconnect() {
        guard !isManualDisconnect, activeEndpoint != nil else { return }
        guard reconnectTask == nil else { return }

        let delaySeconds: UInt64
        if reconnectAttempt == 0 {
            delaySeconds = 1
        } else if reconnectAttempt < 5 {
            delaySeconds = min(30, 1 << reconnectAttempt)
        } else {
            delaySeconds = 30
        }
        reconnectAttempt += 1

        let attemptNum = reconnectAttempt
        Task { @MainActor in
            NetworkLogService.shared.log(
                "Connection lost. Reconnecting in \(delaySeconds)s (attempt \(attemptNum))...",
                level: .warning
            )
        }

        reconnectTask = Task { [weak self] in
            do {
                try await Task.sleep(nanoseconds: delaySeconds * 1_000_000_000)
            } catch {
                return
            }

            guard let self = self else { return }
            await self.executeAutoReconnect()
        }
    }

    private func executeAutoReconnect() async {
        reconnectTask = nil
        guard !isManualDisconnect, let endpoint = activeEndpoint else { return }

        do {
            let keyBytes = try endpoint.decodePublicKey()
            guard keyBytes.count == 32 else { return }
            if clientInstance == nil {
                try start()
            }
            let initLog = "[CoreBridge] Initiating relay reconnection with verified key"
            print(initLog)
            systemLogger.info("\(initLog, privacy: .public)")
            let rawToken = endpoint.secretTokenHex.trimmingCharacters(in: .whitespacesAndNewlines)
            let tokenParam: String? = rawToken.isEmpty ? nil : rawToken
            try clientInstance?.connect(relayAddress: endpoint.formattedAddress, relayPublicKey: Data(keyBytes), secretTokenHex: tokenParam)
            print("[CoreBridge] Reconnection session established successfully")
            systemLogger.info("[CoreBridge] Reconnection session established successfully")
            Task { @MainActor in
                NetworkLogService.shared.log("[CoreBridge] Reconnection session established successfully", level: .info)
            }
        } catch {
            print("[CoreBridge] Reconnection session terminated with an error")
            logFfiError(error, context: "executeAutoReconnect")
            let errString = error.localizedDescription
            self.lastErrorMessage = errString
            Task { @MainActor in
                NetworkLogService.shared.log("[CoreBridge] Reconnection session terminated with an error", level: .error)
            }
            scheduleAutoReconnect()
        }
    }

    public static func performHealthCheck(endpoint: RelayEndpoint) async -> Result<UInt32, HealthCheckError> {
        do {
            try endpoint.validateHost()
            try endpoint.validatePort()
        } catch {
            return .failure(HealthCheckError(error.localizedDescription))
        }

        if !endpoint.publicKeyBase64.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            do {
                _ = try endpoint.decodePublicKey()
            } catch {
                return .failure(HealthCheckError("Invalid Public Key: \(error.localizedDescription)"))
            }
        }

        guard let nwPort = NWEndpoint.Port(rawValue: endpoint.port) else {
            return .failure(HealthCheckError("Invalid port value: \(endpoint.port)"))
        }

        let nwHost = NWEndpoint.Host(endpoint.host.trimmingCharacters(in: CharacterSet(charactersIn: "[]")))
        let parameters = NWParameters.tcp
        parameters.prohibitExpensivePaths = false

        let connection = NWConnection(host: nwHost, port: nwPort, using: parameters)
        final class HealthCheckTracker: @unchecked Sendable {
            private let lock = NSLock()
            private var completed = false
            func claim() -> Bool {
                lock.lock()
                defer { lock.unlock() }
                if completed { return false }
                completed = true
                return true
            }
        }

        let tracker = HealthCheckTracker()
        let startTime = DispatchTime.now()

        return await withCheckedContinuation { continuation in
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    if tracker.claim() {
                        let endTime = DispatchTime.now()
                        let nanos = endTime.uptimeNanoseconds - startTime.uptimeNanoseconds
                        let ms = max(1, UInt32(nanos / 1_000_000))
                        connection.cancel()
                        continuation.resume(returning: .success(ms))
                    }

                case .failed(let error):
                    if tracker.claim() {
                        connection.cancel()
                        continuation.resume(returning: .failure(HealthCheckError("Connection failed: \(error.localizedDescription)")))
                    }

                case .waiting(let error):
                    if tracker.claim() {
                        connection.cancel()
                        continuation.resume(returning: .failure(HealthCheckError("Connection waiting/unreachable: \(error.localizedDescription)")))
                    }

                case .cancelled:
                    if tracker.claim() {
                        continuation.resume(returning: .failure(HealthCheckError("Connection cancelled")))
                    }

                default:
                    break
                }
            }

            connection.start(queue: .global())

            Task {
                try? await Task.sleep(nanoseconds: 4_000_000_000)
                if tracker.claim() {
                    connection.cancel()
                    continuation.resume(returning: .failure(HealthCheckError("Connection timed out after 4000ms")))
                }
            }
        }
    }
}

extension EchoMeshClient {
    public func sendPacket(recipient: [UInt8], data: [UInt8]) throws {
        try self.sendPacket(recipient: Data(recipient), data: Data(data))
    }
}