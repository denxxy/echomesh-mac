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
    case messageReceived(MessagePayload)
    case messageStatusUpdated(messageId: String, status: DeliveryStatus)
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

    public func onMessageReceived(message: MessagePayload) {
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

    deinit {
        eventContinuation.finish()
    }
}

public extension Notification.Name {
    static let echoMeshStateChanged = Notification.Name("echoMeshStateChanged")
    static let echoMeshMessageReceived = Notification.Name("echoMeshMessageReceived")
    static let echoMeshMessageStatusUpdated = Notification.Name("echoMeshMessageStatusUpdated")
}

/// Swift Actor managing the lifecycle of the underlying Rust `EchoMeshClient` and Tokio runtime,
/// including automatic reconnect with exponential backoff.
public actor CoreBridgeService {
    public static let shared = CoreBridgeService()

    private var client: EchoMeshClient?
    public let listener: ClientEventListener
    public let storagePath: String

    // Reconnection and endpoint state
    private var activeEndpoint: RelayEndpoint?
    private var isManualDisconnect: Bool = false
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

        // Hook up listener state transition callback to handle auto-reconnect
        listener.onStateChangeCallback = { [weak self] state in
            Task { [weak self] in
                await self?.handleStateTransition(state)
            }
        }
    }

    /// Initializes the Rust client with persistent storage in Application Support/EchoMesh.
    public func start() throws {
        guard client == nil else { return }
        client = try EchoMeshClient(storagePath: storagePath, listener: listener)
    }

    /// Connects to a relay given its address string and raw 32-byte public key.
    /// Connects to a relay given its address string and raw 32-byte public key.
    public func connect(relayAddress: String, relayPublicKey: [UInt8]) throws {
        if client == nil {
            try start()
        }
        guard relayPublicKey.count == 32 else {
            throw CoreBridgeError.invalidPublicKey("Expected 32 bytes, got \(relayPublicKey.count)")
        }
        do {
            try client?.connect(relayAddress: relayAddress, relayPublicKey: Data(relayPublicKey))
        } catch let error as EchoMeshError {
            throw mapEchoMeshError(error)
        } catch {
            throw CoreBridgeError.connectionFailed(error.localizedDescription)
        }
    }

    /// Connects to a remote relay endpoint, decoding and validating configuration.
    public func connectToRelay(endpoint: RelayEndpoint) async throws {
        // Validate host and port
        do {
            try endpoint.validateHost()
            try endpoint.validatePort()
        } catch {
            let desc = error.localizedDescription
            Task { @MainActor in
                NetworkLogService.shared.log("Invalid endpoint \(endpoint.formattedAddress): \(desc)", level: .error)
            }
            throw CoreBridgeError.invalidEndpoint(desc)
        }

        // Validate and decode 32-byte public key
        let keyBytes: [UInt8]
        do {
            keyBytes = try endpoint.decodePublicKey()
        } catch {
            let desc = error.localizedDescription
            Task { @MainActor in
                NetworkLogService.shared.log("Invalid public key for \(endpoint.formattedAddress): \(desc)", level: .error)
            }
            throw CoreBridgeError.invalidPublicKey(desc)
        }

        guard keyBytes.count == 32 else {
            let desc = "Expected 32 bytes, got \(keyBytes.count)"
            Task { @MainActor in
                NetworkLogService.shared.log("Invalid public key length for \(endpoint.formattedAddress): \(desc)", level: .error)
            }
            throw CoreBridgeError.invalidPublicKey(desc)
        }

        self.isManualDisconnect = false
        self.activeEndpoint = endpoint
        self.reconnectTask?.cancel()
        self.reconnectTask = nil
        self.reconnectAttempt = 0
        self.lastErrorMessage = nil

        let address = endpoint.formattedAddress
        Task { @MainActor in
            NetworkLogService.shared.log("Connecting to relay \(address)...", level: .info)
        }

        do {
            if client == nil {
                try start()
            }
            try client?.connect(relayAddress: address, relayPublicKey: Data(keyBytes))
        } catch let error as EchoMeshError {
            let mapped = mapEchoMeshError(error)
            let errString = mapped.localizedDescription ?? error.localizedDescription
            self.lastErrorMessage = errString
            Task { @MainActor in
                NetworkLogService.shared.log("Failed connection to \(address): \(errString)", level: .error)
            }
            scheduleAutoReconnect()
            throw mapped
        } catch {
            let errString = error.localizedDescription
            self.lastErrorMessage = errString
            Task { @MainActor in
                NetworkLogService.shared.log("Failed connection to \(address): \(errString)", level: .error)
            }
            scheduleAutoReconnect()
            throw CoreBridgeError.connectionFailed(errString)
        }
    }

    /// Connects to a remote Reality Relay or local Mesh peer via raw URL and Data.
    public func connect(relayUrl: String, relayKey: Data) throws {
        if client == nil {
            try start()
        }
        guard relayKey.count == 32 else {
            throw CoreBridgeError.invalidPublicKey("Expected 32 bytes, got \(relayKey.count)")
        }
        do {
            try client?.connect(relayAddress: relayUrl, relayPublicKey: relayKey)
        } catch let error as EchoMeshError {
            throw mapEchoMeshError(error)
        } catch {
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
        }
    }

    /// Sends an encrypted message to the target recipient.
    public func sendMessage(to: String, text: String) throws -> MessagePayload {
        if client == nil {
            try start()
        }
        guard let client = client else {
            throw EchoMeshError.RuntimeError("Client initialization failed")
        }
        return try client.sendMessage(to: to, text: text)
    }

    /// Disconnects from the current relay/mesh, canceling auto-reconnection.
    public func disconnect() throws {
        isManualDisconnect = true
        reconnectTask?.cancel()
        reconnectTask = nil
        reconnectAttempt = 0
        lastErrorMessage = nil

        try client?.disconnect()
        Task { @MainActor in
            NetworkLogService.shared.log("Disconnected manually from relay.", level: .info)
        }
    }

    /// Gracefully stops the Tokio runtime and releases resources upon app exit.
    public func shutdown() {
        isManualDisconnect = true
        reconnectTask?.cancel()
        reconnectTask = nil

        do {
            try client?.shutdown()
        } catch {
            print("[CoreBridgeService] Error during shutdown: \(error)")
        }
        client = nil
    }

    /// Current connection state of the Rust engine.
    public func currentState() -> NetworkState {
        return client?.currentState() ?? .offline
    }

    /// Current measured latency in milliseconds.
    public func pingMs() -> UInt32 {
        return client?.pingMs() ?? 0
    }

    /// Returns the active relay endpoint being used.
    public func getActiveEndpoint() -> RelayEndpoint? {
        return activeEndpoint
    }

    /// Returns the last connection error message, if any.
    public func getLastErrorMessage() -> String? {
        return lastErrorMessage
    }

    /// Internal handler invoked on network state transitions from the core engine.
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

    /// Schedules an auto-reconnection attempt with exponential backoff (1s, 2s, 4s, ..., max 30s).
    private func scheduleAutoReconnect() {
        guard !isManualDisconnect, let endpoint = activeEndpoint else { return }
        guard reconnectTask == nil else { return }

        // Exponential backoff: min(30, 1 << attempt) seconds
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
        let targetAddress = endpoint.formattedAddress

        Task { @MainActor in
            NetworkLogService.shared.log(
                "Connection lost. Reconnecting to \(targetAddress) in \(delaySeconds)s (attempt \(attemptNum))...",
                level: .warning
            )
        }

        reconnectTask = Task { [weak self] in
            do {
                try await Task.sleep(nanoseconds: delaySeconds * 1_000_000_000)
            } catch {
                return // Task was cancelled
            }

            guard let self = self else { return }
            await self.executeAutoReconnect()
        }
    }

    /// Executes the pending reconnection attempt.
    private func executeAutoReconnect() async {
        reconnectTask = nil
        guard !isManualDisconnect, let endpoint = activeEndpoint else { return }

        do {
            let keyBytes = try endpoint.decodePublicKey()
            guard keyBytes.count == 32 else { return }
            if client == nil {
                try start()
            }
            try client?.connect(relayAddress: endpoint.formattedAddress, relayPublicKey: Data(keyBytes))
        } catch {
            let errString = error.localizedDescription
            self.lastErrorMessage = errString
            scheduleAutoReconnect()
        }
    }

    /// Performs an asynchronous health check (TCP handshake/ping) to verify endpoint reachability
    /// and measure round-trip time (RTT in ms).
    public static func performHealthCheck(endpoint: RelayEndpoint) async -> Result<UInt32, HealthCheckError> {
        // Validate host and port first
        do {
            try endpoint.validateHost()
            try endpoint.validatePort()
        } catch {
            return .failure(HealthCheckError(error.localizedDescription))
        }

        // Validate public key if present
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
