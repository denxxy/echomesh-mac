import Foundation
import SwiftUI
import Observation

/// Main application state coordinating network lifecycle, identity, and user configuration.
@Observable
@MainActor
public final class AppState {
    public static let shared = AppState()

    public var networkState: NetworkState = .offline
    public var pingMs: UInt32 = 0
    public var identity: IdentityKeyPair? = nil
    public var isSettingsPresented: Bool = false
    public var errorMessage: String? = nil
    public var lastConnectionError: String? = nil
    public var isErrorPopoverPresented: Bool = false

    public let configManager: RelayConfigManager
    public let logService: NetworkLogService
    private let bridge: CoreBridgeService
    private let keychain: KeychainService
    private var eventTask: Task<Void, Never>?

    public init(
        bridge: CoreBridgeService = .shared,
        keychain: KeychainService = .shared,
        configManager: RelayConfigManager? = nil,
        logService: NetworkLogService? = nil
    ) {
        self.bridge = bridge
        self.keychain = keychain
        self.configManager = configManager ?? .shared
        self.logService = logService ?? .shared

        loadIdentity()
        startEventListener()

        // Attempt initial connection if active endpoint has a configured key
        if !self.configManager.activeEndpoint.publicKeyBase64.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            connectCurrentRelay()
        }
    }

    /// Active relay endpoint currently configured.
    public var currentEndpoint: RelayEndpoint {
        configManager.activeEndpoint
    }

    public func loadIdentity() {
        do {
            self.identity = try keychain.getOrCreateIdentity()
            logService.log("Identity key loaded successfully from Apple Keychain.", level: .info)
        } catch {
            let msg = "Failed to access Keychain identity: \(error.localizedDescription)"
            self.errorMessage = msg
            logService.log(msg, level: .error)
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
                case .stateChanged(let state):
                    self.networkState = state
                    let currentPing = await self.bridge.pingMs()
                    self.pingMs = currentPing
                    if state == .connectedRealityRelay || state == .connectedBleMeshFallback {
                        self.lastConnectionError = nil
                    }

                case .messageReceived, .messageStatusUpdated:
                    break
                }
            }
        }
    }

    /// Connects to the currently selected active endpoint.
    public func connectCurrentRelay() {
        connectToRelay(currentEndpoint)
    }

    /// Connects to a specific relay endpoint.
    public func connectToRelay(_ endpoint: RelayEndpoint) {
        configManager.setActive(id: endpoint.id)
        networkState = .connecting
        lastConnectionError = nil

        Task {
            do {
                try await bridge.connectToRelay(endpoint: endpoint)
                let currentPing = await bridge.pingMs()
                self.pingMs = currentPing
                self.lastConnectionError = nil
            } catch {
                let desc = error.localizedDescription
                self.networkState = .offline
                self.lastConnectionError = desc
                self.errorMessage = "Connection error: \(desc)"
            }
        }
    }

    /// Switches the active relay and initiates connection.
    public func switchEndpoint(_ endpoint: RelayEndpoint) {
        configManager.setActive(id: endpoint.id)
        connectToRelay(endpoint)
    }

    /// Disconnects manually from the current relay.
    public func disconnect() {
        Task {
            do {
                try await bridge.disconnect()
                self.networkState = .offline
                self.pingMs = 0
                self.lastConnectionError = nil
            } catch {
                self.errorMessage = "Failed to disconnect: \(error.localizedDescription)"
            }
        }
    }

    /// Tests connection and measures latency (RTT in ms) to a given endpoint.
    public func healthCheck(endpoint: RelayEndpoint) async -> Result<UInt32, HealthCheckError> {
        logService.log("Initiating health check for \(endpoint.formattedAddress)...", level: .info)
        let result = await CoreBridgeService.performHealthCheck(endpoint: endpoint)
        switch result {
        case .success(let ms):
            logService.log("Health check for \(endpoint.formattedAddress) succeeded: RTT = \(ms) ms.", level: .info)
        case .failure(let err):
            logService.log("Health check for \(endpoint.formattedAddress) failed: \(err.message)", level: .warning)
        }
        return result
    }

    /// Status label displayed in UI.
    public func statusDescription() -> String {
        switch networkState {
        case .offline:
            if let err = lastConnectionError {
                return "Error: \(err)"
            }
            return "Offline"
        case .connecting:
            return "Connecting to \(currentEndpoint.formattedAddress)..."
        case .connectedRealityRelay:
            return "Connected (\(currentEndpoint.formattedAddress))"
        case .connectedBleMeshFallback:
            return "Mesh Fallback Active"
        }
    }

    /// Status indicator color.
    public var statusColor: Color {
        switch networkState {
        case .offline:
            return .red
        case .connecting:
            return .yellow
        case .connectedRealityRelay:
            return .green
        case .connectedBleMeshFallback:
            return .orange
        }
    }

    /// Whether the status indicator should pulse (active connected state).
    public var isPulsing: Bool {
        networkState == .connectedRealityRelay
    }
}
