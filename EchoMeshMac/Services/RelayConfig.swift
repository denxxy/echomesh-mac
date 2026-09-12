import Foundation
import Observation

/// Errors related to relay endpoint validation and configuration.
public enum RelayConfigError: LocalizedError, Equatable, Sendable {
    case invalidHost(String)
    case invalidPort(UInt16)
    case emptyPublicKey
    case invalidBase64
    case invalidKeyLength(expected: Int, actual: Int)

    public var errorDescription: String? {
        switch self {
        case .invalidHost(let host):
            return "Invalid host or IP address: '\(host)'"
        case .invalidPort(let port):
            return "Invalid port: \(port). Port must be between 1 and 65535."
        case .emptyPublicKey:
            return "Public key cannot be empty."
        case .invalidBase64:
            return "Public key is not a valid Base64 encoded string."
        case .invalidKeyLength(let expected, let actual):
            return "Invalid public key length: expected \(expected) bytes, got \(actual) bytes."
        }
    }
}

/// Configuration model representing a remote EchoMesh relay endpoint.
public struct RelayEndpoint: Codable, Identifiable, Hashable, Sendable {
    public var id: UUID
    public var name: String
    public var host: String
    public var port: UInt16
    public var publicKeyBase64: String
    public var secretTokenHex: String = "" // Новое поле токена маскировки
    public var isDefault: Bool

    enum CodingKeys: String, CodingKey {
        case id, name, host, port, publicKeyBase64, secretTokenHex, isDefault
    }

    public init(
        id: UUID = UUID(),
        name: String,
        host: String,
        port: UInt16 = 8443,
        publicKeyBase64: String = "",
        secretTokenHex: String = "",
        isDefault: Bool = false
    ) {
        self.id = id
        self.name = name
        self.host = host
        self.port = port
        self.publicKeyBase64 = publicKeyBase64
        self.secretTokenHex = secretTokenHex
        self.isDefault = isDefault
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.id = try container.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        self.name = try container.decode(String.self, forKey: .name)
        self.host = try container.decode(String.self, forKey: .host)
        self.port = try container.decode(UInt16.self, forKey: .port)
        self.publicKeyBase64 = try container.decodeIfPresent(String.self, forKey: .publicKeyBase64) ?? ""
        self.secretTokenHex = try container.decodeIfPresent(String.self, forKey: .secretTokenHex) ?? ""
        self.isDefault = try container.decodeIfPresent(Bool.self, forKey: .isDefault) ?? false
    }

    /// Formatted address string in the format "host:port" (or "[ipv6]:port" for raw IPv6).
    public var formattedAddress: String {
        let trimmedHost = host.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmedHost.contains(":") && !trimmedHost.hasPrefix("[") && !trimmedHost.hasSuffix("]") {
            return "[\(trimmedHost)]:\(port)"
        }
        return "\(trimmedHost):\(port)"
    }

    /// Decodes the Base64 public key into a 32-byte array.
    /// Throws `RelayConfigError` if not valid Base64 or if length is not exactly 32 bytes.
    public func decodePublicKey() throws -> [UInt8] {
        let trimmed = publicKeyBase64.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw RelayConfigError.emptyPublicKey
        }

        guard let data = Data(base64Encoded: trimmed) else {
            throw RelayConfigError.invalidBase64
        }

        guard data.count == 32 else {
            throw RelayConfigError.invalidKeyLength(expected: 32, actual: data.count)
        }

        return [UInt8](data)
    }

    /// Validates the host or IP address format.
    public func validateHost() throws {
        let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw RelayConfigError.invalidHost(host)
        }

        // Check for valid IPv4
        var sin = sockaddr_in()
        if inet_pton(AF_INET, trimmed, &sin.sin_addr) == 1 {
            return
        }

        // Check for valid IPv6
        var sin6 = sockaddr_in6()
        let strippedIpv6 = trimmed.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        if inet_pton(AF_INET6, strippedIpv6, &sin6.sin6_addr) == 1 {
            return
        }

        // Check domain / hostname format
        let hostRegex = #"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$|^localhost$"#
        if trimmed.range(of: hostRegex, options: .regularExpression) != nil {
            return
        }

        // Allow internal/local single-label hostnames if alphanumeric (must start and end with alphanumeric)
        let singleLabelRegex = #"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"#
        if trimmed.range(of: singleLabelRegex, options: .regularExpression) != nil {
            return
        }

        throw RelayConfigError.invalidHost(host)
    }

    /// Validates the port range (1...65535).
    public func validatePort() throws {
        guard port >= 1 else {
            throw RelayConfigError.invalidPort(port)
        }
    }

    /// Comprehensive validation of host, port, and (optionally) the public key if present.
    public func validate(requirePublicKey: Bool = false) throws {
        try validateHost()
        try validatePort()
        if requirePublicKey || !publicKeyBase64.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            _ = try decodePublicKey()
        }
    }
}

/// Thread-safe configuration manager persisting relay endpoints in JSON format.
@Observable
@MainActor
public final class RelayConfigManager: Sendable {
    public static let shared = RelayConfigManager()

    public private(set) var endpoints: [RelayEndpoint] = []
    public private(set) var activeEndpointId: UUID?

    private let storageURL: URL

    /// Default primary relay node specified by the EchoMesh architecture.
    public static let defaultEndpoint = RelayEndpoint(
        name: "Primary Relay",
        host: "77.81.5.109",
        port: 8443,
        publicKeyBase64: "oZvg53goRI3fNUZz5VwK6XzFI9KIkduWu6gYZsms1gY=",
        isDefault: true
    )

    public init(storageURL: URL? = nil) {
        if let customURL = storageURL {
            self.storageURL = customURL
        } else {
            let appSupport = FileManager.default.urls(
                for: .applicationSupportDirectory,
                in: .userDomainMask
            ).first ?? URL(fileURLWithPath: NSTemporaryDirectory())
            let echoMeshDir = appSupport.appendingPathComponent("EchoMesh", isDirectory: true)
            self.storageURL = echoMeshDir.appendingPathComponent("relays.json")
        }
        load()
    }

    /// Currently active endpoint for connection.
    public var activeEndpoint: RelayEndpoint {
        if let id = activeEndpointId, let found = endpoints.first(where: { $0.id == id }) {
            return found
        }
        if let def = endpoints.first(where: { $0.isDefault }) {
            return def
        }
        return endpoints.first ?? Self.defaultEndpoint
    }

    /// Loads endpoints from disk or seeds with the default node on first run.
    public func load() {
        let parentDir = storageURL.deletingLastPathComponent()
        if !FileManager.default.fileExists(atPath: parentDir.path) {
            try? FileManager.default.createDirectory(at: parentDir, withIntermediateDirectories: true)
        }

        guard FileManager.default.fileExists(atPath: storageURL.path),
              let data = try? Data(contentsOf: storageURL),
              let decoded = try? JSONDecoder().decode([RelayEndpoint].self, from: data),
              !decoded.isEmpty else {
            // First run or empty file: seed default relay
            self.endpoints = [Self.defaultEndpoint]
            self.activeEndpointId = Self.defaultEndpoint.id
            save()
            return
        }

        self.endpoints = decoded
        // Ensure default relay has verified key if it was saved empty
        for i in self.endpoints.indices {
            if self.endpoints[i].host == "77.81.5.109" && self.endpoints[i].publicKeyBase64.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                self.endpoints[i].publicKeyBase64 = "oZvg53goRI3fNUZz5VwK6XzFI9KIkduWu6gYZsms1gY="
            }
        }
        if let defaultNode = self.endpoints.first(where: { $0.isDefault }) {
            self.activeEndpointId = defaultNode.id
        } else {
            self.activeEndpointId = self.endpoints.first?.id
        }
    }

    /// Saves the current list of endpoints to disk atomically.
    public func save() {
        let parentDir = storageURL.deletingLastPathComponent()
        if !FileManager.default.fileExists(atPath: parentDir.path) {
            try? FileManager.default.createDirectory(at: parentDir, withIntermediateDirectories: true)
        }

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(endpoints) else { return }
        try? data.write(to: storageURL, options: .atomic)
    }

    /// Adds a new endpoint and persists changes.
    public func add(endpoint: RelayEndpoint) {
        var newEndpoint = endpoint
        if endpoints.isEmpty {
            newEndpoint.isDefault = true
        }
        if newEndpoint.isDefault {
            for i in endpoints.indices {
                endpoints[i].isDefault = false
            }
        }
        endpoints.append(newEndpoint)
        if newEndpoint.isDefault || activeEndpointId == nil {
            activeEndpointId = newEndpoint.id
        }
        save()
    }

    /// Updates an existing endpoint.
    public func update(endpoint: RelayEndpoint) {
        guard let idx = endpoints.firstIndex(where: { $0.id == endpoint.id }) else { return }
        if endpoint.isDefault {
            for i in endpoints.indices {
                endpoints[i].isDefault = false
            }
        }
        endpoints[idx] = endpoint
        save()
    }

    /// Deletes an endpoint by id.
    public func delete(id: UUID) {
        endpoints.removeAll(where: { $0.id == id })
        if endpoints.isEmpty {
            endpoints = [Self.defaultEndpoint]
        }
        if activeEndpointId == id {
            activeEndpointId = endpoints.first?.id
        }
        save()
    }

    /// Selects an endpoint as active.
    public func setActive(id: UUID) {
        if endpoints.contains(where: { $0.id == id }) {
            self.activeEndpointId = id
        }
    }

    /// Marks an endpoint as default.
    public func setDefault(id: UUID) {
        for i in endpoints.indices {
            endpoints[i].isDefault = (endpoints[i].id == id)
        }
        setActive(id: id)
        save()
    }
}
