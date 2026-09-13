import Foundation
import Observation

public enum RelayConfigError: LocalizedError, Equatable, Sendable {
    case invalidHost(String)
    case invalidPort(UInt16)
    case emptyPublicKey
    case invalidBase64
    case invalidKeyLength(expected: Int, actual: Int)

    public var errorDescription: String? {
        switch self {
        case .invalidHost(let host): return "Invalid host or IP address: '\(host)'"
        case .invalidPort(let port): return "Invalid port: \(port). Port must be between 1 and 65535."
        case .emptyPublicKey: return "Public key cannot be empty."
        case .invalidBase64: return "Public key is not a valid Base64 encoded string."
        case .invalidKeyLength(let expected, let actual): return "Invalid public key length: expected \(expected) bytes, got \(actual) bytes."
        }
    }
}

public struct RelayEndpoint: Codable, Identifiable, Hashable, Sendable {
    public var id: UUID
    public var name: String
    public var host: String
    public var port: UInt16
    public var publicKeyBase64: String
    public var secretTokenHex: String = ""
    public var isDefault: Bool

    enum CodingKeys: String, CodingKey { case id, name, host, port, publicKeyBase64, secretTokenHex, isDefault }

    public init(id: UUID = UUID(), name: String, host: String, port: UInt16 = 8443, publicKeyBase64: String = "", secretTokenHex: String = "", isDefault: Bool = false) {
        self.id = id
        self.name = name
        self.host = host
        self.port = port
        self.publicKeyBase64 = publicKeyBase64
        self.secretTokenHex = secretTokenHex
        self.isDefault = isDefault
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        name = try c.decode(String.self, forKey: .name)
        host = try c.decode(String.self, forKey: .host)
        port = try c.decode(UInt16.self, forKey: .port)
        publicKeyBase64 = try c.decodeIfPresent(String.self, forKey: .publicKeyBase64) ?? ""
        secretTokenHex = try c.decodeIfPresent(String.self, forKey: .secretTokenHex) ?? ""
        isDefault = try c.decodeIfPresent(Bool.self, forKey: .isDefault) ?? false
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id)
        try c.encode(name, forKey: .name)
        try c.encode(host, forKey: .host)
        try c.encode(port, forKey: .port)
        try c.encode(publicKeyBase64, forKey: .publicKeyBase64)
        try c.encode(isDefault, forKey: .isDefault)
    }

    public var formattedAddress: String {
        let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.contains(":") && !trimmed.hasPrefix("[") && !trimmed.hasSuffix("]") { return "[\(trimmed)]:\(port)" }
        return "\(trimmed):\(port)"
    }

    public func decodePublicKey() throws -> [UInt8] {
        let trimmed = publicKeyBase64.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw RelayConfigError.emptyPublicKey }
        guard let data = Data(base64Encoded: trimmed) else { throw RelayConfigError.invalidBase64 }
        guard data.count == 32 else { throw RelayConfigError.invalidKeyLength(expected: 32, actual: data.count) }
        return [UInt8](data)
    }

    public func validateHost() throws {
        let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw RelayConfigError.invalidHost(host) }
        var sin = sockaddr_in()
        if inet_pton(AF_INET, trimmed, &sin.sin_addr) == 1 { return }
        var sin6 = sockaddr_in6()
        let ipv6 = trimmed.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        if inet_pton(AF_INET6, ipv6, &sin6.sin6_addr) == 1 { return }
        let hostRegex = #"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$|^localhost$"#
        if trimmed.range(of: hostRegex, options: .regularExpression) != nil { return }
        let singleLabelRegex = #"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"#
        if trimmed.range(of: singleLabelRegex, options: .regularExpression) != nil { return }
        throw RelayConfigError.invalidHost(host)
    }

    public func validatePort() throws { guard port >= 1 else { throw RelayConfigError.invalidPort(port) } }
    public func validate(requirePublicKey: Bool = false) throws {
        try validateHost()
        try validatePort()
        if requirePublicKey || !publicKeyBase64.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { _ = try decodePublicKey() }
    }
}

@Observable
@MainActor
public final class RelayConfigManager: Sendable {
    public static let shared = RelayConfigManager()
    public private(set) var endpoints: [RelayEndpoint] = []
    public private(set) var activeEndpointId: UUID?
    private let storageURL: URL
    private static let relayCredentialService = "com.echomesh.mac.relay"

    public static let defaultEndpoint = RelayEndpoint(
        name: "Primary Relay",
        host: "77.81.5.109",
        port: 8443,
        publicKeyBase64: "oZvg53goRI3fNUZz5VwK6XzFI9KIkduWu6gYZsms1gY=",
        secretTokenHex: "",
        isDefault: true
    )

    public init(storageURL: URL? = nil) {
        if let storageURL { self.storageURL = storageURL }
        else {
            let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first ?? URL(fileURLWithPath: NSTemporaryDirectory())
            self.storageURL = appSupport.appendingPathComponent("EchoMesh", isDirectory: true).appendingPathComponent("relays.json")
        }
        load()
    }

    public var activeEndpoint: RelayEndpoint {
        if let id = activeEndpointId, let found = endpoints.first(where: { $0.id == id }) { return found }
        if let def = endpoints.first(where: { $0.isDefault }) { return def }
        return endpoints.first ?? Self.defaultEndpoint
    }

    private static func credentialStore(for id: UUID) -> KeychainService {
        KeychainService(serviceName: relayCredentialService, accountName: "relay-\(id.uuidString)")
    }

    private static func persistCredential(_ token: String, for id: UUID) {
        let store = credentialStore(for: id)
        if token.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { try? store.deletePrivateKey() }
        else { try? store.savePrivateKey(Data(token.utf8)) }
    }

    private static func loadCredential(for id: UUID) -> String {
        guard let data = try? credentialStore(for: id).loadPrivateKey() else { return "" }
        return String(data: data, encoding: .utf8) ?? ""
    }

    public func load() {
        let parent = storageURL.deletingLastPathComponent()
        if !FileManager.default.fileExists(atPath: parent.path) { try? FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true) }
        guard FileManager.default.fileExists(atPath: storageURL.path),
              let data = try? Data(contentsOf: storageURL),
              let decoded = try? JSONDecoder().decode([RelayEndpoint].self, from: data),
              !decoded.isEmpty else {
            endpoints = [Self.defaultEndpoint]
            activeEndpointId = Self.defaultEndpoint.id
            save()
            return
        }

        endpoints = decoded
        var migrated = false
        for i in endpoints.indices {
            if endpoints[i].host == Self.defaultEndpoint.host && endpoints[i].publicKeyBase64.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                endpoints[i].publicKeyBase64 = Self.defaultEndpoint.publicKeyBase64
            }
            let legacy = endpoints[i].secretTokenHex
            if !legacy.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                Self.persistCredential(legacy, for: endpoints[i].id)
                migrated = true
            }
            endpoints[i].secretTokenHex = Self.loadCredential(for: endpoints[i].id)
        }
        if migrated { save() }
        activeEndpointId = endpoints.first(where: { $0.isDefault })?.id ?? endpoints.first?.id
    }

    public func save() {
        let parent = storageURL.deletingLastPathComponent()
        if !FileManager.default.fileExists(atPath: parent.path) { try? FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true) }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(endpoints) else { return }
        try? data.write(to: storageURL, options: .atomic)
    }

    public func add(endpoint: RelayEndpoint) {
        var endpoint = endpoint
        if endpoints.isEmpty { endpoint.isDefault = true }
        if endpoint.isDefault { for i in endpoints.indices { endpoints[i].isDefault = false } }
        Self.persistCredential(endpoint.secretTokenHex, for: endpoint.id)
        endpoints.append(endpoint)
        if endpoint.isDefault || activeEndpointId == nil { activeEndpointId = endpoint.id }
        save()
    }

    public func update(endpoint: RelayEndpoint) {
        guard let idx = endpoints.firstIndex(where: { $0.id == endpoint.id }) else { return }
        if endpoint.isDefault { for i in endpoints.indices { endpoints[i].isDefault = false } }
        Self.persistCredential(endpoint.secretTokenHex, for: endpoint.id)
        endpoints[idx] = endpoint
        save()
    }

    public func delete(id: UUID) {
        try? Self.credentialStore(for: id).deletePrivateKey()
        endpoints.removeAll(where: { $0.id == id })
        if endpoints.isEmpty { endpoints = [Self.defaultEndpoint] }
        if activeEndpointId == id { activeEndpointId = endpoints.first?.id }
        save()
    }

    public func setActive(id: UUID) { if endpoints.contains(where: { $0.id == id }) { activeEndpointId = id } }
    public func setDefault(id: UUID) {
        for i in endpoints.indices { endpoints[i].isDefault = (endpoints[i].id == id) }
        setActive(id: id)
        save()
    }
}
