import Foundation
import Security

public enum KeychainError: LocalizedError, Equatable {
    case duplicateItem
    case itemNotFound
    case unhandledError(status: OSStatus)
    case invalidKeyData

    public var errorDescription: String? {
        switch self {
        case .duplicateItem:
            return "The requested key already exists in the Keychain."
        case .itemNotFound:
            return "No identity key was found in the Keychain."
        case .unhandledError(let status):
            let message = SecCopyErrorMessageString(status, nil) as String? ?? "Unknown error"
            return "Keychain operation failed with status \(status): \(message)"
        case .invalidKeyData:
            return "The cryptographic key data retrieved from Keychain is invalid."
        }
    }
}

/// Secure service for reading, writing, and deriving Ed25519/X25519 identity keys
/// using Apple Keychain Services API with `kSecAttrAccessibleAfterFirstUnlock`.
public final class KeychainService: @unchecked Sendable {
    public static let shared = KeychainService()

    public let serviceName: String
    public let accountName: String
    public let accessGroup: String?

    public init(
        serviceName: String = "com.echomesh.mac.identity",
        accountName: String = "primary_identity_seed",
        accessGroup: String? = nil
    ) {
        self.serviceName = serviceName
        self.accountName = accountName
        self.accessGroup = accessGroup
    }

    // MARK: - Core Keychain Operations

    /// Loads the stored private key raw bytes from Keychain, or returns nil if absent.
    public func loadPrivateKey() throws -> Data? {
        var query = baseQuery()
        query[kSecReturnData as String] = kCFBooleanTrue
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        switch status {
        case errSecSuccess:
            guard let data = item as? Data else {
                throw KeychainError.invalidKeyData
            }
            return data
        case errSecItemNotFound:
            return nil
        default:
            throw KeychainError.unhandledError(status: status)
        }
    }

    /// Saves a new private key or updates an existing one with `kSecAttrAccessibleAfterFirstUnlock`.
    public func savePrivateKey(_ data: Data) throws {
        var query = baseQuery()
        query[kSecValueData as String] = data
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock

        let status = SecItemAdd(query as CFDictionary, nil)

        if status == errSecDuplicateItem {
            // Update existing entry
            let updateQuery = baseQuery()
            let attributesToUpdate: [String: Any] = [
                kSecValueData as String: data,
                kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
            ]
            let updateStatus = SecItemUpdate(updateQuery as CFDictionary, attributesToUpdate as CFDictionary)
            if updateStatus != errSecSuccess {
                throw KeychainError.unhandledError(status: updateStatus)
            }
        } else if status != errSecSuccess {
            throw KeychainError.unhandledError(status: status)
        }
    }

    /// Deletes the private key from Keychain (used for account reset or tests).
    public func deletePrivateKey() throws {
        let query = baseQuery()
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            throw KeychainError.unhandledError(status: status)
        }
    }

    // MARK: - Identity Management & Rust Engine Bridge

    /// Checks if a private key exists in Keychain.
    /// If absent, invokes Rust `generateIdentityKeypair()` and persists the 32-byte secret seed.
    /// If present, invokes Rust `derivePublicKey()` to regenerate public keys and encodings.
    public func getOrCreateIdentity() throws -> IdentityKeyPair {
        if let storedKey = try loadPrivateKey() {
            return try derivePublicKey(privateKey: storedKey)
        }

        let newKeyPair = try generateIdentityKeypair()
        try savePrivateKey(newKeyPair.privateKey)
        return newKeyPair
    }

    /// Exports the Identity Public Key in Base58 format.
    public func exportPublicKeyBase58() throws -> String {
        let identity = try getOrCreateIdentity()
        return identity.publicKeyBase58
    }

    /// Exports the Identity Public Key in Hex format.
    public func exportPublicKeyHex() throws -> String {
        let identity = try getOrCreateIdentity()
        return identity.publicKeyHex
    }

    // MARK: - Private Helpers

    private func baseQuery() -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: accountName
        ]

        if let accessGroup = accessGroup, !accessGroup.isEmpty {
            query[kSecAttrAccessGroup as String] = accessGroup
        }

        return query
    }
}
