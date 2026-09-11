import XCTest
@testable import EchoMeshMac

final class KeychainServiceTests: XCTestCase {
    private var testKeychain: KeychainService!
    private let testAccount = "unit_test_identity_\(UUID().uuidString)"

    override func setUp() {
        super.setUp()
        testKeychain = KeychainService(
            serviceName: "com.echomesh.mac.tests",
            accountName: testAccount
        )
    }

    override func tearDown() {
        try? testKeychain.deletePrivateKey()
        super.tearDown()
    }

    func testSaveAndLoadPrivateKey() throws {
        let fakeKey = Data(repeating: 0x7A, count: 32)
        try testKeychain.savePrivateKey(fakeKey)

        let loaded = try testKeychain.loadPrivateKey()
        XCTAssertNotNil(loaded, "Stored private key should be retrievable from Keychain")
        XCTAssertEqual(loaded, fakeKey, "Loaded private key data must match saved key data")
    }

    func testGetOrCreateIdentityPersistence() throws {
        // First retrieval generates and saves a new identity
        let identity1 = try testKeychain.getOrCreateIdentity()
        XCTAssertEqual(identity1.privateKey.count, 32, "Ed25519 private key must be 32 bytes")
        XCTAssertEqual(identity1.publicKey.count, 32, "Ed25519 public key must be 32 bytes")
        XCTAssertEqual(identity1.publicKeyHex.count, 64, "Public key hex must be 64 characters")
        XCTAssertFalse(identity1.publicKeyBase58.isEmpty, "Public key Base58 must not be empty")

        // Second retrieval should return the exact same persisted key
        let identity2 = try testKeychain.getOrCreateIdentity()
        XCTAssertEqual(identity1.privateKey, identity2.privateKey, "Key must persist across calls")
        XCTAssertEqual(identity1.publicKey, identity2.publicKey, "Public key must match")
        XCTAssertEqual(identity1.publicKeyHex, identity2.publicKeyHex, "Hex key must match")
        XCTAssertEqual(identity1.publicKeyBase58, identity2.publicKeyBase58, "Base58 key must match")
    }

    func testExportPublicKeyFormats() throws {
        let base58Key = try testKeychain.exportPublicKeyBase58()
        let hexKey = try testKeychain.exportPublicKeyHex()

        XCTAssertFalse(base58Key.isEmpty)
        XCTAssertEqual(hexKey.count, 64)
    }
}
