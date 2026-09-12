import XCTest
@testable import EchoMeshMac

final class RelayConfigTests: XCTestCase {
    private var tempStorageDir: URL!
    private var tempStorageURL: URL!

    override func setUp() {
        super.setUp()
        tempStorageDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("relay_config_tests_\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: tempStorageDir, withIntermediateDirectories: true)
        tempStorageURL = tempStorageDir.appendingPathComponent("relays.json")
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: tempStorageDir)
        super.tearDown()
    }

    // MARK: - 1. Base64 32-byte Key Parsing and Validation

    func testValid32ByteBase64KeyParsing() throws {
        // 32 bytes filled with value 0x42
        let rawBytes = [UInt8](repeating: 0x42, count: 32)
        let base64String = Data(rawBytes).base64EncodedString()

        let endpoint = RelayEndpoint(
            name: "Test Node",
            host: "77.81.5.109",
            port: 8443,
            publicKeyBase64: base64String
        )

        let decoded = try endpoint.decodePublicKey()
        XCTAssertEqual(decoded.count, 32, "Decoded key must have exactly 32 bytes")
        XCTAssertEqual(decoded, rawBytes, "Decoded bytes must match original input")
        XCTAssertNoThrow(try endpoint.validate(requirePublicKey: true))
    }

    func testInvalidBase64CharactersThrows() {
        let endpoint = RelayEndpoint(
            name: "Invalid Base64 Node",
            host: "77.81.5.109",
            port: 8443,
            publicKeyBase64: "!!!Not_A_Base64_String???"
        )

        XCTAssertThrowsError(try endpoint.decodePublicKey()) { error in
            guard let relayErr = error as? RelayConfigError else {
                XCTFail("Expected RelayConfigError, got \(error)")
                return
            }
            XCTAssertEqual(relayErr, .invalidBase64)
        }
    }

    func testInvalidKeyLengthThrows() {
        // 16 bytes (too short)
        let shortBytes = [UInt8](repeating: 0xAA, count: 16)
        let shortBase64 = Data(shortBytes).base64EncodedString()

        let endpointShort = RelayEndpoint(
            name: "Short Key Node",
            host: "77.81.5.109",
            port: 8443,
            publicKeyBase64: shortBase64
        )

        XCTAssertThrowsError(try endpointShort.decodePublicKey()) { error in
            guard let relayErr = error as? RelayConfigError else {
                XCTFail("Expected RelayConfigError, got \(error)")
                return
            }
            XCTAssertEqual(relayErr, .invalidKeyLength(expected: 32, actual: 16))
        }

        // 64 bytes (too long)
        let longBytes = [UInt8](repeating: 0xBB, count: 64)
        let longBase64 = Data(longBytes).base64EncodedString()

        let endpointLong = RelayEndpoint(
            name: "Long Key Node",
            host: "77.81.5.109",
            port: 8443,
            publicKeyBase64: longBase64
        )

        XCTAssertThrowsError(try endpointLong.decodePublicKey()) { error in
            guard let relayErr = error as? RelayConfigError else {
                XCTFail("Expected RelayConfigError, got \(error)")
                return
            }
            XCTAssertEqual(relayErr, .invalidKeyLength(expected: 32, actual: 64))
        }
    }

    func testEmptyKeyValidation() {
        let endpoint = RelayEndpoint(
            name: "Empty Key Node",
            host: "77.81.5.109",
            port: 8443,
            publicKeyBase64: ""
        )

        XCTAssertThrowsError(try endpoint.decodePublicKey()) { error in
            guard let relayErr = error as? RelayConfigError else {
                XCTFail("Expected RelayConfigError, got \(error)")
                return
            }
            XCTAssertEqual(relayErr, .emptyPublicKey)
        }

        // When requirePublicKey is false, validate should pass for empty key
        XCTAssertNoThrow(try endpoint.validate(requirePublicKey: false))

        // When requirePublicKey is true, validate should throw emptyPublicKey
        XCTAssertThrowsError(try endpoint.validate(requirePublicKey: true))
    }

    // MARK: - 2. Host:Port Formatting

    func testFormattedAddressIPv4() {
        let endpoint = RelayEndpoint(
            name: "IPv4 Relay",
            host: "77.81.5.109",
            port: 8443
        )
        XCTAssertEqual(endpoint.formattedAddress, "77.81.5.109:8443")
    }

    func testFormattedAddressDomain() {
        let endpoint = RelayEndpoint(
            name: "Domain Relay",
            host: "relay.echomesh.io",
            port: 443
        )
        XCTAssertEqual(endpoint.formattedAddress, "relay.echomesh.io:443")
    }

    func testFormattedAddressIPv6() {
        // Raw IPv6 address should be wrapped in brackets
        let endpoint = RelayEndpoint(
            name: "IPv6 Relay",
            host: "2001:db8::1",
            port: 8443
        )
        XCTAssertEqual(endpoint.formattedAddress, "[2001:db8::1]:8443")

        // Already bracketed IPv6 should not be double-bracketed
        let endpointBracketed = RelayEndpoint(
            name: "Bracketed IPv6",
            host: "[2001:db8::1]",
            port: 8443
        )
        XCTAssertEqual(endpointBracketed.formattedAddress, "[2001:db8::1]:8443")
    }

    // MARK: - 3. Host and Port Validation

    func testHostValidation() throws {
        // Valid hosts
        let validHosts = ["77.81.5.109", "127.0.0.1", "::1", "relay.echomesh.io", "localhost", "my-relay"]
        for host in validHosts {
            let ep = RelayEndpoint(name: "Test", host: host, port: 8443)
            XCTAssertNoThrow(try ep.validateHost(), "Host '\(host)' should be valid")
        }

        // Invalid hosts
        let invalidHosts = ["", "   ", "invalid host with spaces", "---"]
        for host in invalidHosts {
            let ep = RelayEndpoint(name: "Test", host: host, port: 8443)
            XCTAssertThrowsError(try ep.validateHost(), "Host '\(host)' should be invalid")
        }
    }

    func testPortRangeValidation() {
        // Valid ports
        let validPorts: [UInt16] = [1, 80, 443, 8443, 65535]
        for port in validPorts {
            let ep = RelayEndpoint(name: "Test", host: "77.81.5.109", port: port)
            XCTAssertNoThrow(try ep.validatePort(), "Port \(port) should be valid")
        }

        // Port 0 is invalid
        let zeroPortEp = RelayEndpoint(name: "Test", host: "77.81.5.109", port: 0)
        XCTAssertThrowsError(try zeroPortEp.validatePort())
    }

    // MARK: - 4. RelayConfigManager Persistence & Default Node

    @MainActor
    func testRelayConfigManagerInitializesDefaultNode() {
        let manager = RelayConfigManager(storageURL: tempStorageURL)

        XCTAssertEqual(manager.endpoints.count, 1)
        let initialNode = manager.endpoints[0]
        XCTAssertEqual(initialNode.name, "Primary Relay")
        XCTAssertEqual(initialNode.host, "77.81.5.109")
        XCTAssertEqual(initialNode.port, 8443)
        XCTAssertEqual(initialNode.publicKeyBase64, "oZvg53goRI3fNUZz5VwK6XzFI9KIkduWu6gYZsms1gY=")
        XCTAssertEqual(initialNode.secretTokenHex, "6563686f6d6573685f7365637265745f6d6573685f746f6b656e5f32303236")
        XCTAssertTrue(initialNode.isDefault)
        XCTAssertEqual(manager.activeEndpoint.id, initialNode.id)
    }

    @MainActor
    func testRelayConfigManagerSaveAndReload() {
        let manager = RelayConfigManager(storageURL: tempStorageURL)

        let customNode = RelayEndpoint(
            name: "Secondary Frankfurt",
            host: "fra.echomesh.io",
            port: 9443,
            publicKeyBase64: Data(repeating: 0x55, count: 32).base64EncodedString(),
            isDefault: false
        )
        manager.add(endpoint: customNode)

        XCTAssertEqual(manager.endpoints.count, 2)

        // Reload fresh manager from the same file URL
        let reloadedManager = RelayConfigManager(storageURL: tempStorageURL)
        XCTAssertEqual(reloadedManager.endpoints.count, 2)
        XCTAssertTrue(reloadedManager.endpoints.contains(where: { $0.name == "Secondary Frankfurt" }))
        XCTAssertTrue(reloadedManager.endpoints.contains(where: { $0.name == "Primary Relay" }))
    }

    @MainActor
    func testRelayConfigManagerSetDefaultAndActive() {
        let manager = RelayConfigManager(storageURL: tempStorageURL)

        let node2 = RelayEndpoint(
            name: "Node 2",
            host: "10.0.0.2",
            port: 8443
        )
        manager.add(endpoint: node2)

        manager.setDefault(id: node2.id)

        XCTAssertTrue(manager.endpoints.first(where: { $0.id == node2.id })?.isDefault ?? false)
        XCTAssertFalse(manager.endpoints.first(where: { $0.name == "Primary Relay" })?.isDefault ?? true)
        XCTAssertEqual(manager.activeEndpoint.id, node2.id)
    }

    @MainActor
    func testRelayConfigManagerDeleteNode() {
        let manager = RelayConfigManager(storageURL: tempStorageURL)

        let node2 = RelayEndpoint(
            name: "Node to Delete",
            host: "10.0.0.3",
            port: 8443
        )
        manager.add(endpoint: node2)
        XCTAssertEqual(manager.endpoints.count, 2)

        manager.delete(id: node2.id)
        XCTAssertEqual(manager.endpoints.count, 1)
        XCTAssertFalse(manager.endpoints.contains(where: { $0.id == node2.id }))
    }

    func testSecretTokenHexPersistenceAndBackwardCompatibility() throws {
        // 1. New model encoding/decoding
        let endpointWithToken = RelayEndpoint(
            name: "Reality Secure Relay",
            host: "reality.echomesh.io",
            port: 8443,
            publicKeyBase64: "oZvg53goRI3fNUZz5VwK6XzFI9KIkduWu6gYZsms1gY=",
            secretTokenHex: "a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890",
            isDefault: false
        )

        let encoded = try JSONEncoder().encode(endpointWithToken)
        let decoded = try JSONDecoder().decode(RelayEndpoint.self, from: encoded)

        XCTAssertEqual(decoded.secretTokenHex, "a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890")
        XCTAssertEqual(decoded.name, "Reality Secure Relay")

        // 2. Backward compatibility: older JSON without secretTokenHex
        let legacyJson = """
        {
            "id": "\(UUID().uuidString)",
            "name": "Legacy Relay",
            "host": "legacy.echomesh.io",
            "port": 8443,
            "publicKeyBase64": "oZvg53goRI3fNUZz5VwK6XzFI9KIkduWu6gYZsms1gY=",
            "isDefault": true
        }
        """.data(using: .utf8)!

        let decodedLegacy = try JSONDecoder().decode(RelayEndpoint.self, from: legacyJson)
        XCTAssertEqual(decodedLegacy.secretTokenHex, "")
        XCTAssertEqual(decodedLegacy.name, "Legacy Relay")
    }
}
