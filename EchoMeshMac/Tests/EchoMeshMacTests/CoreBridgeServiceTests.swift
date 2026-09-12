import XCTest
@testable import EchoMeshMac

final class MockEventListener: CoreEventsListener, @unchecked Sendable {
    var stateTransitions: [NetworkState] = []
    var receivedMessages: [MessageRecord] = []
    var statusUpdates: [(messageId: String, status: DeliveryStatus)] = []
    var receivedPackets: [(sender: Data, data: Data)] = []

    private let lock = NSLock()

    func onStateChanged(state: NetworkState) {
        lock.lock()
        defer { lock.unlock() }
        stateTransitions.append(state)
    }

    func onMessageReceived(message: MessageRecord) {
        lock.lock()
        defer { lock.unlock() }
        receivedMessages.append(message)
    }

    func onMessageStatusUpdated(messageId: String, status: DeliveryStatus) {
        lock.lock()
        defer { lock.unlock() }
        statusUpdates.append((messageId, status))
    }

    func onPacketReceived(sender: Data, data: Data) {
        lock.lock()
        defer { lock.unlock() }
        receivedPackets.append((sender, data))
    }
}

final class CoreBridgeServiceTests: XCTestCase {
    private var tempStorageDir: URL!

    override func setUp() {
        super.setUp()
        tempStorageDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("echomesh_tests_\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: tempStorageDir, withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: tempStorageDir)
        super.tearDown()
    }

    func testMockEventListenerStateTransitions() async {
        let mockListener = MockEventListener()

        mockListener.onStateChanged(state: .offline)
        mockListener.onStateChanged(state: .connecting)
        mockListener.onStateChanged(state: .connectedRealityRelay)
        mockListener.onStateChanged(state: .connectedBleMeshFallback)

        XCTAssertEqual(mockListener.stateTransitions, [
            .offline,
            .connecting,
            .connectedRealityRelay,
            .connectedBleMeshFallback
        ])
    }

    func testClientEventListenerAsyncStream() async {
        let listener = ClientEventListener()
        let expectation = XCTestExpectation(description: "Stream receives events")

        let consumerTask = Task {
            var receivedEvents: [CoreEngineEvent] = []
            for await event in listener.eventStream {
                receivedEvents.append(event)
                if receivedEvents.count == 2 {
                    expectation.fulfill()
                    break
                }
            }
            return receivedEvents
        }

        // Trigger events
        listener.onStateChanged(state: .connecting)
        listener.onMessageStatusUpdated(messageId: "test_msg_1", status: .relayed)

        await fulfillment(of: [expectation], timeout: 2.0)
        let events = await consumerTask.value
        XCTAssertEqual(events.count, 2)
    }

    func testCoreBridgeServiceEndToEnd() async throws {
        let bridge = CoreBridgeService(storagePath: tempStorageDir.path)

        // 1. Initial State
        let initialState = await bridge.currentState()
        XCTAssertEqual(initialState, .offline)

        // 2. Connect to Reality Relay
        let fakeKey = Data(repeating: 0x42, count: 32)
        try await bridge.connect(relayUrl: "https://tyo-reality.echomesh.io:8443", relayKey: fakeKey)

        let connectingOrConnected = await bridge.currentState()
        XCTAssertTrue(
            connectingOrConnected == .connecting || connectingOrConnected == .connectedRealityRelay,
            "State should update upon connection initiation"
        )

        // 3. Send Message
        let payload = try await bridge.sendMessage(to: "peer_alice", text: "Unit test wire message")
        XCTAssertEqual(payload.recipient, "peer_alice")
        XCTAssertEqual(payload.content, "Unit test wire message")
        XCTAssertEqual(payload.status, .sent)

        // Allow background tokio tasks to process status updates
        try await Task.sleep(nanoseconds: 350_000_000)

        // 4. Disconnect & Shutdown
        try await bridge.disconnect()
        let postDisconnect = await bridge.currentState()
        XCTAssertEqual(postDisconnect, .offline)

        await bridge.shutdown()
    }

    func testPrimaryRelayConnectionVerification() async throws {
        let bridge = CoreBridgeService(storagePath: tempStorageDir.path)

        let endpoint = RelayEndpoint(
            name: "Primary Relay",
            host: "77.81.5.109",
            port: 8443,
            publicKeyBase64: "oZvg53goRI3fNUZz5VwK6XzFI9KIkduWu6gYZsms1gY=",
            isDefault: true
        )

        do {
            try await bridge.connectToRelay(endpoint: endpoint)
            let state = await bridge.currentState()
            XCTAssertEqual(state, .connectedRealityRelay)
            try await bridge.disconnect()
        } catch CoreBridgeError.handshakeUnexpectedEof(let msg) {
            // When remote relay 77.81.5.109 is running older build before restart,
            // verify error was cleanly propagated without infinite reconnect loop.
            XCTAssertTrue(msg.contains("Server closed connection"))
        } catch CoreBridgeError.handshakeTimeout(let msg) {
            XCTAssertTrue(msg.contains("Handshake timed out waiting for relay response"))
        } catch CoreBridgeError.connectionFailed(let msg) {
            // Handled when remote host is unreachable or connection refused
            XCTAssertTrue(msg.contains("TCP connection error") || msg.contains("Connection refused") || msg.contains("failed"))
        }

        await bridge.shutdown()
    }

    func testInvalidKeyValidation() async {
        let bridge = CoreBridgeService(storagePath: tempStorageDir.path)

        let invalidEndpoint = RelayEndpoint(
            name: "Invalid Node",
            host: "77.81.5.109",
            port: 8443,
            publicKeyBase64: "invalid_base64!",
            isDefault: false
        )

        do {
            try await bridge.connectToRelay(endpoint: invalidEndpoint)
            XCTFail("Should throw invalidPublicKey error")
        } catch CoreBridgeError.invalidPublicKey(let msg) {
            XCTAssertTrue(msg.contains("32 байта") || msg.contains("Base64"))
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }

        let lastErr = await bridge.getLastErrorMessage()
        XCTAssertNotNil(lastErr)

        await bridge.shutdown()
    }

    func testSendMessagePayloadNotReadyWhenOffline() async throws {
        let bridge = CoreBridgeService(storagePath: tempStorageDir.path)

        // Before start -> notInitialized
        do {
            try await bridge.sendMessage(payload: Data("PING".utf8), recipient: ChatViewModel.echoPeerId)
            XCTFail("Should throw notInitialized error")
        } catch CoreBridgeError.clientNotInitialized {
            // Expected
        } catch {
            XCTFail("Expected CoreBridgeError.clientNotInitialized, got \(error)")
        }

        // After start, but offline -> notReady
        try await bridge.start()
        do {
            try await bridge.sendMessage(payload: Data("PING".utf8), recipient: ChatViewModel.echoPeerId)
            XCTFail("Should throw notReady error")
        } catch CoreBridgeError.notReady {
            // Expected
        } catch {
            XCTFail("Expected CoreBridgeError.notReady, got \(error)")
        }

        await bridge.shutdown()
    }

    @MainActor
    func testEchoPeerIdLength() {
        XCTAssertEqual(ChatViewModel.echoPeerId.count, 32)
        XCTAssertEqual(ChatViewModel.echoPeerId, [UInt8](repeating: 0xEE, count: 32))
    }

    func testContactAndConversationStorage() async throws {
        let bridge = CoreBridgeService(storagePath: tempStorageDir.path)
        try await bridge.start()

        // 1. Check auto-seeded Echo Relay Node contact
        let initialContacts = try await bridge.getContacts()
        XCTAssertEqual(initialContacts.count, 1)
        XCTAssertEqual(initialContacts[0].name, "Echo Relay Node")
        XCTAssertEqual(initialContacts[0].peerId, Data(repeating: 0xEE, count: 32))

        // 2. Add custom contact
        let aliceKeyHex = String(repeating: "aa", count: 32)
        try await bridge.addContact(peerIdHex: aliceKeyHex, name: "Alice")

        let contacts = try await bridge.getContacts()
        XCTAssertEqual(contacts.count, 2)
        XCTAssertTrue(contacts.contains { $0.name == "Alice" })

        // 3. Send message to Alice
        let sent = try await bridge.sendChatMessage(recipientPeerIdHex: aliceKeyHex, text: "Hello Alice")
        XCTAssertEqual(sent.text, "Hello Alice")
        XCTAssertTrue(sent.isOutgoing)

        // 4. Retrieve messages
        let messages = try await bridge.getMessages(peerIdHex: aliceKeyHex, limit: 50)
        XCTAssertEqual(messages.count, 1)
        XCTAssertEqual(messages[0].text, "Hello Alice")

        // 5. Retrieve conversations
        let convs = try await bridge.getConversations()
        let aliceConv = convs.first { $0.peerId == Data(repeating: 0xAA, count: 32) }
        XCTAssertNotNil(aliceConv)
        XCTAssertEqual(aliceConv?.lastMessage, "Hello Alice")

        await bridge.shutdown()
    }

    func testKeyValidator() {
        // Valid 64-char Hex
        let hex64 = String(repeating: "ab", count: 32)
        let res1 = KeyValidator.validate(hex64)
        XCTAssertTrue(res1.isValid)
        XCTAssertEqual(res1.hexString, hex64)

        // Valid with 0x prefix
        let res2 = KeyValidator.validate("0x" + hex64)
        XCTAssertTrue(res2.isValid)
        XCTAssertEqual(res2.hexString, hex64)

        // Valid 32-byte Base64
        let base64 = Data(repeating: 0x42, count: 32).base64EncodedString()
        let res3 = KeyValidator.validate(base64)
        XCTAssertTrue(res3.isValid)

        // Invalid length
        let res4 = KeyValidator.validate("1234abcd")
        XCTAssertFalse(res4.isValid)

        // Empty string
        let res5 = KeyValidator.validate("")
        XCTAssertFalse(res5.isValid)
    }
}
