import XCTest
@testable import EchoMeshMac

final class MockEventListener: CoreEventsListener, @unchecked Sendable {
    var stateTransitions: [NetworkState] = []
    var receivedMessages: [MessagePayload] = []
    var statusUpdates: [(messageId: String, status: DeliveryStatus)] = []

    private let lock = NSLock()

    func onStateChanged(state: NetworkState) {
        lock.lock()
        defer { lock.unlock() }
        stateTransitions.append(state)
    }

    func onMessageReceived(message: MessagePayload) {
        lock.lock()
        defer { lock.unlock() }
        receivedMessages.append(message)
    }

    func onMessageStatusUpdated(messageId: String, status: DeliveryStatus) {
        lock.lock()
        defer { lock.unlock() }
        statusUpdates.append((messageId, status))
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
}
