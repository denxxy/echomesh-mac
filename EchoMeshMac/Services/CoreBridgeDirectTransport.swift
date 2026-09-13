import Foundation

public extension CoreBridgeService {
    /// Returns the public EchoMesh identity used for LAN/BLE discovery.
    /// Private identity material never crosses the UniFFI boundary.
    func directTransportPeerId() throws -> Data {
        if client == nil {
            try start()
        }
        guard let client else {
            throw CoreBridgeError.clientNotInitialized
        }
        return client.localPeerId()
    }

    /// Builds an authenticated EMD1 packet. Native bearers only see ciphertext.
    func buildDirectTransportPacket(recipient: Data, payload: Data) throws -> Data {
        if client == nil {
            try start()
        }
        guard let client else {
            throw CoreBridgeError.clientNotInitialized
        }
        guard recipient.count == 32 else {
            throw CoreBridgeError.invalidPublicKey("Expected 32 bytes, got \(recipient.count)")
        }
        return try client.buildDirectPacket(recipient: recipient, data: payload)
    }

    /// Passes one complete direct packet back to Rust for identity verification,
    /// E2EE decryption, encrypted persistence and normal event delivery.
    func receiveDirectTransportPacket(_ packet: Data) throws {
        if client == nil {
            try start()
        }
        guard let client else {
            throw CoreBridgeError.clientNotInitialized
        }
        try client.receiveDirectPacket(packet: packet)
    }
}
