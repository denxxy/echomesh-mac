import CoreBluetooth
import Foundation
import os.log

@MainActor
public final class BLETransportService: NSObject {
    public static let shared = BLETransportService()

    // These UUIDs are part of the EchoMesh cross-platform BLE wire contract.
    // Keep them byte-for-byte aligned with echomesh-core::transport::ble_native.
    private static let serviceUUID = CBUUID(string: "5E4D0001-7A11-4EF0-9F84-4543484F4D53")
    private static let identityUUID = CBUUID(string: "5E4D0002-7A11-4EF0-9F84-4543484F4D53")
    private static let inboundUUID = CBUUID(string: "5E4D0003-7A11-4EF0-9F84-4543484F4D53")
    private static let magic = Data([0x45, 0x4D, 0x42, 0x31])
    private static let headerSize = 12
    private static let maxPacket = 1_400
    private static let maxFragments = 128

    private let logger = Logger(subsystem: "com.echomesh.mac", category: "BLE")
    private var central: CBCentralManager!
    private var peripheralManager: CBPeripheralManager!
    private var localPeerId: Data?
    private var started = false
    private var peers: [Data: CBPeripheral] = [:]
    private var inbound: [UUID: CBCharacteristic] = [:]
    private var assemblies: [AssemblyKey: Assembly] = [:]

    private struct AssemblyKey: Hashable {
        let source: UUID
        let messageId: UInt32
    }

    private struct Assembly {
        var parts: [Data?]
        var received: Int = 0
        var bytes: Int = 0
    }

    private override init() { super.init() }

    public func start() {
        guard !started else { return }
        started = true
        Task {
            do {
                let peerId = try await CoreBridgeService.shared.directTransportPeerId()
                guard peerId.count == 32 else { return }
                await MainActor.run {
                    self.localPeerId = peerId
                    self.central = CBCentralManager(delegate: self, queue: .main)
                    self.peripheralManager = CBPeripheralManager(delegate: self, queue: .main)
                }
            } catch {
                logger.error("Unable to initialize BLE transport")
            }
        }
    }

    public func stop() {
        started = false
        central?.stopScan()
        for peer in peers.values { central?.cancelPeripheralConnection(peer) }
        peripheralManager?.stopAdvertising()
        peripheralManager?.removeAllServices()
        peers.removeAll(); inbound.removeAll(); assemblies.removeAll()
    }

    public func send(recipientPeerId: Data, payload: Data) async throws {
        guard let peer = peers[recipientPeerId], let characteristic = inbound[peer.identifier] else {
            throw CoreBridgeError.connectionFailed("BLE peer is not reachable")
        }
        let packet = try await CoreBridgeService.shared.buildDirectTransportPacket(
            recipient: recipientPeerId,
            payload: payload
        )
        let mtu = peer.maximumWriteValueLength(for: .withResponse)
        for fragment in try fragments(packet, mtu: mtu, messageId: UInt32.random(in: .min ... .max)) {
            peer.writeValue(fragment, for: characteristic, type: .withResponse)
        }
    }

    private func configureGattServer() {
        guard peripheralManager.state == .poweredOn else { return }
        let identity = CBMutableCharacteristic(
            type: Self.identityUUID, properties: [.read], value: nil, permissions: [.readable]
        )
        let input = CBMutableCharacteristic(
            type: Self.inboundUUID,
            properties: [.write, .writeWithoutResponse],
            value: nil,
            permissions: [.writeable]
        )
        let service = CBMutableService(type: Self.serviceUUID, primary: true)
        service.characteristics = [identity, input]
        peripheralManager.removeAllServices()
        peripheralManager.add(service)
    }

    private func scan() {
        guard started, central.state == .poweredOn else { return }
        central.scanForPeripherals(
            withServices: [Self.serviceUUID],
            options: [CBCentralManagerScanOptionAllowDuplicatesKey: false]
        )
    }

    private func fragments(_ packet: Data, mtu: Int, messageId: UInt32) throws -> [Data] {
        guard packet.count <= Self.maxPacket else {
            throw CoreBridgeError.connectionFailed("BLE packet exceeds transport limit")
        }
        let chunkSize = max(32, mtu) - Self.headerSize
        guard chunkSize > 0 else { throw CoreBridgeError.connectionFailed("BLE MTU is too small") }
        let total = max(1, (packet.count + chunkSize - 1) / chunkSize)
        guard total <= Self.maxFragments else {
            throw CoreBridgeError.connectionFailed("BLE packet requires too many fragments")
        }
        let chunks = packet.isEmpty ? [Data()] : stride(from: 0, to: packet.count, by: chunkSize).map {
            packet.subdata(in: $0..<min($0 + chunkSize, packet.count))
        }
        return chunks.enumerated().map { index, chunk in
            var out = Data(Self.magic)
            appendBE(messageId, to: &out); appendBE(UInt16(index), to: &out); appendBE(UInt16(total), to: &out)
            out.append(chunk)
            return out
        }
    }

    private func ingest(_ fragment: Data, source: UUID) {
        guard fragment.count >= Self.headerSize, fragment.prefix(4) == Self.magic else { return }
        let b = [UInt8](fragment)
        let id = UInt32(b[4]) << 24 | UInt32(b[5]) << 16 | UInt32(b[6]) << 8 | UInt32(b[7])
        let index = Int(UInt16(b[8]) << 8 | UInt16(b[9]))
        let total = Int(UInt16(b[10]) << 8 | UInt16(b[11]))
        guard total > 0, total <= Self.maxFragments, index < total else { return }
        let payload = fragment.subdata(in: Self.headerSize..<fragment.count)
        let key = AssemblyKey(source: source, messageId: id)
        var a = assemblies[key] ?? Assembly(parts: Array(repeating: nil, count: total))
        guard a.parts.count == total else { assemblies.removeValue(forKey: key); return }
        if a.parts[index] == nil { a.parts[index] = payload; a.received += 1; a.bytes += payload.count }
        guard a.bytes <= Self.maxPacket else { assemblies.removeValue(forKey: key); return }
        assemblies[key] = a
        guard a.received == total else { return }
        assemblies.removeValue(forKey: key)
        var packet = Data(capacity: a.bytes)
        for part in a.parts { guard let part else { return }; packet.append(part) }
        Task {
            do { try await CoreBridgeService.shared.receiveDirectTransportPacket(packet) }
            catch { logger.error("Rejected BLE direct packet") }
        }
    }

    private func appendBE<T: FixedWidthInteger>(_ value: T, to data: inout Data) {
        var value = value.bigEndian
        withUnsafeBytes(of: &value) { data.append(contentsOf: $0) }
    }
}

extension BLETransportService: CBCentralManagerDelegate {
    public func centralManagerDidUpdateState(_ central: CBCentralManager) {
        if central.state == .poweredOn { scan() }
    }

    public func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                               advertisementData: [String: Any], rssi RSSI: NSNumber) {
        if started, peripheral.state == .disconnected { central.connect(peripheral) }
    }

    public func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        peripheral.delegate = self
        peripheral.discoverServices([Self.serviceUUID])
    }

    public func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral,
                               error: Error?) {
        inbound.removeValue(forKey: peripheral.identifier)
        peers = peers.filter { $0.value.identifier != peripheral.identifier }
        assemblies = assemblies.filter { $0.key.source != peripheral.identifier }
        if started, central.state == .poweredOn { central.connect(peripheral) }
    }
}

extension BLETransportService: CBPeripheralDelegate {
    public func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard error == nil else { return }
        for service in peripheral.services ?? [] where service.uuid == Self.serviceUUID {
            peripheral.discoverCharacteristics([Self.identityUUID, Self.inboundUUID], for: service)
        }
    }

    public func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService,
                           error: Error?) {
        guard error == nil else { return }
        for c in service.characteristics ?? [] {
            if c.uuid == Self.identityUUID { peripheral.readValue(for: c) }
            if c.uuid == Self.inboundUUID { inbound[peripheral.identifier] = c }
        }
    }

    public func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic,
                           error: Error?) {
        guard error == nil, characteristic.uuid == Self.identityUUID,
              let id = characteristic.value, id.count == 32, id != localPeerId else { return }
        peers[id] = peripheral
    }
}

extension BLETransportService: CBPeripheralManagerDelegate {
    public func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        if peripheral.state == .poweredOn { configureGattServer() }
    }

    public func peripheralManager(_ peripheral: CBPeripheralManager, didAdd service: CBService, error: Error?) {
        guard error == nil, started else { return }
        peripheral.startAdvertising([
            CBAdvertisementDataServiceUUIDsKey: [Self.serviceUUID],
            CBAdvertisementDataLocalNameKey: "EchoMesh"
        ])
    }

    public func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveRead request: CBATTRequest) {
        guard request.characteristic.uuid == Self.identityUUID, let localPeerId else {
            peripheral.respond(to: request, withResult: .readNotPermitted); return
        }
        request.value = localPeerId
        peripheral.respond(to: request, withResult: .success)
    }

    public func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveWrite requests: [CBATTRequest]) {
        for request in requests where request.characteristic.uuid == Self.inboundUUID {
            if let value = request.value { ingest(value, source: request.central.identifier) }
            peripheral.respond(to: request, withResult: .success)
        }
    }
}
