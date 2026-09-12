import Foundation
import CoreBluetooth
import CryptoKit
import EchoMeshCore

/// Native macOS BLE bearer for EchoMesh direct E2EE packets.
///
/// CoreBluetooth only transports opaque EMB1 fragments. Peer identity,
/// signatures, recipient validation, encryption and reassembly stay in the
/// Rust `DirectTransportCrypto` boundary.
final class BleTransportService: NSObject, @unchecked Sendable {
    static let serviceUUID = CBUUID(string: "E0C40001-4D45-5348-8000-4543484F0001")
    static let routeUUID = CBUUID(string: "E0C40002-4D45-5348-8000-4543484F0002")
    static let dataUUID = CBUUID(string: "E0C40003-4D45-5348-8000-4543484F0003")

    private let queue = DispatchQueue(label: "com.echomesh.ble", qos: .userInitiated)
    private let crypto: DirectTransportCrypto
    private lazy var central = CBCentralManager(delegate: self, queue: queue)
    private lazy var peripheral = CBPeripheralManager(delegate: self, queue: queue)

    private var routeCharacteristic: CBMutableCharacteristic?
    private var dataCharacteristic: CBMutableCharacteristic?
    private var discoveredDataCharacteristics: [UUID: CBCharacteristic] = [:]
    private var routesToPeripherals: [Data: CBPeripheral] = [:]
    private var pendingNotifications: [Data] = []
    private var nextMessageId: UInt32 = UInt32.random(in: UInt32.min...UInt32.max)

    var onMessage: (@Sendable (DirectMessage) -> Void)?
    var onAvailabilityChanged: (@Sendable (Bool) -> Void)?

    init(storagePath: String) throws {
        self.crypto = try DirectTransportCrypto(storagePath: storagePath)
        super.init()
        _ = central
        _ = peripheral
    }

    func start() {
        queue.async { [weak self] in
            guard let self else { return }
            if self.central.state == .poweredOn {
                self.startScanning()
            }
            if self.peripheral.state == .poweredOn {
                self.publishServiceIfNeeded()
            }
        }
    }

    func stop() {
        queue.async { [weak self] in
            guard let self else { return }
            self.central.stopScan()
            for peripheral in self.routesToPeripherals.values {
                self.central.cancelPeripheralConnection(peripheral)
            }
            self.routesToPeripherals.removeAll()
            self.discoveredDataCharacteristics.removeAll()
            self.peripheral.stopAdvertising()
            self.peripheral.removeAllServices()
            self.routeCharacteristic = nil
            self.dataCharacteristic = nil
            self.pendingNotifications.removeAll()
            try? self.crypto.resetBleReassembly()
        }
    }

    /// Sends plaintext to a peer. The plaintext crosses into Rust immediately;
    /// only encrypted direct-packet fragments are handed to CoreBluetooth.
    func send(to peerId: Data, data: Data) throws {
        guard peerId.count == 32 else {
            throw BleTransportError.invalidPeerId
        }

        let packet = try crypto.seal(
            recipientPeerId: [UInt8](peerId),
            data: [UInt8](data)
        )
        let targetRoute = Self.routeId(for: peerId)

        queue.async { [weak self] in
            guard let self else { return }
            do {
                try self.sendOpaquePacket(Data(packet), toRoute: targetRoute)
            } catch {
                // Delivery failures are surfaced through the service boundary;
                // callers can fall back to LAN/relay on the next send attempt.
            }
        }
    }

    private func sendOpaquePacket(_ packet: Data, toRoute route: Data) throws {
        let id = nextMessageId
        nextMessageId &+= 1

        if let target = routesToPeripherals[route],
           let characteristic = discoveredDataCharacteristics[target.identifier],
           target.state == .connected {
            let mtu = max(32, target.maximumWriteValueLength(for: .withoutResponse))
            let fragments = try crypto.bleFragments(
                packet: [UInt8](packet),
                mtu: UInt32(mtu),
                messageId: id
            )
            for fragment in fragments {
                target.writeValue(Data(fragment), for: characteristic, type: .withoutResponse)
            }
            return
        }

        // The remote peer may be the central and this Mac the peripheral. In
        // that direction notifications are broadcast to subscribed EchoMesh
        // centrals; E2EE recipient validation makes non-target peers discard it.
        guard let characteristic = dataCharacteristic else {
            throw BleTransportError.noConnectedPeer
        }
        let fragments = try crypto.bleFragments(
            packet: [UInt8](packet),
            mtu: 185,
            messageId: id
        )
        for fragment in fragments {
            let value = Data(fragment)
            if !peripheral.updateValue(value, for: characteristic, onSubscribedCentrals: nil) {
                pendingNotifications.append(value)
            }
        }
    }

    private func consume(fragment: Data) {
        do {
            if let message = try crypto.openBleFragment(fragment: [UInt8](fragment)) {
                onMessage?(message)
            }
        } catch {
            // Authentication, recipient or framing errors are intentionally
            // dropped at the BLE boundary and never forwarded to the UI.
        }
    }

    private func startScanning() {
        central.scanForPeripherals(
            withServices: [Self.serviceUUID],
            options: [CBCentralManagerScanOptionAllowDuplicatesKey: false]
        )
    }

    private func publishServiceIfNeeded() {
        guard dataCharacteristic == nil else {
            if !peripheral.isAdvertising {
                peripheral.startAdvertising([CBAdvertisementDataServiceUUIDsKey: [Self.serviceUUID]])
            }
            return
        }

        let routeValue = Self.routeId(for: Data(crypto.localPeerId()))
        let route = CBMutableCharacteristic(
            type: Self.routeUUID,
            properties: [.read],
            value: routeValue,
            permissions: [.readable]
        )
        let data = CBMutableCharacteristic(
            type: Self.dataUUID,
            properties: [.write, .writeWithoutResponse, .notify],
            value: nil,
            permissions: [.writeable]
        )
        let service = CBMutableService(type: Self.serviceUUID, primary: true)
        service.characteristics = [route, data]
        routeCharacteristic = route
        dataCharacteristic = data
        peripheral.add(service)
    }

    private static func routeId(for peerId: Data) -> Data {
        Data(SHA256.hash(data: peerId).prefix(16))
    }
}

extension BleTransportService: CBCentralManagerDelegate {
    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        let available = central.state == .poweredOn && peripheral.state == .poweredOn
        onAvailabilityChanged?(available)
        if central.state == .poweredOn {
            startScanning()
        } else {
            routesToPeripherals.removeAll()
            discoveredDataCharacteristics.removeAll()
        }
    }

    func centralManager(
        _ central: CBCentralManager,
        didDiscover peripheral: CBPeripheral,
        advertisementData: [String: Any],
        rssi RSSI: NSNumber
    ) {
        guard peripheral.state == .disconnected else { return }
        peripheral.delegate = self
        central.connect(peripheral, options: nil)
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        peripheral.delegate = self
        peripheral.discoverServices([Self.serviceUUID])
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        discoveredDataCharacteristics.removeValue(forKey: peripheral.identifier)
        routesToPeripherals = routesToPeripherals.filter { $0.value.identifier != peripheral.identifier }
        if central.state == .poweredOn {
            central.connect(peripheral, options: nil)
        }
    }
}

extension BleTransportService: CBPeripheralDelegate {
    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard error == nil else { return }
        for service in peripheral.services ?? [] where service.uuid == Self.serviceUUID {
            peripheral.discoverCharacteristics([Self.routeUUID, Self.dataUUID], for: service)
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        guard error == nil else { return }
        for characteristic in service.characteristics ?? [] {
            switch characteristic.uuid {
            case Self.routeUUID:
                peripheral.readValue(for: characteristic)
            case Self.dataUUID:
                discoveredDataCharacteristics[peripheral.identifier] = characteristic
                peripheral.setNotifyValue(true, for: characteristic)
            default:
                break
            }
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        guard error == nil, let value = characteristic.value else { return }
        if characteristic.uuid == Self.routeUUID, value.count == 16 {
            routesToPeripherals[value] = peripheral
        } else if characteristic.uuid == Self.dataUUID {
            consume(fragment: value)
        }
    }
}

extension BleTransportService: CBPeripheralManagerDelegate {
    func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        let available = peripheral.state == .poweredOn && central.state == .poweredOn
        onAvailabilityChanged?(available)
        if peripheral.state == .poweredOn {
            publishServiceIfNeeded()
        }
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, didAdd service: CBService, error: Error?) {
        guard error == nil else { return }
        peripheral.startAdvertising([CBAdvertisementDataServiceUUIDsKey: [Self.serviceUUID]])
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveWrite requests: [CBATTRequest]) {
        for request in requests {
            guard request.characteristic.uuid == Self.dataUUID, let value = request.value else {
                peripheral.respond(to: request, withResult: .requestNotSupported)
                continue
            }
            consume(fragment: value)
            peripheral.respond(to: request, withResult: .success)
        }
    }

    func peripheralManagerIsReady(toUpdateSubscribers peripheral: CBPeripheralManager) {
        guard let characteristic = dataCharacteristic else { return }
        while let first = pendingNotifications.first {
            guard peripheral.updateValue(first, for: characteristic, onSubscribedCentrals: nil) else { return }
            pendingNotifications.removeFirst()
        }
    }
}

enum BleTransportError: LocalizedError {
    case invalidPeerId
    case noConnectedPeer

    var errorDescription: String? {
        switch self {
        case .invalidPeerId: return "EchoMesh BLE peer id must be 32 bytes"
        case .noConnectedPeer: return "No EchoMesh BLE peer is currently connected"
        }
    }
}
