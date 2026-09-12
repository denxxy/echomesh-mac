use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, Mutex};

use crate::EchoMeshError;

/// EchoMesh private BLE service. Peers advertise this UUID and expose two
/// characteristics: a read-only 32-byte Ed25519 identity and a write-only inbox.
pub const ECHOMESH_BLE_SERVICE_UUID: uuid::Uuid =
    uuid::Uuid::from_u128(0x5e4d_0001_7a11_4ef0_9f84_4543_484f_4d53);
pub const ECHOMESH_BLE_IDENTITY_UUID: uuid::Uuid =
    uuid::Uuid::from_u128(0x5e4d_0002_7a11_4ef0_9f84_4543_484f_4d53);
pub const ECHOMESH_BLE_INBOX_UUID: uuid::Uuid =
    uuid::Uuid::from_u128(0x5e4d_0003_7a11_4ef0_9f84_4543_484f_4d53);

/// Conservative application MTU. The GATT backends negotiate the real ATT MTU,
/// but keeping application writes below 128 bytes works across the supported
/// desktop stacks and leaves room for the fragment header.
pub const BLE_APPLICATION_MTU: usize = 128;
pub const BLE_SCAN_WINDOW: Duration = Duration::from_millis(1500);
pub const BLE_POWER_ON_TIMEOUT: Duration = Duration::from_secs(8);

/// Native BLE transport. On macOS it is backed by CoreBluetooth; on Windows it
/// is backed by WinRT. Both roles run at once: every EchoMesh node advertises a
/// small GATT server and scans as a central when it has a message to send.
pub struct NativeBleTransport {
    inbound_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    #[cfg(all(feature = "native-ble", any(target_os = "macos", target_os = "windows")))]
    _server_task: tokio::task::JoinHandle<()>,
}

impl NativeBleTransport {
    pub async fn start(local_peer_id: [u8; 32]) -> Result<Arc<Self>, EchoMeshError> {
        imp::start(local_peer_id).await
    }

    /// Receives one complete opaque E2EE envelope from the native BLE bearer.
    pub async fn recv_envelope(&self) -> Option<Vec<u8>> {
        self.inbound_rx.lock().await.recv().await
    }

    /// Finds the peer by its cryptographic identity and writes an already-E2EE
    /// encrypted envelope to its GATT inbox.
    pub async fn send_envelope(
        &self,
        recipient_peer_id: [u8; 32],
        envelope: &[u8],
    ) -> Result<(), EchoMeshError> {
        imp::send_envelope(recipient_peer_id, envelope).await
    }
}

#[cfg(all(feature = "native-ble", any(target_os = "macos", target_os = "windows")))]
mod imp {
    use super::*;
    use std::collections::HashMap;

    use ble_peripheral_rust::{
        gatt::{
            characteristic::Characteristic,
            peripheral_event::{
                PeripheralEvent, ReadRequestResponse, RequestResponse, WriteRequestResponse,
            },
            properties::{AttributePermission, CharacteristicProperty},
            service::Service,
        },
        Peripheral as PeripheralServer, PeripheralImpl,
    };
    use btleplug::api::{Central, Manager as _, Peripheral as _, ScanFilter, WriteType};
    use btleplug::platform::Manager;

    use crate::transport::ble::{fragment_packet, BleReassembler};
    use crate::transport::direct::{decode_direct_packet, encode_direct_packet};

    pub async fn start(local_peer_id: [u8; 32]) -> Result<Arc<NativeBleTransport>, EchoMeshError> {
        let (event_tx, mut event_rx) = mpsc::channel::<PeripheralEvent>(256);
        let (inbound_tx, inbound_rx) = mpsc::channel::<Vec<u8>>(128);

        let mut peripheral = PeripheralServer::new(event_tx)
            .await
            .map_err(|e| ble_error("create peripheral", e))?;

        tokio::time::timeout(BLE_POWER_ON_TIMEOUT, async {
            loop {
                match peripheral.is_powered().await {
                    Ok(true) => break Ok::<(), EchoMeshError>(()),
                    Ok(false) => tokio::time::sleep(Duration::from_millis(100)).await,
                    Err(e) => break Err(ble_error("query peripheral power", e)),
                }
            }
        })
        .await
        .map_err(|_| EchoMeshError::ConnectionError("BLE adapter did not power on in time".into()))??;

        let service = Service {
            uuid: ECHOMESH_BLE_SERVICE_UUID,
            primary: true,
            characteristics: vec![
                Characteristic {
                    uuid: ECHOMESH_BLE_IDENTITY_UUID,
                    properties: vec![CharacteristicProperty::Read],
                    permissions: vec![AttributePermission::Readable],
                    value: None,
                    descriptors: vec![],
                },
                Characteristic {
                    uuid: ECHOMESH_BLE_INBOX_UUID,
                    properties: vec![CharacteristicProperty::Write],
                    permissions: vec![AttributePermission::Writeable],
                    value: None,
                    descriptors: vec![],
                },
            ],
        };
        peripheral
            .add_service(&service)
            .await
            .map_err(|e| ble_error("publish EchoMesh GATT service", e))?;
        peripheral
            .start_advertising("EchoMesh", &[ECHOMESH_BLE_SERVICE_UUID])
            .await
            .map_err(|e| ble_error("start BLE advertising", e))?;

        let server_task = tokio::spawn(async move {
            // Message IDs are only unique within one central, so isolate
            // reassembly by the OS-provided client identifier as well.
            let mut reassemblers: HashMap<String, BleReassembler> = HashMap::new();
            let _peripheral_lifetime = peripheral;

            while let Some(event) = event_rx.recv().await {
                match event {
                    PeripheralEvent::ReadRequest {
                        request,
                        offset,
                        responder,
                    } if request.service == ECHOMESH_BLE_SERVICE_UUID
                        && request.characteristic == ECHOMESH_BLE_IDENTITY_UUID =>
                    {
                        let offset = offset as usize;
                        let response = if offset <= local_peer_id.len() {
                            ReadRequestResponse {
                                value: local_peer_id[offset..].to_vec(),
                                response: RequestResponse::Success,
                            }
                        } else {
                            ReadRequestResponse {
                                value: Vec::new(),
                                response: RequestResponse::InvalidOffset,
                            }
                        };
                        let _ = responder.send(response);
                    }
                    PeripheralEvent::WriteRequest {
                        request,
                        offset,
                        value,
                        responder,
                    } if request.service == ECHOMESH_BLE_SERVICE_UUID
                        && request.characteristic == ECHOMESH_BLE_INBOX_UUID =>
                    {
                        if offset != 0 {
                            let _ = responder.send(WriteRequestResponse {
                                response: RequestResponse::InvalidOffset,
                            });
                            continue;
                        }

                        let reassembler = reassemblers
                            .entry(request.client.clone())
                            .or_insert_with(BleReassembler::new);
                        match reassembler.push(&value) {
                            Ok(Some(packet)) => match decode_direct_packet(&packet) {
                                Ok(envelope) => {
                                    let _ = inbound_tx.try_send(envelope.to_vec());
                                    let _ = responder.send(WriteRequestResponse {
                                        response: RequestResponse::Success,
                                    });
                                }
                                Err(_) => {
                                    let _ = responder.send(WriteRequestResponse {
                                        response: RequestResponse::UnlikelyError,
                                    });
                                }
                            },
                            Ok(None) => {
                                let _ = responder.send(WriteRequestResponse {
                                    response: RequestResponse::Success,
                                });
                            }
                            Err(_) => {
                                let _ = responder.send(WriteRequestResponse {
                                    response: RequestResponse::UnlikelyError,
                                });
                            }
                        }
                    }
                    PeripheralEvent::ReadRequest { responder, .. } => {
                        let _ = responder.send(ReadRequestResponse {
                            value: Vec::new(),
                            response: RequestResponse::RequestNotSupported,
                        });
                    }
                    PeripheralEvent::WriteRequest { responder, .. } => {
                        let _ = responder.send(WriteRequestResponse {
                            response: RequestResponse::RequestNotSupported,
                        });
                    }
                    PeripheralEvent::StateUpdate { .. }
                    | PeripheralEvent::CharacteristicSubscriptionUpdate { .. } => {}
                }
            }
        });

        Ok(Arc::new(NativeBleTransport {
            inbound_rx: Mutex::new(inbound_rx),
            _server_task: server_task,
        }))
    }

    pub async fn send_envelope(
        recipient_peer_id: [u8; 32],
        envelope: &[u8],
    ) -> Result<(), EchoMeshError> {
        let direct_packet = encode_direct_packet(envelope)?;
        let fragments = fragment_packet(
            &direct_packet,
            BLE_APPLICATION_MTU,
            rand::random::<u32>(),
        )?;

        let manager = Manager::new()
            .await
            .map_err(|e| btle_error("create central manager", e))?;
        let adapters = manager
            .adapters()
            .await
            .map_err(|e| btle_error("enumerate BLE adapters", e))?;
        if adapters.is_empty() {
            return Err(EchoMeshError::ConnectionError(
                "no Bluetooth adapter is available".into(),
            ));
        }

        for adapter in adapters {
            adapter
                .start_scan(ScanFilter {
                    services: vec![ECHOMESH_BLE_SERVICE_UUID],
                })
                .await
                .map_err(|e| btle_error("start BLE scan", e))?;
            tokio::time::sleep(BLE_SCAN_WINDOW).await;
            let peripherals = adapter
                .peripherals()
                .await
                .map_err(|e| btle_error("enumerate BLE peripherals", e))?;
            let _ = adapter.stop_scan().await;

            for peripheral in peripherals {
                if !peripheral
                    .is_connected()
                    .await
                    .map_err(|e| btle_error("query BLE connection", e))?
                {
                    if peripheral.connect().await.is_err() {
                        continue;
                    }
                }
                if peripheral.discover_services().await.is_err() {
                    let _ = peripheral.disconnect().await;
                    continue;
                }

                let chars = peripheral.characteristics();
                let identity_char = chars
                    .iter()
                    .find(|c| c.uuid == ECHOMESH_BLE_IDENTITY_UUID)
                    .cloned();
                let inbox_char = chars
                    .iter()
                    .find(|c| c.uuid == ECHOMESH_BLE_INBOX_UUID)
                    .cloned();
                let (Some(identity_char), Some(inbox_char)) = (identity_char, inbox_char) else {
                    let _ = peripheral.disconnect().await;
                    continue;
                };

                let identity = match peripheral.read(&identity_char).await {
                    Ok(value) => value,
                    Err(_) => {
                        let _ = peripheral.disconnect().await;
                        continue;
                    }
                };
                if identity.as_slice() != recipient_peer_id {
                    let _ = peripheral.disconnect().await;
                    continue;
                }

                for fragment in &fragments {
                    peripheral
                        .write(&inbox_char, fragment, WriteType::WithResponse)
                        .await
                        .map_err(|e| btle_error("write BLE fragment", e))?;
                }
                let _ = peripheral.disconnect().await;
                return Ok(());
            }
        }

        Err(EchoMeshError::ConnectionError(
            "target EchoMesh peer was not found over BLE".into(),
        ))
    }

    fn ble_error(context: &'static str, error: impl std::fmt::Display) -> EchoMeshError {
        EchoMeshError::ConnectionError(format!("{context}: {error}"))
    }

    fn btle_error(context: &'static str, error: impl std::fmt::Display) -> EchoMeshError {
        EchoMeshError::ConnectionError(format!("{context}: {error}"))
    }
}

#[cfg(not(all(feature = "native-ble", any(target_os = "macos", target_os = "windows"))))]
mod imp {
    use super::*;

    pub async fn start(_local_peer_id: [u8; 32]) -> Result<Arc<NativeBleTransport>, EchoMeshError> {
        Err(EchoMeshError::ConnectionError(
            "native BLE transport is unavailable on this target/build".into(),
        ))
    }

    pub async fn send_envelope(
        _recipient_peer_id: [u8; 32],
        _envelope: &[u8],
    ) -> Result<(), EchoMeshError> {
        Err(EchoMeshError::ConnectionError(
            "native BLE transport is unavailable on this target/build".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_ble_uuids_are_distinct() {
        assert_ne!(ECHOMESH_BLE_SERVICE_UUID, ECHOMESH_BLE_IDENTITY_UUID);
        assert_ne!(ECHOMESH_BLE_SERVICE_UUID, ECHOMESH_BLE_INBOX_UUID);
        assert_ne!(ECHOMESH_BLE_IDENTITY_UUID, ECHOMESH_BLE_INBOX_UUID);
    }
}
