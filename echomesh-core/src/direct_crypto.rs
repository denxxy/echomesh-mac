use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::e2ee::{decrypt_direct, encrypt_for_peer};
use crate::identity::ClientIdentity;
use crate::transport::ble::{fragment_packet, BleReassembler};
use crate::transport::direct::{decode_direct_packet, encode_direct_packet};
use crate::EchoMeshError;

#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct DirectMessage {
    pub sender_peer_id: Vec<u8>,
    pub data: Vec<u8>,
}

/// Crypto/framing boundary used by native LAN/BLE bearer implementations.
/// Native platform code only sees opaque direct packets/fragments.
#[derive(uniffi::Object)]
pub struct DirectTransportCrypto {
    identity: Arc<ClientIdentity>,
    ble_reassembler: Mutex<BleReassembler>,
}

#[uniffi::export]
impl DirectTransportCrypto {
    #[uniffi::constructor]
    pub fn new(storage_path: String) -> Result<Arc<Self>, EchoMeshError> {
        let identity = ClientIdentity::load_or_generate(Path::new(&storage_path))?;
        Ok(Arc::new(Self {
            identity: Arc::new(identity),
            ble_reassembler: Mutex::new(BleReassembler::new()),
        }))
    }

    pub fn local_peer_id(&self) -> Vec<u8> {
        self.identity.public_key_vec()
    }

    pub fn seal(&self, recipient_peer_id: Vec<u8>, data: Vec<u8>) -> Result<Vec<u8>, EchoMeshError> {
        let recipient: [u8; 32] = recipient_peer_id
            .as_slice()
            .try_into()
            .map_err(|_| EchoMeshError::InvalidKeyLength {
                expected: 32,
                actual: recipient_peer_id.len() as u32,
            })?;
        let envelope = encrypt_for_peer(&self.identity, &recipient, &data)?;
        encode_direct_packet(&envelope)
    }

    pub fn open(&self, packet: Vec<u8>) -> Result<DirectMessage, EchoMeshError> {
        let envelope = decode_direct_packet(&packet)?;
        let decrypted = decrypt_direct(&self.identity, envelope)?;
        Ok(DirectMessage {
            sender_peer_id: decrypted.sender_peer_id.to_vec(),
            data: decrypted.plaintext,
        })
    }

    pub fn ble_fragments(
        &self,
        packet: Vec<u8>,
        mtu: u32,
        message_id: u32,
    ) -> Result<Vec<Vec<u8>>, EchoMeshError> {
        fragment_packet(&packet, mtu as usize, message_id)
    }

    /// Adds one raw GATT fragment. Returns a complete authenticated direct
    /// message only when all fragments have arrived and E2EE verification passes.
    pub fn open_ble_fragment(&self, fragment: Vec<u8>) -> Result<Option<DirectMessage>, EchoMeshError> {
        let packet = self
            .ble_reassembler
            .lock()
            .map_err(|_| EchoMeshError::RuntimeError("BLE reassembler lock poisoned".to_string()))?
            .push(&fragment)?;
        packet.map(|packet| self.open(packet)).transpose()
    }

    pub fn reset_ble_reassembly(&self) -> Result<(), EchoMeshError> {
        self.ble_reassembler
            .lock()
            .map_err(|_| EchoMeshError::RuntimeError("BLE reassembler lock poisoned".to_string()))?
            .clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_contexts_exchange_authenticated_packets() {
        let alice = ClientIdentity::from_secret([1u8; 32]);
        let bob = ClientIdentity::from_secret([2u8; 32]);
        let envelope = encrypt_for_peer(&alice, &bob.public_key(), b"native bearer").unwrap();
        let packet = encode_direct_packet(&envelope).unwrap();
        let opened = decrypt_direct(&bob, decode_direct_packet(&packet).unwrap()).unwrap();
        assert_eq!(opened.sender_peer_id, alice.public_key());
        assert_eq!(opened.plaintext, b"native bearer");
    }
}
