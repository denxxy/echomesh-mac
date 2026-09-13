use std::collections::HashMap;

use crate::transport::direct::DIRECT_MAX_PACKET;
use crate::EchoMeshError;

pub const BLE_FRAGMENT_MAGIC: &[u8; 4] = b"EMB1";
pub const BLE_FRAGMENT_HEADER_LEN: usize = 12;
pub const BLE_MIN_MTU: usize = 32;
pub const BLE_MAX_FRAGMENTS: usize = 128;

pub fn fragment_packet(packet: &[u8], mtu: usize, message_id: u32) -> Result<Vec<Vec<u8>>, EchoMeshError> {
    if mtu < BLE_MIN_MTU || mtu <= BLE_FRAGMENT_HEADER_LEN {
        return Err(EchoMeshError::ConnectionError("BLE MTU is too small".to_string()));
    }
    if packet.len() > DIRECT_MAX_PACKET {
        return Err(EchoMeshError::ConnectionError("BLE direct packet exceeds maximum size".to_string()));
    }
    let chunk_size = mtu - BLE_FRAGMENT_HEADER_LEN;
    let total = packet.len().div_ceil(chunk_size).max(1);
    if total > BLE_MAX_FRAGMENTS || total > u16::MAX as usize {
        return Err(EchoMeshError::ConnectionError("BLE packet requires too many fragments".to_string()));
    }

    let mut fragments = Vec::with_capacity(total);
    if packet.is_empty() {
        fragments.push(encode_fragment(message_id, 0, 1, &[]));
        return Ok(fragments);
    }
    for (index, chunk) in packet.chunks(chunk_size).enumerate() {
        fragments.push(encode_fragment(message_id, index as u16, total as u16, chunk));
    }
    Ok(fragments)
}

fn encode_fragment(message_id: u32, index: u16, total: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(BLE_FRAGMENT_HEADER_LEN + payload.len());
    out.extend_from_slice(BLE_FRAGMENT_MAGIC);
    out.extend_from_slice(&message_id.to_be_bytes());
    out.extend_from_slice(&index.to_be_bytes());
    out.extend_from_slice(&total.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

#[derive(Default)]
pub struct BleReassembler {
    pending: HashMap<u32, Assembly>,
}

struct Assembly {
    parts: Vec<Option<Vec<u8>>>,
    received: usize,
    bytes: usize,
}

impl BleReassembler {
    pub fn new() -> Self { Self::default() }

    pub fn push(&mut self, fragment: &[u8]) -> Result<Option<Vec<u8>>, EchoMeshError> {
        if fragment.len() < BLE_FRAGMENT_HEADER_LEN || &fragment[..4] != BLE_FRAGMENT_MAGIC {
            return Err(EchoMeshError::ConnectionError("invalid BLE fragment".to_string()));
        }
        let message_id = u32::from_be_bytes(fragment[4..8].try_into().unwrap());
        let index = u16::from_be_bytes(fragment[8..10].try_into().unwrap()) as usize;
        let total = u16::from_be_bytes(fragment[10..12].try_into().unwrap()) as usize;
        if total == 0 || total > BLE_MAX_FRAGMENTS || index >= total {
            return Err(EchoMeshError::ConnectionError("invalid BLE fragment sequence".to_string()));
        }

        let payload = &fragment[BLE_FRAGMENT_HEADER_LEN..];
        let assembly = self.pending.entry(message_id).or_insert_with(|| Assembly {
            parts: vec![None; total],
            received: 0,
            bytes: 0,
        });
        if assembly.parts.len() != total {
            self.pending.remove(&message_id);
            return Err(EchoMeshError::ConnectionError("BLE fragment count changed mid-message".to_string()));
        }
        if assembly.parts[index].is_none() {
            assembly.bytes += payload.len();
            if assembly.bytes > DIRECT_MAX_PACKET {
                self.pending.remove(&message_id);
                return Err(EchoMeshError::ConnectionError("BLE reassembly exceeds maximum packet size".to_string()));
            }
            assembly.parts[index] = Some(payload.to_vec());
            assembly.received += 1;
        }
        if assembly.received != total { return Ok(None); }

        let assembly = self.pending.remove(&message_id).expect("assembly exists");
        let mut packet = Vec::with_capacity(assembly.bytes);
        for part in assembly.parts {
            packet.extend_from_slice(&part.expect("all fragments received"));
        }
        Ok(Some(packet))
    }

    pub fn discard(&mut self, message_id: u32) {
        self.pending.remove(&message_id);
    }

    pub fn clear(&mut self) {
        self.pending.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragments_reassemble_out_of_order() {
        let packet = vec![0xA5; 1000];
        let mut fragments = fragment_packet(&packet, 128, 42).unwrap();
        fragments.reverse();
        let mut reassembler = BleReassembler::new();
        let mut complete = None;
        for fragment in fragments {
            if let Some(packet) = reassembler.push(&fragment).unwrap() { complete = Some(packet); }
        }
        assert_eq!(complete.unwrap(), packet);
    }

    #[test]
    fn duplicate_fragment_is_idempotent() {
        let fragments = fragment_packet(b"hello world", 32, 7).unwrap();
        let mut reassembler = BleReassembler::new();
        assert_eq!(reassembler.push(&fragments[0]).unwrap(), Some(b"hello world".to_vec()));
    }

    #[test]
    fn rejects_invalid_fragment_count() {
        let mut fragment = encode_fragment(1, 0, (BLE_MAX_FRAGMENTS + 1) as u16, b"x");
        assert!(BleReassembler::new().push(&fragment).is_err());
        fragment.clear();
    }
}
