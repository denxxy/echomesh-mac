use crate::EchoMeshError;

pub const DIRECT_MAGIC: &[u8; 4] = b"EMD1";
pub const DIRECT_HEADER_LEN: usize = 6;
pub const DIRECT_MAX_PAYLOAD: usize = crate::protocol::MAX_PAYLOAD_SIZE;
pub const DIRECT_MAX_PACKET: usize = DIRECT_HEADER_LEN + DIRECT_MAX_PAYLOAD;

pub fn encode_direct_packet(payload: &[u8]) -> Result<Vec<u8>, EchoMeshError> {
    if payload.len() > DIRECT_MAX_PAYLOAD {
        return Err(EchoMeshError::ConnectionError(format!(
            "direct packet payload too large: {} > {}",
            payload.len(), DIRECT_MAX_PAYLOAD
        )));
    }
    let mut wire = Vec::with_capacity(DIRECT_HEADER_LEN + payload.len());
    wire.extend_from_slice(DIRECT_MAGIC);
    wire.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    wire.extend_from_slice(payload);
    Ok(wire)
}

pub fn decode_direct_packet(wire: &[u8]) -> Result<&[u8], EchoMeshError> {
    if wire.len() < DIRECT_HEADER_LEN || &wire[..4] != DIRECT_MAGIC {
        return Err(EchoMeshError::ConnectionError("invalid direct packet header".to_string()));
    }
    let len = u16::from_be_bytes([wire[4], wire[5]]) as usize;
    if len > DIRECT_MAX_PAYLOAD || wire.len() != DIRECT_HEADER_LEN + len {
        return Err(EchoMeshError::ConnectionError("invalid direct packet length".to_string()));
    }
    Ok(&wire[DIRECT_HEADER_LEN..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_packet_round_trip() {
        let wire = encode_direct_packet(b"opaque-e2ee-envelope").unwrap();
        assert_eq!(decode_direct_packet(&wire).unwrap(), b"opaque-e2ee-envelope");
    }
}
