use crate::EchoMeshError;
use base64::Engine;

pub type PeerId = [u8; 32];

#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Contact {
    pub peer_id: Vec<u8>,
    pub name: String,
    pub added_at: u64,
}

#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MessageRecord {
    pub id: String,
    pub conversation_peer_id: Vec<u8>,
    pub sender_peer_id: Vec<u8>,
    pub text: String,
    pub timestamp: u64,
    pub is_outgoing: bool,
    pub status: u8, // 0 = Sending, 1 = Sent, 2 = Failed
}

#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConversationSummary {
    pub peer_id: Vec<u8>,
    pub title: String,
    pub last_message: Option<String>,
    pub last_timestamp: u64,
    pub unread_count: u32,
}

/// Converts a byte slice to lowercase hex.
pub fn peer_id_to_hex(id: &[u8]) -> String {
    hex::encode(id)
}

/// Parses a 32-byte peer ID from hex (with or without 0x prefix).
pub fn hex_to_peer_id(s: &str) -> Result<PeerId, EchoMeshError> {
    let clean = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    let bytes = hex::decode(clean).map_err(|e| {
        EchoMeshError::StorageError(format!("Invalid hex string '{}': {}", s, e))
    })?;

    if bytes.len() != 32 {
        return Err(EchoMeshError::InvalidKeyLength {
            expected: 32,
            actual: bytes.len() as u32,
        });
    }

    let mut peer_id = [0u8; 32];
    peer_id.copy_from_slice(&bytes);
    Ok(peer_id)
}

/// Flexible parser that accepts Hex (with or without 0x), Base64, or Base58,
/// validating that the decoded result is exactly 32 bytes.
pub fn parse_peer_id(input: &str) -> Result<PeerId, EchoMeshError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(EchoMeshError::InvalidKeyLength {
            expected: 32,
            actual: 0,
        });
    }

    // 1. Try hex first if starts with 0x or 64 hex chars
    let clean_hex = trimmed.trim_start_matches("0x").trim_start_matches("0X");
    if clean_hex.len() == 64 {
        if let Ok(bytes) = hex::decode(clean_hex) {
            if bytes.len() == 32 {
                let mut id = [0u8; 32];
                id.copy_from_slice(&bytes);
                return Ok(id);
            }
        }
    }

    // 2. Try Base64
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(trimmed) {
        if bytes.len() == 32 {
            let mut id = [0u8; 32];
            id.copy_from_slice(&bytes);
            return Ok(id);
        }
    }

    // 3. Try Base58
    if let Ok(bytes) = bs58::decode(trimmed).into_vec() {
        if bytes.len() == 32 {
            let mut id = [0u8; 32];
            id.copy_from_slice(&bytes);
            return Ok(id);
        }
    }

    // 4. Fallback to hex_to_peer_id for detailed error reporting
    hex_to_peer_id(trimmed)
}
