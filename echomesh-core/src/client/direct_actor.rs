use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::{broadcast, mpsc};
use tracing::debug;

use crate::client::session::OutboundPacket;
use crate::e2ee::{decrypt_from_peer, encrypt_for_peer, E2EE_MAGIC};
use crate::identity::ClientIdentity;
use crate::model::MessageRecord;
use crate::route::peer_route_id;
use crate::storage::StorageManager;
use crate::transport::lan::LanPeerStream;
use crate::{CoreEventsListener, EchoMeshError};

/// Runs an authenticated direct LAN connection using exactly the same E2EE
/// envelope as the relay path. The LAN peer address is therefore only a bearer
/// hint; the cryptographic recipient/sender identities remain authoritative.
pub async fn run_lan_actor(
    mut stream: LanPeerStream,
    expected_peer_id: [u8; 32],
    identity: Arc<ClientIdentity>,
    storage: Arc<StorageManager>,
    listener: Arc<dyn CoreEventsListener>,
    mut outbound_rx: mpsc::Receiver<OutboundPacket>,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> Result<(), EchoMeshError> {
    loop {
        tokio::select! {
            inbound = stream.recv_envelope() => {
                let Some(envelope) = inbound? else { break; };
                let decrypted = decrypt_direct_envelope(&identity, &envelope)?;
                if decrypted.sender_peer_id != expected_peer_id {
                    return Err(EchoMeshError::CryptoError(
                        "LAN peer identity does not match the expected contact".to_string(),
                    ));
                }
                persist_incoming(&storage, &listener, decrypted.sender_peer_id, decrypted.plaintext)?;
            }
            outbound = outbound_rx.recv() => {
                let Some(packet) = outbound else { break; };
                let recipient: [u8; 32] = packet.recipient.as_slice().try_into().map_err(|_| {
                    EchoMeshError::InvalidKeyLength {
                        expected: 32,
                        actual: packet.recipient.len() as u32,
                    }
                })?;
                if recipient != expected_peer_id {
                    return Err(EchoMeshError::ConnectionError(
                        "LAN connection is bound to a different peer".to_string(),
                    ));
                }
                let envelope = encrypt_for_peer(&identity, &recipient, &packet.data)?;
                stream.send_envelope(&envelope).await?;
            }
            _ = shutdown_rx.recv() => {
                debug!("LAN actor received shutdown");
                break;
            }
        }
    }
    Ok(())
}

fn decrypt_direct_envelope(
    identity: &ClientIdentity,
    envelope: &[u8],
) -> Result<crate::e2ee::DecryptedEnvelope, EchoMeshError> {
    if envelope.len() < 36 || &envelope[..4] != E2EE_MAGIC {
        return Err(EchoMeshError::CryptoError(
            "invalid direct E2EE envelope".to_string(),
        ));
    }
    let mut sender = [0u8; 32];
    sender.copy_from_slice(&envelope[4..36]);
    decrypt_from_peer(identity, peer_route_id(&sender), envelope)
}

fn persist_incoming(
    storage: &StorageManager,
    listener: &Arc<dyn CoreEventsListener>,
    sender_peer_id: [u8; 32],
    plaintext: Vec<u8>,
) -> Result<(), EchoMeshError> {
    let text = String::from_utf8(plaintext.clone())
        .unwrap_or_else(|_| "[binary encrypted message]".to_string());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let message = MessageRecord {
        id: format!("lan_{}_{}", now, rand::random::<u16>()),
        conversation_peer_id: sender_peer_id.to_vec(),
        sender_peer_id: sender_peer_id.to_vec(),
        text,
        timestamp: now,
        is_outgoing: false,
        status: 1,
    };
    storage.save_message(&message)?;
    listener.on_message_received(message);
    listener.on_packet_received(sender_peer_id.to_vec(), plaintext);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_envelope_authenticates_sender_without_outer_route() {
        let alice = ClientIdentity::from_secret([1u8; 32]);
        let bob = ClientIdentity::from_secret([2u8; 32]);
        let envelope = encrypt_for_peer(&alice, &bob.public_key(), b"lan hello").unwrap();
        let decrypted = decrypt_direct_envelope(&bob, &envelope).unwrap();
        assert_eq!(decrypted.sender_peer_id, alice.public_key());
        assert_eq!(decrypted.plaintext, b"lan hello");
    }
}
