use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, warn};

use crate::client::session::OutboundPacket;
use crate::e2ee::{decrypt_from_peer, encrypt_for_peer};
use crate::identity::ClientIdentity;
use crate::model::MessageRecord;
use crate::noise::{NoiseSession, ENCRYPTED_FRAME_SIZE};
use crate::protocol::{Frame, ECHO_SERVICE_PEER_ID};
use crate::route::{peer_route_id, registration_ack_route, registration_frame};
use crate::storage::StorageManager;
use crate::{CoreEventsListener, EchoMeshError};

pub async fn register_relay_route(
    stream: &mut TcpStream,
    session: &mut NoiseSession,
    identity: &ClientIdentity,
) -> Result<(), EchoMeshError> {
    let frame = registration_frame(identity.route_id());
    let packet = session.encrypt_frame(&frame)?;
    stream
        .write_all(&packet)
        .await
        .map_err(|e| EchoMeshError::ConnectionError(e.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|e| EchoMeshError::ConnectionError(e.to_string()))?;
    Ok(())
}

/// Single owner of an established relay socket and Noise state.
///
/// There are no separate inbound/outbound Noise mutex workers: the actor
/// serializes access to the cipher state while `tokio::select!` multiplexes
/// socket reads, application sends and shutdown.
pub async fn run_relay_actor(
    tcp_stream: TcpStream,
    mut session: NoiseSession,
    identity: Arc<ClientIdentity>,
    storage: Arc<StorageManager>,
    listener: Arc<dyn CoreEventsListener>,
    mut outbound_rx: mpsc::Receiver<OutboundPacket>,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> Result<(), EchoMeshError> {
    let (mut reader, mut writer) = tcp_stream.into_split();

    loop {
        tokio::select! {
            incoming = read_noise_packet(&mut reader) => {
                let Some(ciphertext) = incoming? else { break; };
                let frame = session.decrypt_frame(&ciphertext)?;
                handle_incoming_frame(&identity, &storage, &listener, frame)?;
            }
            outbound = outbound_rx.recv() => {
                let Some(packet) = outbound else { break; };
                send_outbound_packet(&mut writer, &mut session, &identity, packet).await?;
            }
            _ = shutdown_rx.recv() => {
                debug!("relay actor received shutdown");
                break;
            }
        }
    }

    Ok(())
}

async fn read_noise_packet(reader: &mut OwnedReadHalf) -> Result<Option<Vec<u8>>, EchoMeshError> {
    let len = match reader.read_u16().await {
        Ok(len) => len as usize,
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(EchoMeshError::ConnectionError(err.to_string())),
    };
    if len == 0 || len > ENCRYPTED_FRAME_SIZE {
        return Err(EchoMeshError::ConnectionError(
            "invalid encrypted relay frame length".to_string(),
        ));
    }
    let mut ciphertext = vec![0u8; len];
    reader
        .read_exact(&mut ciphertext)
        .await
        .map_err(|e| EchoMeshError::ConnectionError(e.to_string()))?;
    Ok(Some(ciphertext))
}

async fn send_outbound_packet(
    writer: &mut OwnedWriteHalf,
    session: &mut NoiseSession,
    identity: &ClientIdentity,
    packet: OutboundPacket,
) -> Result<(), EchoMeshError> {
    let mut nonce = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let frame = if packet.recipient == ECHO_SERVICE_PEER_ID {
        Frame::new(
            ECHO_SERVICE_PEER_ID[..16].try_into().expect("16-byte echo route"),
            nonce,
            bytes::Bytes::from(packet.data),
        )
        .map_err(|e| EchoMeshError::ConnectionError(format!("frame encoding: {e}")))?
    } else {
        let recipient: [u8; 32] = packet
            .recipient
            .as_slice()
            .try_into()
            .map_err(|_| EchoMeshError::InvalidKeyLength {
                expected: 32,
                actual: packet.recipient.len() as u32,
            })?;
        let encrypted = encrypt_for_peer(identity, &recipient, &packet.data)?;
        Frame::new(peer_route_id(&recipient), nonce, bytes::Bytes::from(encrypted))
            .map_err(|e| EchoMeshError::ConnectionError(format!("frame encoding: {e}")))?
    };

    let wire = session.encrypt_frame(&frame)?;
    writer
        .write_all(&wire)
        .await
        .map_err(|e| EchoMeshError::ConnectionError(e.to_string()))?;
    writer
        .flush()
        .await
        .map_err(|e| EchoMeshError::ConnectionError(e.to_string()))?;
    Ok(())
}

fn handle_incoming_frame(
    identity: &ClientIdentity,
    storage: &StorageManager,
    listener: &Arc<dyn CoreEventsListener>,
    frame: Frame,
) -> Result<(), EchoMeshError> {
    if let Some(route) = registration_ack_route(&frame) {
        if route == identity.route_id() {
            debug!("relay route registration acknowledged");
        } else {
            warn!("relay returned a mismatched route acknowledgement");
        }
        return Ok(());
    }

    let (sender_peer_id, plaintext) = if frame.session_id == ECHO_SERVICE_PEER_ID[..16] {
        (ECHO_SERVICE_PEER_ID, frame.payload.to_vec())
    } else {
        let decrypted = decrypt_from_peer(identity, frame.session_id, &frame.payload)?;
        (decrypted.sender_peer_id, decrypted.plaintext)
    };

    let text = String::from_utf8(plaintext.clone())
        .unwrap_or_else(|_| "[binary encrypted message]".to_string());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let message = MessageRecord {
        id: format!("msg_{}_{}", now, rand::random::<u16>()),
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
    use crate::e2ee::encrypt_for_peer;

    struct Sink;
    impl CoreEventsListener for Sink {
        fn on_state_changed(&self, _state: crate::NetworkState) {}
        fn on_message_received(&self, _message: MessageRecord) {}
        fn on_message_status_updated(&self, _message_id: String, _status: crate::DeliveryStatus) {}
        fn on_packet_received(&self, _sender: Vec<u8>, _data: Vec<u8>) {}
    }

    #[test]
    fn inbound_e2ee_uses_authenticated_sender_identity() {
        let alice = ClientIdentity::from_secret([1u8; 32]);
        let bob = ClientIdentity::from_secret([2u8; 32]);
        let payload = encrypt_for_peer(&alice, &bob.public_key(), b"hello").unwrap();
        let frame = Frame::new(alice.route_id(), [1u8; 8], bytes::Bytes::from(payload)).unwrap();
        let storage = StorageManager::new_in_memory().unwrap();
        let listener: Arc<dyn CoreEventsListener> = Arc::new(Sink);
        handle_incoming_frame(&bob, &storage, &listener, frame).unwrap();
        let messages = storage.get_messages(&alice.public_key(), 10, 0).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].text, "hello");
    }
}
