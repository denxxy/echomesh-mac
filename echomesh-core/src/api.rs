use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::AsyncWriteExt;
use tracing::warn;
use zeroize::Zeroize;

use crate::client::actor::{register_relay_route, run_relay_actor};
use crate::client::session::{ClientSessionManager, OutboundPacket};
use crate::e2ee::{decrypt_direct, encrypt_for_peer};
use crate::identity::ClientIdentity;
use crate::model::{Contact, ConversationSummary, MessageRecord};
use crate::storage::StorageManager;
use crate::transport::{decode_direct_packet, encode_direct_packet};
use crate::{CoreEventsListener, DeliveryStatus, EchoMeshError, MessagePayload, NetworkState};

#[derive(uniffi::Object)]
pub struct EchoMeshClient {
    storage_path: String,
    storage: Arc<StorageManager>,
    identity: Arc<ClientIdentity>,
    listener: Arc<dyn CoreEventsListener>,
    state: Arc<RwLock<NetworkState>>,
    ping_ms: AtomicU32,
    runtime: Arc<tokio::runtime::Runtime>,
    shutdown_sender: Mutex<Option<tokio::sync::broadcast::Sender<()>>>,
    connection_generation: Arc<AtomicU64>,
    session_mgr: Arc<ClientSessionManager>,
}

#[uniffi::export]
impl EchoMeshClient {
    #[uniffi::constructor]
    pub fn new(
        storage_path: String,
        listener: Box<dyn CoreEventsListener>,
    ) -> Result<Arc<Self>, EchoMeshError> {
        let storage_dir = std::path::Path::new(&storage_path);
        std::fs::create_dir_all(storage_dir)
            .map_err(|e| EchoMeshError::StorageError(format!("create storage directory: {e}")))?;

        let identity = Arc::new(ClientIdentity::load_or_generate(storage_dir)?);
        let mut database_key = identity.database_key();
        let db_path = storage_dir.join("echomesh.db");
        let storage_result = StorageManager::new_encrypted(&db_path, &database_key);
        database_key.zeroize();
        let storage = Arc::new(storage_result?);

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| EchoMeshError::RuntimeError(e.to_string()))?;

        Ok(Arc::new(Self {
            storage_path,
            storage,
            identity,
            listener: Arc::from(listener),
            state: Arc::new(RwLock::new(NetworkState::Offline)),
            ping_ms: AtomicU32::new(0),
            runtime: Arc::new(runtime),
            shutdown_sender: Mutex::new(None),
            connection_generation: Arc::new(AtomicU64::new(0)),
            session_mgr: Arc::new(ClientSessionManager::new()),
        }))
    }

    pub fn storage_path(&self) -> String {
        self.storage_path.clone()
    }

    pub fn local_peer_id(&self) -> Vec<u8> {
        self.identity.public_key_vec()
    }

    pub fn local_peer_id_hex(&self) -> String {
        hex::encode(self.identity.public_key())
    }

    pub fn current_state(&self) -> NetworkState {
        *self.state.read().unwrap()
    }

    pub fn ping_ms(&self) -> u32 {
        self.ping_ms.load(Ordering::Relaxed)
    }

    pub fn send_packet(&self, recipient: Vec<u8>, data: Vec<u8>) -> Result<(), EchoMeshError> {
        self.session_mgr.send_packet(recipient, data)
    }

    /// Produces one opaque, authenticated E2EE packet for a LAN/BLE bearer.
    /// Native transport adapters never receive identity private-key material.
    pub fn build_direct_packet(
        &self,
        recipient: Vec<u8>,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, EchoMeshError> {
        let recipient: [u8; 32] = recipient
            .as_slice()
            .try_into()
            .map_err(|_| EchoMeshError::InvalidKeyLength {
                expected: 32,
                actual: recipient.len() as u32,
            })?;
        let envelope = encrypt_for_peer(&self.identity, &recipient, &data)?;
        encode_direct_packet(&envelope)
    }

    /// Accepts one complete EMD1 direct packet from LAN/BLE, verifies the
    /// signed sender identity, decrypts it, persists it and emits normal core
    /// callbacks exactly like relay delivery.
    pub fn receive_direct_packet(&self, packet: Vec<u8>) -> Result<(), EchoMeshError> {
        let envelope = decode_direct_packet(&packet)?;
        let decrypted = decrypt_direct(&self.identity, envelope)?;
        let text = String::from_utf8(decrypted.plaintext.clone())
            .unwrap_or_else(|_| "[binary encrypted message]".to_string());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let message = MessageRecord {
            id: format!("direct_{}_{}", now, rand::random::<u16>()),
            conversation_peer_id: decrypted.sender_peer_id.to_vec(),
            sender_peer_id: decrypted.sender_peer_id.to_vec(),
            text,
            timestamp: now,
            is_outgoing: false,
            status: 1,
        };
        self.storage.save_message(&message)?;
        self.listener.on_message_received(message);
        self.listener
            .on_packet_received(decrypted.sender_peer_id.to_vec(), decrypted.plaintext);
        Ok(())
    }

    pub fn connect(
        &self,
        relay_address: String,
        relay_public_key: Vec<u8>,
        secret_token_hex: Option<String>,
    ) -> Result<(), EchoMeshError> {
        if relay_public_key.len() != 32 {
            return Err(EchoMeshError::InvalidKeyLength {
                expected: 32,
                actual: relay_public_key.len() as u32,
            });
        }
        let token_value = secret_token_hex
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                EchoMeshError::ConnectionError(
                    "relay secret token is required; no built-in production credential is used"
                        .to_string(),
                )
            })?;
        let token = hex::decode(token_value).unwrap_or_else(|_| token_value.as_bytes().to_vec());
        if token.is_empty() {
            return Err(EchoMeshError::ConnectionError(
                "relay secret token is empty".to_string(),
            ));
        }

        let server_static_key: [u8; 32] = relay_public_key.as_slice().try_into().unwrap();
        let clean_addr = relay_address
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_start_matches("mesh://")
            .trim()
            .to_string();
        if clean_addr.is_empty() {
            return Err(EchoMeshError::ConnectionError("empty relay address".to_string()));
        }

        self.stop_active_connection();
        let generation = self.connection_generation.fetch_add(1, Ordering::SeqCst) + 1;
        self.session_mgr.set_handshake();
        self.set_state(NetworkState::Connecting);

        let identity = self.identity.clone();
        let connect_timeout = Duration::from_secs(5);
        let connect_result = self.runtime.block_on(async {
            let mut tcp_stream = match tokio::time::timeout(
                connect_timeout,
                tokio::net::TcpStream::connect(&clean_addr),
            )
            .await
            {
                Ok(Ok(stream)) => stream,
                Ok(Err(e)) => return Err(EchoMeshError::ConnectionError(e.to_string())),
                Err(_) => {
                    return Err(EchoMeshError::HandshakeTimeout(
                        "relay TCP connection timed out".to_string(),
                    ))
                }
            };

            let hello = crate::transport::PseudoTlsBuilder::new(token, "cloudflare.com").build();
            tcp_stream
                .write_all(&hello)
                .await
                .map_err(|e| EchoMeshError::ConnectionError(e.to_string()))?;
            tcp_stream
                .flush()
                .await
                .map_err(|e| EchoMeshError::ConnectionError(e.to_string()))?;

            let mut noise = crate::noise::client_noise_handshake(
                &mut tcp_stream,
                &server_static_key,
                connect_timeout,
            )
            .await?;
            register_relay_route(&mut tcp_stream, &mut noise, &identity).await?;
            Ok::<_, EchoMeshError>((tcp_stream, noise))
        });

        let (tcp_stream, noise_session) = match connect_result {
            Ok(value) => value,
            Err(error) => {
                self.session_mgr.disconnect();
                self.set_state(NetworkState::Offline);
                return Err(error);
            }
        };

        let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel::<OutboundPacket>(256);
        self.session_mgr.set_transport(outbound_tx);
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel::<()>(2);
        *self.shutdown_sender.lock().unwrap() = Some(shutdown_tx);
        self.ping_ms.store(38, Ordering::Relaxed);
        self.set_state(NetworkState::ConnectedRealityRelay);

        let identity = self.identity.clone();
        let storage = self.storage.clone();
        let listener = self.listener.clone();
        let state = self.state.clone();
        let session_mgr = self.session_mgr.clone();
        let generation_counter = self.connection_generation.clone();

        self.runtime.spawn(async move {
            if let Err(error) = run_relay_actor(
                tcp_stream,
                noise_session,
                identity,
                storage,
                listener.clone(),
                outbound_rx,
                shutdown_rx,
            )
            .await
            {
                warn!(error = %error, "relay actor stopped after connection error");
            }

            if generation_counter.load(Ordering::SeqCst) == generation {
                session_mgr.disconnect();
                *state.write().unwrap() = NetworkState::Offline;
                listener.on_state_changed(NetworkState::Offline);
            }
        });

        Ok(())
    }

    pub fn disconnect(&self) -> Result<(), EchoMeshError> {
        self.connection_generation.fetch_add(1, Ordering::SeqCst);
        self.stop_active_connection();
        self.session_mgr.disconnect();
        self.ping_ms.store(0, Ordering::Relaxed);
        self.set_state(NetworkState::Offline);
        Ok(())
    }

    pub fn add_contact(&self, peer_id_hex: String, name: String) -> Result<(), EchoMeshError> {
        let peer_id = crate::model::parse_peer_id(&peer_id_hex)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.storage.save_contact(&Contact {
            peer_id: peer_id.to_vec(),
            name,
            added_at: now,
        })
    }

    pub fn get_contacts(&self) -> Result<Vec<Contact>, EchoMeshError> {
        self.storage.get_contacts()
    }

    pub fn get_conversations(&self) -> Result<Vec<ConversationSummary>, EchoMeshError> {
        self.storage.get_conversations()
    }

    pub fn get_messages(
        &self,
        peer_id_hex: String,
        limit: u32,
    ) -> Result<Vec<MessageRecord>, EchoMeshError> {
        let peer_id = crate::model::parse_peer_id(&peer_id_hex)?;
        self.storage.get_messages(&peer_id, limit as usize, 0)
    }

    pub fn send_chat_message(
        &self,
        recipient_peer_id_hex: String,
        text: String,
    ) -> Result<MessageRecord, EchoMeshError> {
        let recipient = crate::model::parse_peer_id(&recipient_peer_id_hex)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let mut message = MessageRecord {
            id: format!("msg_{}_{}", now, rand::random::<u16>()),
            conversation_peer_id: recipient.to_vec(),
            sender_peer_id: self.identity.public_key_vec(),
            text: text.clone(),
            timestamp: now,
            is_outgoing: true,
            status: 0,
        };
        self.storage.save_message(&message)?;

        if self.session_mgr.is_transport() {
            match self.send_packet(recipient.to_vec(), text.into_bytes()) {
                Ok(()) => {
                    message.status = 1;
                    self.storage.update_message_status(&message.id, 1)?;
                    self.listener
                        .on_message_status_updated(message.id.clone(), DeliveryStatus::Sent);
                }
                Err(error) => {
                    message.status = 2;
                    let _ = self.storage.update_message_status(&message.id, 2);
                    self.listener
                        .on_message_status_updated(message.id.clone(), DeliveryStatus::Failed);
                    return Err(error);
                }
            }
        } else if recipient == crate::protocol::ECHO_SERVICE_PEER_ID {
            message.status = 1;
            self.storage.update_message_status(&message.id, 1)?;
            self.listener
                .on_message_status_updated(message.id.clone(), DeliveryStatus::Sent);
            self.spawn_local_echo(recipient, text);
        } else {
            message.status = 2;
            self.storage.update_message_status(&message.id, 2)?;
            self.listener
                .on_message_status_updated(message.id.clone(), DeliveryStatus::Failed);
        }
        Ok(message)
    }

    pub fn send_message(&self, to: String, text: String) -> Result<MessagePayload, EchoMeshError> {
        let recipient_hex = if to.to_lowercase().contains("echo") {
            hex::encode(crate::protocol::ECHO_SERVICE_PEER_ID)
        } else if crate::model::parse_peer_id(&to).is_ok() {
            to.clone()
        } else {
            return Err(EchoMeshError::CryptoError(
                "recipient must be a 32-byte EchoMesh peer identity".to_string(),
            ));
        };
        let record = self.send_chat_message(recipient_hex, text.clone())?;
        let status = if record.status == 2 {
            DeliveryStatus::Failed
        } else {
            DeliveryStatus::Sent
        };
        Ok(MessagePayload {
            id: record.id,
            sender: "me".to_string(),
            recipient: to,
            content: text,
            timestamp: record.timestamp,
            status,
        })
    }

    pub fn shutdown(&self) -> Result<(), EchoMeshError> {
        self.disconnect()
    }
}

impl EchoMeshClient {
    fn set_state(&self, state: NetworkState) {
        *self.state.write().unwrap() = state;
        self.listener.on_state_changed(state);
    }

    fn stop_active_connection(&self) {
        if let Some(tx) = self.shutdown_sender.lock().unwrap().take() {
            let _ = tx.send(());
        }
    }

    fn spawn_local_echo(&self, recipient: [u8; 32], text: String) {
        let storage = self.storage.clone();
        let listener = self.listener.clone();
        self.runtime.spawn(async move {
            tokio::time::sleep(Duration::from_millis(120)).await;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            let reply = MessageRecord {
                id: format!("echo_{}_{}", now, rand::random::<u16>()),
                conversation_peer_id: recipient.to_vec(),
                sender_peer_id: recipient.to_vec(),
                text: format!("Echoed: {}", text),
                timestamp: now,
                is_outgoing: false,
                status: 1,
            };
            let _ = storage.save_message(&reply);
            listener.on_message_received(reply);
            listener.on_packet_received(recipient.to_vec(), format!("Echoed: {}", text).into_bytes());
        });
    }
}
