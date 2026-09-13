use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::RngCore;

use crate::client::session::{ClientSessionManager, OutboundPacket};
use crate::crypto::IdentityKeyPair;
use crate::model::{Contact, ConversationSummary, MessageRecord};
use crate::storage::StorageManager;
use crate::{CoreEventsListener, DeliveryStatus, EchoMeshError, MessagePayload, NetworkState};

const ROUTE_REGISTRATION_ID: [u8; 16] = [0xF0; 16];
const ECHO_ROUTE_ID: [u8; 16] = [0xEE; 16];

#[derive(uniffi::Object)]
pub struct EchoMeshClient {
    storage_path: String,
    storage: Arc<StorageManager>,
    identity: IdentityKeyPair,
    listener: Arc<dyn CoreEventsListener>,
    state: Arc<RwLock<NetworkState>>,
    ping_ms: AtomicU32,
    runtime: Arc<tokio::runtime::Runtime>,
    shutdown_sender: Mutex<Option<tokio::sync::broadcast::Sender<()>>>,
    session_mgr: Arc<ClientSessionManager>,
    outbound_tx: Arc<RwLock<Option<tokio::sync::mpsc::Sender<OutboundPacket>>>>,
}

#[uniffi::export]
impl EchoMeshClient {
    #[uniffi::constructor]
    pub fn new(storage_path: String, listener: Box<dyn CoreEventsListener>) -> Result<Arc<Self>, EchoMeshError> {
        std::fs::create_dir_all(&storage_path).map_err(|e| EchoMeshError::StorageError(e.to_string()))?;
        let root = std::path::Path::new(&storage_path);
        let storage = Arc::new(StorageManager::new(root.join("echomesh.db"))?);
        let identity = crate::crypto::load_or_generate_identity(&root.join("identity.key"))?;
        let runtime = crate::runtime::shared_runtime()?;
        let (tx, _) = tokio::sync::broadcast::channel::<()>(4);
        Ok(Arc::new(Self {
            storage_path,
            storage,
            identity,
            listener: Arc::from(listener),
            state: Arc::new(RwLock::new(NetworkState::Offline)),
            ping_ms: AtomicU32::new(0),
            runtime,
            shutdown_sender: Mutex::new(Some(tx)),
            session_mgr: Arc::new(ClientSessionManager::new()),
            outbound_tx: Arc::new(RwLock::new(None)),
        }))
    }

    pub fn storage_path(&self) -> String { self.storage_path.clone() }
    pub fn current_state(&self) -> NetworkState { *self.state.read().unwrap() }
    pub fn ping_ms(&self) -> u32 { self.ping_ms.load(Ordering::Relaxed) }
    pub fn local_peer_id_hex(&self) -> String { self.identity.public_key_hex.clone() }
    pub fn local_peer_id(&self) -> Vec<u8> { self.identity.public_key.clone() }

    pub fn send_packet(&self, recipient: Vec<u8>, data: Vec<u8>) -> Result<(), EchoMeshError> {
        let guard = self.outbound_tx.read().unwrap();
        let tx = guard.as_ref().ok_or(EchoMeshError::NotReady)?;
        tx.try_send(OutboundPacket { recipient, data })
            .map_err(|e| EchoMeshError::ConnectionError(format!("outbound queue unavailable: {}", e)))
    }

    pub fn connect(&self, relay_address: String, relay_public_key: Vec<u8>, secret_token_hex: Option<String>) -> Result<(), EchoMeshError> {
        if relay_public_key.len() != 32 {
            return Err(EchoMeshError::InvalidKeyLength { expected: 32, actual: relay_public_key.len() as u32 });
        }
        let token_text = secret_token_hex.as_deref().map(str::trim).filter(|v| !v.is_empty()).ok_or_else(|| {
            EchoMeshError::ConnectionError("relay authentication token is required; no compiled default exists".into())
        })?;
        let token = hex::decode(token_text).unwrap_or_else(|_| token_text.as_bytes().to_vec());
        if token.is_empty() { return Err(EchoMeshError::ConnectionError("relay authentication token is empty".into())); }
        let server_key: [u8; 32] = relay_public_key.as_slice().try_into().unwrap();
        let clean_addr = relay_address.trim_start_matches("https://").trim_start_matches("http://").trim_start_matches("mesh://").to_string();

        self.session_mgr.set_handshake();
        *self.state.write().unwrap() = NetworkState::Connecting;
        self.listener.on_state_changed(NetworkState::Connecting);

        let timeout = Duration::from_secs(5);
        let identity_public = self.identity.public_key.clone();
        let connected = self.runtime.block_on(async {
            let mut stream = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&clean_addr)).await
                .map_err(|_| EchoMeshError::HandshakeTimeout("TCP connect timed out".into()))?
                .map_err(|e| EchoMeshError::ConnectionError(format!("TCP connection to {} failed: {}", clean_addr, e)))?;
            use tokio::io::AsyncWriteExt;
            let hello = crate::transport::PseudoTlsBuilder::new(token, "cloudflare.com").build();
            stream.write_all(&hello).await.map_err(|e| EchoMeshError::ConnectionError(e.to_string()))?;
            stream.flush().await.map_err(|e| EchoMeshError::ConnectionError(e.to_string()))?;
            let mut session = crate::noise::client_noise_handshake(&mut stream, &server_key, timeout).await?;
            let registration = crate::protocol::Frame::new(
                ROUTE_REGISTRATION_ID,
                [0u8; 8],
                bytes::Bytes::from(identity_public),
            ).map_err(|e| EchoMeshError::ConnectionError(e.to_string()))?;
            let packet = session.encrypt_frame(&registration)?;
            stream.write_all(&packet).await.map_err(|e| EchoMeshError::ConnectionError(e.to_string()))?;
            stream.flush().await.map_err(|e| EchoMeshError::ConnectionError(e.to_string()))?;
            Ok::<_, EchoMeshError>((stream, session))
        });

        match connected {
            Ok((stream, session)) => {
                self.ping_ms.store(38, Ordering::Relaxed);
                *self.state.write().unwrap() = NetworkState::ConnectedRealityRelay;
                self.listener.on_state_changed(NetworkState::ConnectedRealityRelay);
                self.start_relay_workers(stream, session);
                Ok(())
            }
            Err(err) => {
                *self.outbound_tx.write().unwrap() = None;
                self.session_mgr.disconnect();
                *self.state.write().unwrap() = NetworkState::Offline;
                self.listener.on_state_changed(NetworkState::Offline);
                Err(err)
            }
        }
    }

    pub fn disconnect(&self) -> Result<(), EchoMeshError> {
        *self.outbound_tx.write().unwrap() = None;
        self.session_mgr.disconnect();
        *self.state.write().unwrap() = NetworkState::Offline;
        self.ping_ms.store(0, Ordering::Relaxed);
        self.listener.on_state_changed(NetworkState::Offline);
        Ok(())
    }

    pub fn add_contact(&self, peer_id_hex: String, name: String) -> Result<(), EchoMeshError> {
        let peer_id = crate::model::parse_peer_id(&peer_id_hex)?;
        self.storage.save_contact(&Contact { peer_id: peer_id.to_vec(), name, added_at: now_millis() })
    }
    pub fn get_contacts(&self) -> Result<Vec<Contact>, EchoMeshError> { self.storage.get_contacts() }
    pub fn get_conversations(&self) -> Result<Vec<ConversationSummary>, EchoMeshError> { self.storage.get_conversations() }
    pub fn get_messages(&self, peer_id_hex: String, limit: u32) -> Result<Vec<MessageRecord>, EchoMeshError> {
        let id = crate::model::parse_peer_id(&peer_id_hex)?;
        self.storage.get_messages(&id, limit as usize, 0)
    }

    pub fn send_chat_message(&self, recipient_peer_id_hex: String, text: String) -> Result<MessageRecord, EchoMeshError> {
        let recipient = crate::model::parse_peer_id(&recipient_peer_id_hex)?;
        let mut msg = MessageRecord {
            id: format!("msg_{}_{}", now_millis(), rand::random::<u16>()),
            conversation_peer_id: recipient.to_vec(),
            sender_peer_id: self.identity.public_key.clone(),
            text: text.clone(),
            timestamp: now_millis(),
            is_outgoing: true,
            status: 0,
        };
        self.storage.save_message(&msg)?;
        match self.send_packet(recipient.to_vec(), text.into_bytes()) {
            Ok(()) => {
                msg.status = 1;
                self.storage.update_message_status(&msg.id, 1)?;
                self.listener.on_message_status_updated(msg.id.clone(), DeliveryStatus::Sent);
            }
            Err(e) => {
                msg.status = 2;
                self.storage.update_message_status(&msg.id, 2)?;
                self.listener.on_message_status_updated(msg.id.clone(), DeliveryStatus::Failed);
                return Err(e);
            }
        }
        Ok(msg)
    }

    pub fn send_message(&self, to: String, text: String) -> Result<MessagePayload, EchoMeshError> {
        let recipient_hex = if to.to_lowercase().contains("echo") {
            hex::encode(crate::protocol::ECHO_SERVICE_PEER_ID)
        } else {
            crate::model::parse_peer_id(&to)?;
            to.clone()
        };
        let record = self.send_chat_message(recipient_hex, text.clone())?;
        Ok(MessagePayload {
            id: record.id,
            sender: hex::encode(&self.identity.public_key),
            recipient: to,
            content: text,
            timestamp: record.timestamp,
            status: DeliveryStatus::Sent,
        })
    }

    pub fn shutdown(&self) -> Result<(), EchoMeshError> {
        let _ = self.disconnect();
        if let Some(tx) = self.shutdown_sender.lock().unwrap().take() { let _ = tx.send(()); }
        Ok(())
    }
}

impl EchoMeshClient {
    fn start_relay_workers(&self, tcp_stream: tokio::net::TcpStream, session: crate::noise::NoiseSession) {
        let (mut read_half, mut write_half) = tcp_stream.into_split();
        let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::channel::<OutboundPacket>(256);
        *self.outbound_tx.write().unwrap() = Some(outbound_tx.clone());
        let session = Arc::new(tokio::sync::Mutex::new(session));
        self.session_mgr.set_transport(session.clone(), outbound_tx);

        let mut shutdown_out = self.shutdown_sender.lock().unwrap().as_ref().map(|tx| tx.subscribe());
        let session_out = session.clone();
        let sender_private = self.identity.private_key.clone();
        let sender_public = self.identity.public_key.clone();
        self.runtime.spawn(async move {
            use tokio::io::AsyncWriteExt;
            loop {
                tokio::select! {
                    msg = outbound_rx.recv() => {
                        let Some(pkt) = msg else { break };
                        let mut route = [0u8; 16];
                        if pkt.recipient == crate::protocol::ECHO_SERVICE_PEER_ID {
                            route.copy_from_slice(&ECHO_ROUTE_ID);
                        } else {
                            if pkt.recipient.len() != 32 {
                                tracing::warn!("refusing packet with non-32-byte peer key");
                                continue;
                            }
                            route.copy_from_slice(&pkt.recipient[..16]);
                        }
                        let payload = if pkt.recipient == crate::protocol::ECHO_SERVICE_PEER_ID {
                            pkt.data
                        } else {
                            match crate::e2ee::encrypt_authenticated(&sender_private, &sender_public, &pkt.recipient, &pkt.data) {
                                Ok(v) => v,
                                Err(e) => {
                                    tracing::warn!("authenticated E2EE encrypt failed: {}", e);
                                    continue;
                                }
                            }
                        };
                        let mut nonce = [0u8; 8];
                        rand::thread_rng().fill_bytes(&mut nonce);
                        let frame = match crate::protocol::Frame::new(route, nonce, bytes::Bytes::from(payload)) {
                            Ok(f) => f,
                            Err(e) => {
                                tracing::warn!("frame construction failed: {}", e);
                                continue;
                            }
                        };
                        let packet = { let mut s = session_out.lock().await; s.encrypt_frame(&frame) };
                        let Ok(packet) = packet else { break };
                        if write_half.write_all(&packet).await.is_err() || write_half.flush().await.is_err() { break; }
                    }
                    _ = async {
                        if let Some(rx) = shutdown_out.as_mut() { let _ = rx.recv().await; }
                        else { std::future::pending::<()>().await }
                    } => break,
                }
            }
        });

        let listener = self.listener.clone();
        let storage = self.storage.clone();
        let local_private = self.identity.private_key.clone();
        let local_public = self.identity.public_key.clone();
        let state = self.state.clone();
        let outbound_ref = self.outbound_tx.clone();
        let session_mgr = self.session_mgr.clone();
        let session_in = session.clone();
        let mut shutdown_in = self.shutdown_sender.lock().unwrap().as_ref().map(|tx| tx.subscribe());
        self.runtime.spawn(async move {
            loop {
                tokio::select! {
                    result = read_encrypted_frame(&mut read_half, session_in.clone()) => {
                        let frame = match result {
                            Ok(Some(f)) => f,
                            Ok(None) => break,
                            Err(e) => { tracing::warn!("inbound frame failed: {}", e); break; }
                        };
                        let is_echo = frame.session_id == ECHO_ROUTE_ID;
                        let (sender, plaintext) = if is_echo {
                            (crate::protocol::ECHO_SERVICE_PEER_ID.to_vec(), frame.payload.to_vec())
                        } else {
                            match crate::e2ee::decrypt_authenticated(&local_private, &local_public, &frame.payload) {
                                Ok((sender, plain)) => {
                                    if sender[..16] != frame.session_id[..] {
                                        tracing::warn!("dropping E2EE payload: authenticated sender does not match relay route");
                                        continue;
                                    }
                                    (sender, plain)
                                }
                                Err(e) => {
                                    tracing::warn!("dropping unauthenticated E2EE payload: {}", e);
                                    continue;
                                }
                            }
                        };
                        let text = String::from_utf8(plaintext.clone()).unwrap_or_else(|_| hex::encode(&plaintext));
                        let record = MessageRecord {
                            id: format!("msg_{}_{}", now_millis(), rand::random::<u16>()),
                            conversation_peer_id: sender.clone(),
                            sender_peer_id: sender.clone(),
                            text,
                            timestamp: now_millis(),
                            is_outgoing: false,
                            status: 1,
                        };
                        let _ = storage.save_message(&record);
                        listener.on_message_received(record);
                        listener.on_packet_received(sender, plaintext);
                    }
                    _ = async {
                        if let Some(rx) = shutdown_in.as_mut() { let _ = rx.recv().await; }
                        else { std::future::pending::<()>().await }
                    } => break,
                }
            }
            *outbound_ref.write().unwrap() = None;
            session_mgr.disconnect();
            *state.write().unwrap() = NetworkState::Offline;
            listener.on_state_changed(NetworkState::Offline);
        });
    }
}

async fn read_encrypted_frame<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    session: Arc<tokio::sync::Mutex<crate::noise::NoiseSession>>,
) -> Result<Option<crate::protocol::Frame>, EchoMeshError> {
    use tokio::io::AsyncReadExt;
    let len = match reader.read_u16().await {
        Ok(v) => v as usize,
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(EchoMeshError::ConnectionError(e.to_string())),
    };
    if len == 0 || len > crate::noise::ENCRYPTED_FRAME_SIZE {
        return Err(EchoMeshError::ConnectionError("invalid encrypted frame length".into()));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await.map_err(|e| EchoMeshError::ConnectionError(e.to_string()))?;
    let mut s = session.lock().await;
    s.decrypt_frame(&buf).map(Some)
}

fn now_millis() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}
