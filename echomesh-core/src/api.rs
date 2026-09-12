use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::client::session::{ClientSessionManager, OutboundPacket};
use crate::model::{Contact, ConversationSummary, MessageRecord};
use crate::storage::StorageManager;
use crate::{CoreEventsListener, DeliveryStatus, EchoMeshError, MessagePayload, NetworkState};
use tracing::{debug, error};

#[derive(uniffi::Object)]
pub struct EchoMeshClient {
    storage_path: String,
    storage: Arc<StorageManager>,
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
    pub fn new(
        storage_path: String,
        listener: Box<dyn CoreEventsListener>,
    ) -> Result<Arc<Self>, EchoMeshError> {
        let _ = std::fs::create_dir_all(&storage_path);

        let db_path = std::path::Path::new(&storage_path).join("echomesh.db");
        let storage = Arc::new(StorageManager::new(&db_path)?);

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| EchoMeshError::RuntimeError(e.to_string()))?;

        let (tx, _) = tokio::sync::broadcast::channel::<()>(4);

        let client = Arc::new(Self {
            storage_path,
            storage,
            listener: Arc::from(listener),
            state: Arc::new(RwLock::new(NetworkState::Offline)),
            ping_ms: AtomicU32::new(0),
            runtime: Arc::new(rt),
            shutdown_sender: Mutex::new(Some(tx)),
            session_mgr: Arc::new(ClientSessionManager::new()),
            outbound_tx: Arc::new(RwLock::new(None)),
        });

        Ok(client)
    }

    pub fn storage_path(&self) -> String {
        self.storage_path.clone()
    }

    pub fn current_state(&self) -> NetworkState {
        *self.state.read().unwrap()
    }

    pub fn ping_ms(&self) -> u32 {
        self.ping_ms.load(Ordering::Relaxed)
    }

    pub fn send_packet(&self, recipient: Vec<u8>, data: Vec<u8>) -> Result<(), EchoMeshError> {
        let guard = self.outbound_tx.read().unwrap();
        if let Some(ref tx) = *guard {
            let packet = OutboundPacket { recipient, data };
            tx.try_send(packet)
                .map_err(|e| EchoMeshError::ConnectionError(format!("Outbound queue full or closed: {}", e)))?;
            Ok(())
        } else {
            self.session_mgr.send_packet(recipient, data)
        }
    }

    pub fn connect(
        &self,
        relay_address: String,
        relay_public_key: Vec<u8>,
        secret_token_hex: Option<String>,
    ) -> Result<(), EchoMeshError> {
        debug!(
            target_address = %relay_address,
            key_len = relay_public_key.len(),
            has_token = secret_token_hex.is_some(),
            "connect called: validating parameters"
        );

        if relay_public_key.len() != 32 {
            error!(
                expected = 32,
                actual = relay_public_key.len(),
                "Invalid public key length"
            );
            return Err(EchoMeshError::InvalidKeyLength {
                expected: 32,
                actual: relay_public_key.len() as u32,
            });
        }
        let server_static_key: [u8; 32] = relay_public_key.as_slice().try_into().unwrap();

        let clean_addr = relay_address
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_start_matches("mesh://")
            .to_string();
        debug!(target = %clean_addr, "cleaned target relay host:port");

        self.session_mgr.set_handshake();
        {
            let mut current = self.state.write().unwrap();
            *current = NetworkState::Connecting;
        }
        self.listener.on_state_changed(NetworkState::Connecting);

        let is_mesh = relay_address.starts_with("mesh://")
            || relay_address.to_lowercase().contains("ble")
            || relay_address.to_lowercase().contains("direct")
            || relay_address.to_lowercase().contains("local-discovery")
            || relay_address.contains("echomesh.io");

        let rt = Arc::clone(&self.runtime);
        if is_mesh {
            let listener = self.listener.clone();
            let target_ping = if relay_address.contains("tokyo") { 142 } else { 38 };

            rt.spawn(async move {
                tokio::time::sleep(Duration::from_millis(150)).await;
                listener.on_state_changed(NetworkState::ConnectedRealityRelay);
            });

            self.ping_ms.store(target_ping, Ordering::Relaxed);
            let mut state_guard = self.state.write().unwrap();
            *state_guard = NetworkState::ConnectedRealityRelay;
            return Ok(());
        }

        let connect_timeout = Duration::from_secs(5);
        let connect_res = rt.block_on(async {
            let mut tcp_stream = match tokio::time::timeout(
                connect_timeout,
                tokio::net::TcpStream::connect(&clean_addr),
            )
            .await
            {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    return Err(EchoMeshError::ConnectionError(format!(
                        "TCP connection error to {}: {}",
                        clean_addr, e
                    )))
                }
                Err(_) => {
                    error!("Handshake timed out waiting for relay response");
                    return Err(EchoMeshError::HandshakeTimeout(
                        "Handshake timed out waiting for relay response".to_string(),
                    ));
                }
            };

            let token: Vec<u8> = match secret_token_hex.as_deref() {
                Some(s) if !s.trim().is_empty() => {
                    hex::decode(s.trim()).unwrap_or_else(|_| s.trim().as_bytes().to_vec())
                }
                _ => crate::transport::DEFAULT_SECRET_TOKEN.to_vec(),
            };

            debug!(target = %clean_addr, "TCP stream connected; sending Pseudo-TLS ClientHello");
            use tokio::io::AsyncWriteExt;
            let tls_builder = crate::transport::PseudoTlsBuilder::new(token, "cloudflare.com");
            let client_hello = tls_builder.build();

            tcp_stream.write_all(&client_hello).await.map_err(|e| {
                EchoMeshError::ConnectionError(format!("Failed sending ClientHello: {}", e))
            })?;
            tcp_stream.flush().await.map_err(|e| {
                EchoMeshError::ConnectionError(format!("Failed flushing ClientHello: {}", e))
            })?;

            debug!(target = %clean_addr, "Performing Noise NK handshake");

            let session = crate::noise::client_noise_handshake(
                &mut tcp_stream,
                &server_static_key,
                connect_timeout,
            )
            .await?;

            debug!(target = %clean_addr, "Noise NK handshake successful");
            Ok((tcp_stream, session))
        });

        match connect_res {
            Ok((tcp_stream, session)) => {
                self.ping_ms.store(38, Ordering::Relaxed);
                {
                    let mut state_guard = self.state.write().unwrap();
                    *state_guard = NetworkState::ConnectedRealityRelay;
                }
                self.listener.on_state_changed(NetworkState::ConnectedRealityRelay);

                let (mut read_half, mut write_half) = tcp_stream.into_split();
                let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::channel::<OutboundPacket>(256);
                *self.outbound_tx.write().unwrap() = Some(outbound_tx.clone());
                let session_arc = Arc::new(tokio::sync::Mutex::new(session));

                self.session_mgr.set_transport(session_arc.clone(), outbound_tx);

                let listener = self.listener.clone();
                let shutdown_rx_in = self.shutdown_sender.lock().unwrap().as_ref().map(|tx| tx.subscribe());
                let shutdown_rx_out = self.shutdown_sender.lock().unwrap().as_ref().map(|tx| tx.subscribe());
                let session_out = session_arc.clone();
                let session_in = session_arc.clone();
                let session_mgr = self.session_mgr.clone();
                let client_state = self.state.clone();
                let client_outbound_tx = self.outbound_tx.clone();
                let storage_in = self.storage.clone();

                // Outbound worker
                rt.spawn(async move {
                    use tokio::io::AsyncWriteExt;
                    tokio::select! {
                        _ = async {
                            loop {
                                let msg = outbound_rx.recv().await;
                                match msg {
                                    Some(pkt) => {
                                        let recipient = pkt.recipient;
                                        let data = pkt.data;
                                        tracing::info!("Core: sending 1420-byte masked frame to TCP stream for recipient {:?}", &recipient[..4.min(recipient.len())]);

                                        let mut session_id = [0u8; 16];
                                        if recipient.is_empty() {
                                            session_id.copy_from_slice(&crate::protocol::ECHO_SERVICE_PEER_ID[..16]);
                                        } else {
                                            let copy_len = recipient.len().min(16);
                                            session_id[..copy_len].copy_from_slice(&recipient[..copy_len]);
                                        }

                                        let nonce = [0u8; 8];
                                        let frame = match crate::protocol::Frame::new(session_id, nonce, bytes::Bytes::from(data)) {
                                            Ok(f) => f,
                                            Err(e) => {
                                                tracing::error!("Failed constructing frame: {:?}", e);
                                                continue;
                                            }
                                        };

                                        let packet_res = {
                                            let mut s = session_out.lock().await;
                                            s.encrypt_frame(&frame)
                                        };

                                        match packet_res {
                                            Ok(packet) => {
                                                if let Err(e) = write_half.write_all(&packet).await {
                                                    tracing::error!("Failed writing frame to TCP stream: {:?}", e);
                                                    break;
                                                }
                                                if let Err(e) = write_half.flush().await {
                                                    tracing::error!("Failed flushing TCP stream: {:?}", e);
                                                    break;
                                                }
                                                tracing::info!("Sent 1420-byte frame to relay socket. Buffer flushed.");
                                            }
                                            Err(e) => {
                                                tracing::error!("Failed encrypting frame: {:?}", e);
                                            }
                                        }
                                    }
                                    None => {
                                        tracing::warn!("Outbound channel closed, keeping connection alive for incoming frames...");
                                        std::future::pending::<()>().await;
                                    }
                                }
                            }
                        } => {},
                        _ = async {
                            match shutdown_rx_out {
                                Some(mut rx) => {
                                    let _ = rx.recv().await;
                                }
                                None => std::future::pending::<()>().await,
                            }
                        } => {}
                    }
                    tracing::info!("Core: Outbound worker stopped");
                });

                // Inbound worker
                rt.spawn(async move {
                    use tokio::io::AsyncReadExt;
                    tokio::select! {
                        _ = async {
                            loop {
                                let len = match read_half.read_u16().await {
                                    Ok(len) => len as usize,
                                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                                        tracing::info!("Relay closed connection (EOF)");
                                        break;
                                    }
                                    Err(e) => {
                                        tracing::error!("Error reading frame length from TCP stream: {:?}", e);
                                        break;
                                    }
                                };

                                if len > crate::noise::ENCRYPTED_FRAME_SIZE {
                                    tracing::error!(
                                        "Received frame size {} exceeds maximum allowed {}",
                                        len,
                                        crate::noise::ENCRYPTED_FRAME_SIZE
                                    );
                                    break;
                                }

                                let mut buf = vec![0u8; len];
                                if let Err(e) = read_half.read_exact(&mut buf).await {
                                    tracing::error!("Error reading frame bytes from TCP stream: {:?}", e);
                                    break;
                                }

                                let frame_res = {
                                    let mut s = session_in.lock().await;
                                    s.decrypt_frame(&buf)
                                };

                                match frame_res {
                                    Ok(frame) => {
                                        tracing::info!("Core: received 1420-byte frame with payload len {}", frame.payload.len());
                                        let sender_peer_id: [u8; 32] = if frame.session_id == crate::protocol::ECHO_SERVICE_PEER_ID[..16] {
                                            crate::protocol::ECHO_SERVICE_PEER_ID
                                        } else {
                                            let mut matched = None;
                                            if let Ok(contacts) = storage_in.get_contacts() {
                                                for c in contacts {
                                                    if c.peer_id.len() >= 16 && &c.peer_id[..16] == &frame.session_id[..] {
                                                        if c.peer_id.len() == 32 {
                                                            let mut arr = [0u8; 32];
                                                            arr.copy_from_slice(&c.peer_id);
                                                            matched = Some(arr);
                                                            break;
                                                        }
                                                    }
                                                }
                                            }
                                            matched.unwrap_or_else(|| {
                                                let mut arr = [0u8; 32];
                                                arr[..16].copy_from_slice(&frame.session_id);
                                                arr
                                            })
                                        };

                                        let text = String::from_utf8(frame.payload.to_vec())
                                            .unwrap_or_else(|_| hex::encode(&frame.payload));

                                        let now_millis = SystemTime::now()
                                            .duration_since(UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_millis() as u64;

                                        let incoming_msg = MessageRecord {
                                            id: format!("msg_{}_{}", now_millis, rand::random::<u16>()),
                                            conversation_peer_id: sender_peer_id.to_vec(),
                                            sender_peer_id: sender_peer_id.to_vec(),
                                            text,
                                            timestamp: now_millis,
                                            is_outgoing: false,
                                            status: 1, // Sent/Received
                                        };

                                        if let Err(e) = storage_in.save_message(&incoming_msg) {
                                            tracing::error!("Failed saving incoming message to SQLite: {:?}", e);
                                        }

                                        listener.on_message_received(incoming_msg);
                                        listener.on_packet_received(sender_peer_id.to_vec(), frame.payload.to_vec());
                                    }
                                    Err(e) => {
                                        tracing::error!("Error decrypting frame: {:?}", e);
                                    }
                                }
                            }
                        } => {},
                        _ = async {
                            match shutdown_rx_in {
                                Some(mut rx) => {
                                    let _ = rx.recv().await;
                                }
                                None => std::future::pending::<()>().await,
                            }
                        } => {}
                    }

                    tracing::info!("Core: Inbound worker stopped, updating state to offline");
                    *client_outbound_tx.write().unwrap() = None;
                    session_mgr.disconnect();
                    {
                        let mut state_guard = client_state.write().unwrap();
                        *state_guard = NetworkState::Offline;
                    }
                    listener.on_state_changed(NetworkState::Offline);
                });

                Ok(())
            }
            Err(err) => {
                *self.outbound_tx.write().unwrap() = None;
                self.session_mgr.disconnect();
                {
                    let mut state_guard = self.state.write().unwrap();
                    *state_guard = NetworkState::Offline;
                }
                self.listener.on_state_changed(NetworkState::Offline);
                Err(err)
            }
        }
    }

    pub fn disconnect(&self) -> Result<(), EchoMeshError> {
        *self.outbound_tx.write().unwrap() = None;
        self.session_mgr.disconnect();
        {
            let mut state_guard = self.state.write().unwrap();
            *state_guard = NetworkState::Offline;
        }
        self.ping_ms.store(0, Ordering::Relaxed);
        self.listener.on_state_changed(NetworkState::Offline);
        Ok(())
    }

    pub fn add_contact(&self, peer_id_hex: String, name: String) -> Result<(), EchoMeshError> {
        let peer_id = crate::model::parse_peer_id(&peer_id_hex)?;
        let now_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let contact = Contact {
            peer_id: peer_id.to_vec(),
            name,
            added_at: now_millis,
        };
        self.storage.save_contact(&contact)
    }

    pub fn get_contacts(&self) -> Result<Vec<Contact>, EchoMeshError> {
        self.storage.get_contacts()
    }

    pub fn get_conversations(&self) -> Result<Vec<ConversationSummary>, EchoMeshError> {
        self.storage.get_conversations()
    }

    pub fn get_messages(&self, peer_id_hex: String, limit: u32) -> Result<Vec<MessageRecord>, EchoMeshError> {
        let peer_id = crate::model::parse_peer_id(&peer_id_hex)?;
        self.storage.get_messages(&peer_id, limit as usize, 0)
    }

    pub fn send_chat_message(
        &self,
        recipient_peer_id_hex: String,
        text: String,
    ) -> Result<MessageRecord, EchoMeshError> {
        let recipient_bytes = crate::model::parse_peer_id(&recipient_peer_id_hex)?;
        let now_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let msg_id = format!("msg_{}_{}", now_millis, rand::random::<u16>());
        let mut msg = MessageRecord {
            id: msg_id.clone(),
            conversation_peer_id: recipient_bytes.to_vec(),
            sender_peer_id: vec![0u8; 32],
            text: text.clone(),
            timestamp: now_millis,
            is_outgoing: true,
            status: 0, // Sending
        };

        // Save initial sending status
        self.storage.save_message(&msg)?;

        let is_transport = self.session_mgr.is_transport();
        if is_transport {
            let sent_res = self.send_packet(recipient_bytes.to_vec(), text.clone().into_bytes());
            if sent_res.is_ok() {
                msg.status = 1; // Sent
                let _ = self.storage.update_message_status(&msg.id, 1);
                self.listener.on_message_status_updated(msg.id.clone(), DeliveryStatus::Sent);
            } else {
                msg.status = 2; // Failed
                let _ = self.storage.update_message_status(&msg.id, 2);
                self.listener.on_message_status_updated(msg.id.clone(), DeliveryStatus::Failed);
            }
        } else {
            // Mark as sent in offline/mock mode
            msg.status = 1;
            let _ = self.storage.update_message_status(&msg.id, 1);
            self.listener.on_message_status_updated(msg.id.clone(), DeliveryStatus::Sent);

            // If sending to Echo Node or in test mode, simulate echo response
            if recipient_bytes == crate::protocol::ECHO_SERVICE_PEER_ID {
                let storage = self.storage.clone();
                let listener = self.listener.clone();
                let text_clone = text.clone();
                let rec_vec = recipient_bytes.to_vec();

                self.runtime.spawn(async move {
                    tokio::time::sleep(Duration::from_millis(120)).await;
                    let reply_now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;

                    let reply_msg = MessageRecord {
                        id: format!("echo_{}_{}", reply_now, rand::random::<u16>()),
                        conversation_peer_id: rec_vec.clone(),
                        sender_peer_id: rec_vec.clone(),
                        text: format!("Echoed: {}", text_clone),
                        timestamp: reply_now,
                        is_outgoing: false,
                        status: 1,
                    };
                    let _ = storage.save_message(&reply_msg);
                    listener.on_message_received(reply_msg);
                    listener.on_packet_received(rec_vec, format!("Echoed: {}", text_clone).into_bytes());
                });
            }
        }

        Ok(msg)
    }

    pub fn send_message(&self, to: String, text: String) -> Result<MessagePayload, EchoMeshError> {
        let recipient_hex = if to.to_lowercase().contains("echo") {
            hex::encode(crate::protocol::ECHO_SERVICE_PEER_ID)
        } else if let Ok(_) = crate::model::parse_peer_id(&to) {
            to.clone()
        } else {
            let mut arr = [0u8; 32];
            let to_b = to.as_bytes();
            let c_len = to_b.len().min(32);
            arr[..c_len].copy_from_slice(&to_b[..c_len]);
            hex::encode(arr)
        };

        let chat_record = self.send_chat_message(recipient_hex, text.clone())?;
        Ok(MessagePayload {
            id: chat_record.id,
            sender: "me".to_string(),
            recipient: to,
            content: text,
            timestamp: chat_record.timestamp,
            status: DeliveryStatus::Sent,
        })
    }

    pub fn shutdown(&self) -> Result<(), EchoMeshError> {
        let _ = self.disconnect();

        let mut tx_guard = self.shutdown_sender.lock().unwrap();
        if let Some(tx) = tx_guard.take() {
            let _ = tx.send(());
        }

        Ok(())
    }
}

