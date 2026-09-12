use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;

use echomesh_core::noise::{NOISE_PATTERN, NOISE_TAG_LEN};
use echomesh_core::protocol::{Frame, FrameCodec};
use echomesh_core::{
    CoreEventsListener, DeliveryStatus, EchoMeshClient, MessageRecord, NetworkState,
};

struct TestEventListener {
    echo_received: AtomicBool,
    received_payload: std::sync::Mutex<Vec<u8>>,
    received_sender: std::sync::Mutex<Vec<u8>>,
}

impl TestEventListener {
    fn new() -> Self {
        Self {
            echo_received: AtomicBool::new(false),
            received_payload: std::sync::Mutex::new(Vec::new()),
            received_sender: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl CoreEventsListener for TestEventListener {
    fn on_state_changed(&self, _state: NetworkState) {}
    fn on_message_received(&self, _message: MessageRecord) {}
    fn on_message_status_updated(&self, _message_id: String, _status: DeliveryStatus) {}
    fn on_packet_received(&self, sender: Vec<u8>, data: Vec<u8>) {
        *self.received_sender.lock().unwrap() = sender;
        *self.received_payload.lock().unwrap() = data;
        self.echo_received.store(true, Ordering::SeqCst);
    }
}

#[test]
fn test_e2e_client_connect_and_echo_packet() {
    let (server_addr_tx, server_addr_rx) = std::sync::mpsc::channel();
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

    // 1. Launch standalone mock RelayListener (Pseudo-TLS + Noise NK + Echo loopback)
    let server_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async move {
            let builder = snow::Builder::new(NOISE_PATTERN.parse().unwrap());
            let server_keypair = builder.generate_keypair().unwrap();
            let server_pub = server_keypair.public.clone();
            let server_priv = server_keypair.private.clone();

            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            server_addr_tx.send((addr, server_pub)).unwrap();

            tokio::select! {
                res = listener.accept() => {
                    let (mut stream, _) = res.unwrap();

                    // Read Pseudo-TLS ClientHello
                    let mut tls_header = [0u8; 5];
                    stream.read_exact(&mut tls_header).await.unwrap();
                    let tls_body_len = u16::from_be_bytes([tls_header[3], tls_header[4]]) as usize;
                    let mut tls_body = vec![0u8; tls_body_len];
                    stream.read_exact(&mut tls_body).await.unwrap();

                    // Noise NK Handshake (Responder)
                    let builder = snow::Builder::new(NOISE_PATTERN.parse().unwrap());
                    let mut responder = builder
                        .local_private_key(&server_priv)
                        .unwrap()
                        .build_responder()
                        .unwrap();

                    // Read message 1 (-> e, es)
                    let msg1_len = stream.read_u16().await.unwrap() as usize;
                    let mut msg1 = vec![0u8; msg1_len];
                    stream.read_exact(&mut msg1).await.unwrap();
                    let mut dummy = [0u8; 128];
                    responder.read_message(&msg1, &mut dummy).unwrap();

                    // Write message 2 (<- e, ee)
                    let mut msg2 = vec![0u8; 128];
                    let n2 = responder.write_message(&[], &mut msg2).unwrap();
                    msg2.truncate(n2);
                    stream.write_u16(n2 as u16).await.unwrap();
                    stream.write_all(&msg2).await.unwrap();
                    stream.flush().await.unwrap();

                    let mut transport = responder.into_transport_mode().unwrap();

                    // Loop to handle frames and echo
                    loop {
                        tokio::select! {
                            len_res = stream.read_u16() => {
                                let frame_len = match len_res {
                                    Ok(l) => l as usize,
                                    Err(_) => break,
                                };

                                let mut cipher_frame = vec![0u8; frame_len];
                                if stream.read_exact(&mut cipher_frame).await.is_err() {
                                    break;
                                }

                                let mut plain_frame = vec![0u8; cipher_frame.len()];
                                let n = match transport.read_message(&cipher_frame, &mut plain_frame) {
                                    Ok(n) => n,
                                    Err(_) => break,
                                };
                                plain_frame.truncate(n);

                                let received_frame = match Frame::from_slice(&plain_frame) {
                                    Ok(f) => f,
                                    Err(_) => break,
                                };

                                // Echo frame back to client
                                let reply_frame = Frame::new(
                                    received_frame.session_id,
                                    received_frame.nonce,
                                    received_frame.payload,
                                ).unwrap();

                                let mut codec = FrameCodec::new();
                                use tokio_util::codec::Encoder;
                                let mut encoded = bytes::BytesMut::new();
                                codec.encode(reply_frame, &mut encoded).unwrap();

                                let mut out_cipher = vec![0u8; encoded.len() + NOISE_TAG_LEN];
                                let enc_n = transport.write_message(&encoded, &mut out_cipher).unwrap();
                                out_cipher.truncate(enc_n);

                                if stream.write_u16(enc_n as u16).await.is_err() {
                                    break;
                                }
                                if stream.write_all(&out_cipher).await.is_err() {
                                    break;
                                }
                                if stream.flush().await.is_err() {
                                    break;
                                }
                            }
                            _ = shutdown_rx.changed() => {
                                break;
                            }
                        }
                    }
                }
                _ = shutdown_rx.changed() => {}
            }
        });
    });

    let (relay_addr, relay_pub_key) = server_addr_rx.recv().unwrap();

    // 2. Setup client and connect with default disguise token
    let listener = Arc::new(TestEventListener::new());
    let temp_dir = std::env::temp_dir().join(format!("echomesh_e2e_{}", rand::random::<u32>()));
    let _ = std::fs::create_dir_all(&temp_dir);

    struct Bridge(Arc<TestEventListener>);
    impl CoreEventsListener for Bridge {
        fn on_state_changed(&self, s: NetworkState) { self.0.on_state_changed(s); }
        fn on_message_received(&self, m: MessageRecord) { self.0.on_message_received(m); }
        fn on_message_status_updated(&self, id: String, st: DeliveryStatus) { self.0.on_message_status_updated(id, st); }
        fn on_packet_received(&self, sender: Vec<u8>, data: Vec<u8>) { self.0.on_packet_received(sender, data); }
    }

    let client = EchoMeshClient::new(
        temp_dir.to_str().unwrap().to_string(),
        Box::new(Bridge(listener.clone())),
    )
    .unwrap();

    // Connect with secret_token_hex = None (must default to DEFAULT_SECRET_TOKEN)
    client
        .connect(relay_addr.to_string(), relay_pub_key, None)
        .expect("Client connect and handshake must succeed against RelayListener");

    assert_eq!(client.current_state(), NetworkState::ConnectedRealityRelay);

    // Verify connection remains stable past 1s idle (prevents premature socket drop)
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(
        client.current_state(),
        NetworkState::ConnectedRealityRelay,
        "Client must remain connected and not drop connection after 1.5s"
    );

    // 3. Send packet to Echo Service ([0xEE; 32])
    let echo_recipient = vec![0xEEu8; 32];
    let payload = b"Hello EchoMesh Wire Relay Loopback 1420b!".to_vec();

    client
        .send_packet(echo_recipient.clone(), payload.clone())
        .expect("send_packet must succeed in transport mode");

    // 4. Wait for echoed frame from relay
    let start = std::time::Instant::now();
    while !listener.echo_received.load(Ordering::SeqCst) && start.elapsed() < Duration::from_secs(3) {
        std::thread::sleep(Duration::from_millis(20));
    }

    assert!(
        listener.echo_received.load(Ordering::SeqCst),
        "Client must receive echoed packet from relay"
    );
    assert_eq!(*listener.received_payload.lock().unwrap(), payload);
    // The session_id returned is the first 16 bytes of the recipient ([0xEE; 16])
    assert_eq!(&listener.received_sender.lock().unwrap()[..16], &echo_recipient[..16]);

    // Cleanup
    let _ = client.disconnect();
    let _ = shutdown_tx.send(true);
    let _ = server_handle.join();
}
