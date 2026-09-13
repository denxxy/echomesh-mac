use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

use echomesh_core::noise::{NOISE_PATTERN, NOISE_TAG_LEN};
use echomesh_core::protocol::{Frame, FrameCodec, ECHO_SERVICE_PEER_ID, FRAME_SIZE};
use echomesh_core::route::{ROUTER_CONTROL_ID, ROUTE_REGISTER_MAGIC};
use echomesh_core::{CoreEventsListener, DeliveryStatus, EchoMeshClient, MessageRecord, NetworkState};

struct TestListener {
    connected: AtomicBool,
    got_echo: AtomicBool,
}

impl CoreEventsListener for TestListener {
    fn on_state_changed(&self, state: NetworkState) {
        if state == NetworkState::ConnectedRealityRelay {
            self.connected.store(true, Ordering::SeqCst);
        }
    }

    fn on_message_received(&self, message: MessageRecord) {
        if message.text == "TEST_PAYLOAD" {
            self.got_echo.store(true, Ordering::SeqCst);
        }
    }

    fn on_message_status_updated(&self, _message_id: String, _status: DeliveryStatus) {}

    fn on_packet_received(&self, _sender: Vec<u8>, data: Vec<u8>) {
        if data == b"TEST_PAYLOAD" {
            self.got_echo.store(true, Ordering::SeqCst);
        }
    }
}

#[test]
fn end_to_end_noise_handshake_and_echo() {
    let (addr_tx, addr_rx) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            let builder = snow::Builder::new(NOISE_PATTERN.parse().unwrap());
            let keypair = builder.generate_keypair().unwrap();
            let public_key = keypair.public.clone();
            let private_key = keypair.private.clone();

            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            addr_tx
                .send((listener.local_addr().unwrap(), public_key))
                .unwrap();
            let (mut stream, _) = listener.accept().await.unwrap();

            let mut tls_header = [0u8; 5];
            stream.read_exact(&mut tls_header).await.unwrap();
            let tls_len = u16::from_be_bytes([tls_header[3], tls_header[4]]) as usize;
            let mut tls_body = vec![0u8; tls_len];
            stream.read_exact(&mut tls_body).await.unwrap();

            let mut responder = snow::Builder::new(NOISE_PATTERN.parse().unwrap())
                .local_private_key(&private_key)
                .unwrap()
                .build_responder()
                .unwrap();

            let msg1_len = stream.read_u16().await.unwrap() as usize;
            let mut msg1 = vec![0u8; msg1_len];
            stream.read_exact(&mut msg1).await.unwrap();
            responder.read_message(&msg1, &mut [0u8; 256]).unwrap();

            let mut msg2 = vec![0u8; 256];
            let n2 = responder.write_message(&[], &mut msg2).unwrap();
            stream.write_u16(n2 as u16).await.unwrap();
            stream.write_all(&msg2[..n2]).await.unwrap();
            stream.flush().await.unwrap();

            let mut transport = responder.into_transport_mode().unwrap();

            async fn read_frame(
                stream: &mut tokio::net::TcpStream,
                transport: &mut snow::TransportState,
            ) -> Frame {
                let len = stream.read_u16().await.unwrap() as usize;
                let mut ciphertext = vec![0u8; len];
                stream.read_exact(&mut ciphertext).await.unwrap();
                let mut plaintext = vec![0u8; ciphertext.len()];
                let n = transport
                    .read_message(&ciphertext, &mut plaintext)
                    .unwrap();
                plaintext.truncate(n);
                Frame::from_slice(&plaintext).unwrap()
            }

            let registration = read_frame(&mut stream, &mut transport).await;
            assert_eq!(registration.session_id, ROUTER_CONTROL_ID);
            assert_eq!(&registration.payload[..4], ROUTE_REGISTER_MAGIC);

            let frame = read_frame(&mut stream, &mut transport).await;
            assert_eq!(frame.session_id, ECHO_SERVICE_PEER_ID[..16]);
            assert_eq!(&frame.payload[..], b"TEST_PAYLOAD");

            let mut encoded = bytes::BytesMut::with_capacity(FRAME_SIZE);
            tokio_util::codec::Encoder::encode(&mut FrameCodec::new(), frame, &mut encoded)
                .unwrap();
            let mut encrypted = vec![0u8; FRAME_SIZE + NOISE_TAG_LEN];
            let n = transport.write_message(&encoded, &mut encrypted).unwrap();
            stream.write_u16(n as u16).await.unwrap();
            stream.write_all(&encrypted[..n]).await.unwrap();
            stream.flush().await.unwrap();

            tokio::time::sleep(Duration::from_millis(100)).await;
        });
    });

    let (server_addr, server_public_key) = addr_rx.recv().unwrap();
    let state = Arc::new(TestListener {
        connected: AtomicBool::new(false),
        got_echo: AtomicBool::new(false),
    });

    struct Bridge(Arc<TestListener>);
    impl CoreEventsListener for Bridge {
        fn on_state_changed(&self, state: NetworkState) {
            self.0.on_state_changed(state);
        }
        fn on_message_received(&self, message: MessageRecord) {
            self.0.on_message_received(message);
        }
        fn on_message_status_updated(&self, id: String, status: DeliveryStatus) {
            self.0.on_message_status_updated(id, status);
        }
        fn on_packet_received(&self, sender: Vec<u8>, data: Vec<u8>) {
            self.0.on_packet_received(sender, data);
        }
    }

    let temp_dir = std::env::temp_dir().join(format!("echomesh_e2e_{}", rand::random::<u32>()));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let client = EchoMeshClient::new(
        temp_dir.to_string_lossy().to_string(),
        Box::new(Bridge(state.clone())),
    )
    .unwrap();

    client
        .connect(
            server_addr.to_string(),
            server_public_key,
            Some("test-relay-token".to_string()),
        )
        .unwrap();
    assert_eq!(client.current_state(), NetworkState::ConnectedRealityRelay);
    assert!(state.connected.load(Ordering::SeqCst));

    client
        .send_packet(ECHO_SERVICE_PEER_ID.to_vec(), b"TEST_PAYLOAD".to_vec())
        .unwrap();

    for _ in 0..20 {
        if state.got_echo.load(Ordering::SeqCst) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(state.got_echo.load(Ordering::SeqCst));
    server.join().unwrap();
}
