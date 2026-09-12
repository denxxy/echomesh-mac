use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

use echomesh_core::noise::{NOISE_PATTERN, NOISE_TAG_LEN};
use echomesh_core::protocol::{Frame, FrameCodec, ECHO_SERVICE_PEER_ID, FRAME_SIZE};
use echomesh_core::route::{ROUTER_CONTROL_ID, ROUTE_REGISTER_MAGIC};
use echomesh_core::{CoreEventsListener, DeliveryStatus, EchoMeshClient, EchoMeshError, MessageRecord, NetworkState};

struct MockListener { packet_received: AtomicBool }

impl CoreEventsListener for MockListener {
    fn on_state_changed(&self, _state: NetworkState) {}
    fn on_message_received(&self, _message: MessageRecord) {}
    fn on_message_status_updated(&self, _message_id: String, _status: DeliveryStatus) {}
    fn on_packet_received(&self, _sender: Vec<u8>, data: Vec<u8>) {
        if data == b"TEST_PAYLOAD" { self.packet_received.store(true, Ordering::SeqCst); }
    }
}

#[test]
fn test_send_packet_not_ready_when_disconnected() {
    let listener = Box::new(MockListener { packet_received: AtomicBool::new(false) });
    let temp_dir = std::env::temp_dir().join(format!("echomesh_test_{}", rand::random::<u32>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let client = EchoMeshClient::new(temp_dir.to_str().unwrap().to_string(), listener).unwrap();
    assert_eq!(client.send_packet(vec![1u8; 32], b"hello".to_vec()), Err(EchoMeshError::NotReady));
}

#[test]
fn test_send_packet_and_echo_flow() {
    let (addr_tx, addr_rx) = std::sync::mpsc::channel();
    let server_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let builder = snow::Builder::new(NOISE_PATTERN.parse().unwrap());
            let server_keypair = builder.generate_keypair().unwrap();
            let server_pub = server_keypair.public.clone();
            let server_priv = server_keypair.private.clone();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            addr_tx.send((listener.local_addr().unwrap(), server_pub)).unwrap();
            let (mut stream, _) = listener.accept().await.unwrap();

            let mut responder = snow::Builder::new(NOISE_PATTERN.parse().unwrap())
                .local_private_key(&server_priv).unwrap().build_responder().unwrap();
            let mut tls_header = [0u8; 5];
            stream.read_exact(&mut tls_header).await.unwrap();
            let mut tls_body = vec![0u8; u16::from_be_bytes([tls_header[3], tls_header[4]]) as usize];
            stream.read_exact(&mut tls_body).await.unwrap();
            let msg1_len = stream.read_u16().await.unwrap() as usize;
            let mut msg1 = vec![0u8; msg1_len];
            stream.read_exact(&mut msg1).await.unwrap();
            responder.read_message(&msg1, &mut [0u8; 128]).unwrap();
            let mut msg2 = vec![0u8; 128];
            let n2 = responder.write_message(&[], &mut msg2).unwrap();
            stream.write_u16(n2 as u16).await.unwrap();
            stream.write_all(&msg2[..n2]).await.unwrap();
            stream.flush().await.unwrap();
            let mut transport = responder.into_transport_mode().unwrap();

            async fn read_frame(stream: &mut tokio::net::TcpStream, transport: &mut snow::TransportState) -> Frame {
                use tokio::io::AsyncReadExt;
                let len = stream.read_u16().await.unwrap() as usize;
                let mut cipher = vec![0u8; len];
                stream.read_exact(&mut cipher).await.unwrap();
                let mut plain = vec![0u8; cipher.len()];
                let n = transport.read_message(&cipher, &mut plain).unwrap();
                plain.truncate(n);
                Frame::from_slice(&plain).unwrap()
            }

            let registration = read_frame(&mut stream, &mut transport).await;
            assert_eq!(registration.session_id, ROUTER_CONTROL_ID);
            assert_eq!(&registration.payload[..4], ROUTE_REGISTER_MAGIC);

            let received_frame = read_frame(&mut stream, &mut transport).await;
            assert_eq!(&received_frame.payload[..], b"TEST_PAYLOAD");
            assert_eq!(received_frame.session_id, ECHO_SERVICE_PEER_ID[..16]);

            let reply_frame = Frame::new(received_frame.session_id, received_frame.nonce, received_frame.payload).unwrap();
            let mut raw_reply = bytes::BytesMut::with_capacity(FRAME_SIZE);
            let mut codec = FrameCodec::new();
            tokio_util::codec::Encoder::encode(&mut codec, reply_frame, &mut raw_reply).unwrap();
            let mut cipher_reply = vec![0u8; raw_reply.len() + NOISE_TAG_LEN];
            let n = transport.write_message(&raw_reply, &mut cipher_reply).unwrap();
            stream.write_u16(n as u16).await.unwrap();
            stream.write_all(&cipher_reply[..n]).await.unwrap();
            stream.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        });
    });

    let (server_addr, server_pub) = addr_rx.recv().unwrap();
    let mock_listener = Arc::new(MockListener { packet_received: AtomicBool::new(false) });
    let temp_dir = std::env::temp_dir().join(format!("echomesh_test_{}", rand::random::<u32>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    struct ListenerBridge(Arc<MockListener>);
    impl CoreEventsListener for ListenerBridge {
        fn on_state_changed(&self, s: NetworkState) { self.0.on_state_changed(s); }
        fn on_message_received(&self, m: MessageRecord) { self.0.on_message_received(m); }
        fn on_message_status_updated(&self, id: String, st: DeliveryStatus) { self.0.on_message_status_updated(id, st); }
        fn on_packet_received(&self, sender: Vec<u8>, data: Vec<u8>) { self.0.on_packet_received(sender, data); }
    }
    let client = EchoMeshClient::new(temp_dir.to_str().unwrap().to_string(), Box::new(ListenerBridge(mock_listener.clone()))).unwrap();
    client.connect(server_addr.to_string(), server_pub, None).unwrap();
    assert_eq!(client.current_state(), NetworkState::ConnectedRealityRelay);
    client.send_packet(ECHO_SERVICE_PEER_ID.to_vec(), b"TEST_PAYLOAD".to_vec()).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert!(mock_listener.packet_received.load(Ordering::SeqCst));
    server_handle.join().unwrap();
}
