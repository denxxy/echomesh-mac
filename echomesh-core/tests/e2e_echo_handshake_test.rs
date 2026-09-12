use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

use echomesh_core::{
    CoreEventsListener, DeliveryStatus, EchoMeshClient, MessagePayload, NetworkState,
};
use echomesh_relay::server::{ListenerConfig, RelayListener};

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
    fn on_message_received(&self, _message: MessagePayload) {}
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
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // 1. Launch real RelayListener with standard token validator
    let server_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async move {
            let config = ListenerConfig::new(
                "127.0.0.1:0".parse().unwrap(),
                echomesh_relay::config::DEFAULT_SECRET_TOKEN.to_vec(),
            )
            .with_fallback_target("127.0.0.1:443")
            .with_max_connections(50);

            let listener = RelayListener::bind(config).await.unwrap();
            let addr = listener.local_addr().unwrap();
            let pub_key = listener.secrets().public_key.clone();

            server_addr_tx.send((addr, pub_key)).unwrap();

            let _ = listener.run_with_shutdown(shutdown_rx).await;
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
        fn on_message_received(&self, m: MessagePayload) { self.0.on_message_received(m); }
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
