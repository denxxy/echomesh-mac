use echomesh_core::{CoreEventsListener, DeliveryStatus, EchoMeshClient, EchoMeshError, MessageRecord, NetworkState};

struct NoopListener;
impl CoreEventsListener for NoopListener {
    fn on_state_changed(&self, _state: NetworkState) {}
    fn on_message_received(&self, _message: MessageRecord) {}
    fn on_message_status_updated(&self, _message_id: String, _status: DeliveryStatus) {}
    fn on_packet_received(&self, _sender: Vec<u8>, _data: Vec<u8>) {}
}

#[test]
fn production_connect_requires_explicit_relay_credential() {
    let temp_dir = std::env::temp_dir().join(format!("echomesh_auth_{}", rand::random::<u32>()));
    let client = EchoMeshClient::new(temp_dir.to_string_lossy().into_owned(), Box::new(NoopListener)).unwrap();
    let error = client
        .connect("127.0.0.1:9".into(), vec![0x42; 32], None)
        .expect_err("production connect must not fall back to a compiled credential");
    match error {
        EchoMeshError::ConnectionError(message) => assert!(message.contains("authentication token is required")),
        other => panic!("expected credential error, got {other:?}"),
    }
    assert_eq!(client.current_state(), NetworkState::Offline);
}
