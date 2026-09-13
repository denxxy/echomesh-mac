use std::sync::atomic::{AtomicBool, Ordering};

use echomesh_core::{CoreEventsListener, DeliveryStatus, EchoMeshClient, EchoMeshError, MessageRecord, NetworkState};

struct MockListener { packet_received: AtomicBool }
impl CoreEventsListener for MockListener {
    fn on_state_changed(&self, _state: NetworkState) {}
    fn on_message_received(&self, _message: MessageRecord) {}
    fn on_message_status_updated(&self, _message_id: String, _status: DeliveryStatus) {}
    fn on_packet_received(&self, _sender: Vec<u8>, _data: Vec<u8>) { self.packet_received.store(true, Ordering::SeqCst); }
}

#[test]
fn send_packet_is_not_ready_when_disconnected() {
    let temp_dir = std::env::temp_dir().join(format!("echomesh_packet_{}", rand::random::<u32>()));
    let client = EchoMeshClient::new(
        temp_dir.to_string_lossy().into_owned(),
        Box::new(MockListener { packet_received: AtomicBool::new(false) }),
    ).unwrap();
    assert_eq!(client.send_packet(vec![1u8; 32], b"hello".to_vec()), Err(EchoMeshError::NotReady));
}

#[test]
fn client_has_stable_32_byte_public_peer_identity() {
    let temp_dir = std::env::temp_dir().join(format!("echomesh_identity_{}", rand::random::<u32>()));
    let client = EchoMeshClient::new(
        temp_dir.to_string_lossy().into_owned(),
        Box::new(MockListener { packet_received: AtomicBool::new(false) }),
    ).unwrap();
    assert_eq!(client.local_peer_id().len(), 32);
    assert_eq!(client.local_peer_id_hex().len(), 64);
}
