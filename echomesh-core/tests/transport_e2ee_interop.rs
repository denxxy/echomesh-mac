use echomesh_core::e2ee::{decrypt_from_peer, encrypt_for_peer};
use echomesh_core::identity::ClientIdentity;
use echomesh_core::route::peer_route_id;
use echomesh_core::transport::{decode_direct_packet, encode_direct_packet, fragment_ble_packet, BleReassembler};

fn decrypt_direct(identity: &ClientIdentity, envelope: &[u8]) -> Vec<u8> {
    let sender: [u8; 32] = envelope[4..36].try_into().expect("EME1 sender id");
    decrypt_from_peer(identity, peer_route_id(&sender), envelope)
        .expect("authenticated direct E2EE envelope")
        .plaintext
}

#[test]
fn lan_direct_bearer_preserves_client_to_client_e2ee() {
    let alice = ClientIdentity::from_secret([0x11; 32]);
    let bob = ClientIdentity::from_secret([0x22; 32]);
    let envelope = encrypt_for_peer(&alice, &bob.public_key(), b"lan secret").unwrap();
    let packet = encode_direct_packet(&envelope).unwrap();
    let received = decode_direct_packet(&packet).unwrap();
    assert_eq!(decrypt_direct(&bob, received), b"lan secret");
}

#[test]
fn ble_fragments_preserve_client_to_client_e2ee_out_of_order() {
    let alice = ClientIdentity::from_secret([0x33; 32]);
    let bob = ClientIdentity::from_secret([0x44; 32]);
    let envelope = encrypt_for_peer(&alice, &bob.public_key(), b"ble secret over fragmented bearer").unwrap();
    let packet = encode_direct_packet(&envelope).unwrap();

    let mut fragments = fragment_ble_packet(&packet, 64, 0x10203040).unwrap();
    fragments.reverse();
    let mut reassembler = BleReassembler::new();
    let mut reconstructed = None;
    for fragment in fragments {
        if let Some(packet) = reassembler.push(&fragment).unwrap() {
            reconstructed = Some(packet);
        }
    }

    let reconstructed = reconstructed.expect("complete BLE packet");
    let received = decode_direct_packet(&reconstructed).unwrap();
    assert_eq!(decrypt_direct(&bob, received), b"ble secret over fragmented bearer");
}

#[test]
fn direct_bearer_tampering_is_rejected_by_e2ee() {
    let alice = ClientIdentity::from_secret([0x55; 32]);
    let bob = ClientIdentity::from_secret([0x66; 32]);
    let envelope = encrypt_for_peer(&alice, &bob.public_key(), b"authenticated").unwrap();
    let mut packet = encode_direct_packet(&envelope).unwrap();
    let last = packet.len() - 1;
    packet[last] ^= 0x01;
    let received = decode_direct_packet(&packet).unwrap();
    let sender: [u8; 32] = received[4..36].try_into().unwrap();
    assert!(decrypt_from_peer(&bob, peer_route_id(&sender), received).is_err());
}
