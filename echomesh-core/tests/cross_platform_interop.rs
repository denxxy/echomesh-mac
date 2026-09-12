use bytes::BytesMut;
use echomesh_core::e2ee::decrypt_from_peer;
use echomesh_core::identity::{route_id_from_peer_id, ClientIdentity};
use echomesh_core::protocol::{Frame, FrameCodec, FRAME_SIZE};
use echomesh_core::route::{registration_frame, ROUTER_CONTROL_ID};
use echomesh_core::transport::{decode_direct_packet, encode_direct_packet};
use tokio_util::codec::Encoder;

#[test]
fn peer_route_id_vector_v1() {
    let peer_id = [0x01u8; 32];
    assert_eq!(hex::encode(route_id_from_peer_id(&peer_id)), "72cd6e8422c407fb6d098690f1130b7d");
}

#[test]
fn fixed_frame_vector_v1() {
    let frame = Frame::new([0xA5; 16], [0x5A; 8], bytes::Bytes::from_static(b"abc")).unwrap();
    let mut wire = BytesMut::new();
    FrameCodec::new().encode(frame, &mut wire).unwrap();
    assert_eq!(wire.len(), FRAME_SIZE);
    assert_eq!(hex::encode(&wire[..29]), "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a55a5a5a5a5a5a5a5a0003616263");
}

#[test]
fn relay_registration_vector_v2() {
    let identity = ClientIdentity::from_secret([0xA5; 32]);
    let frame = registration_frame(&identity);
    assert_eq!(frame.session_id, ROUTER_CONTROL_ID);
    assert_eq!(hex::encode(frame.payload), "454d5232a1d577350a959ecd921460e0ed89bd1429e5833a915a6429a4e3a7948475c338ef436eb82be89c92f059704403db9d559c2a2b16423cc6e8eb3f616cd0af35135be1d2c1dc667d01cdac4c247a7aac5f6429ca8df0af13ad733265009df84477ba1a8d4c9abb5a01ef42e9aba678af0c");
}

#[test]
fn client_e2ee_vector_v1() {
    let bob = ClientIdentity::from_secret([0x02; 32]);
    let alice = ClientIdentity::from_secret([0x01; 32]);
    let envelope = hex::decode("454d45318a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3945dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef220404040404040404040404040404040404040404040404040023467ed2dc658f18c3b12e2f824ec4115fb6deb880c3fd45941eca5150020db836cc7088c7de0e5034636ce1653afc3c7481b532ad3fb4191b783f16a1ade33e1d890772df17990898abca1d6ae1afc3791495c4ec337c9e761e4655cbc18afacbe8bf08").unwrap();
    let decrypted = decrypt_from_peer(&bob, alice.route_id(), &envelope).unwrap();
    assert_eq!(decrypted.sender_peer_id, alice.public_key());
    assert_eq!(decrypted.plaintext, b"cross-platform-e2ee");
}

#[test]
fn direct_packet_vector_v1() {
    let wire = encode_direct_packet(b"abc").unwrap();
    assert_eq!(hex::encode(&wire), "454d44310003616263");
    assert_eq!(decode_direct_packet(&wire).unwrap(), b"abc");
}
