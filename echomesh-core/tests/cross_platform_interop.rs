use bytes::BytesMut;
use echomesh_core::identity::route_id_from_peer_id;
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
    assert_eq!(
        hex::encode(&wire[..29]),
        "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a55a5a5a5a5a5a5a5a0003616263"
    );
}

#[test]
fn relay_registration_vector_v1() {
    let frame = registration_frame([0xA5; 16]);
    assert_eq!(frame.session_id, ROUTER_CONTROL_ID);
    assert_eq!(hex::encode(frame.payload), "454d5231a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5");
}

#[test]
fn direct_packet_vector_v1() {
    let wire = encode_direct_packet(b"abc").unwrap();
    assert_eq!(hex::encode(&wire), "454d44310003616263");
    assert_eq!(decode_direct_packet(&wire).unwrap(), b"abc");
}
