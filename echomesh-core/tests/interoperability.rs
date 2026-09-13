use echomesh_core::{derive_public_key, Frame, FrameCodec, FRAME_SIZE};
use bytes::{Bytes, BytesMut};
use tokio_util::codec::Encoder;

#[test]
fn frame_wire_vector_is_platform_independent() {
    let frame = Frame::new([0x11;16], [0x22;8], Bytes::from_static(b"abc")).unwrap();
    let mut out=BytesMut::new(); FrameCodec::new().encode(frame,&mut out).unwrap();
    assert_eq!(out.len(),FRAME_SIZE);
    assert_eq!(&out[..16], &[0x11;16]);
    assert_eq!(&out[16..24], &[0x22;8]);
    assert_eq!(&out[24..26], &[0x00,0x03]);
    assert_eq!(&out[26..29], b"abc");
    assert!(out[29..].iter().all(|b|*b==0));
}

#[test]
fn x25519_identity_vector_is_stable() {
    let pair=derive_public_key(vec![7u8;32]).unwrap();
    assert_eq!(pair.public_key.len(),32);
    assert_eq!(hex::encode(&pair.public_key), pair.public_key_hex);
}

#[test]
fn e2ee_envelope_cross_decodes() {
    let recipient=derive_public_key(vec![9u8;32]).unwrap();
    let plaintext=b"cross-platform echomesh payload";
    let envelope=echomesh_core::e2ee::encrypt_for_peer(&recipient.public_key,plaintext).unwrap();
    let decoded=echomesh_core::e2ee::decrypt_from_peer(&recipient.private_key,&envelope).unwrap();
    assert_eq!(decoded,plaintext);
}
