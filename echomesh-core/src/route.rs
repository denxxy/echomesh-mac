use bytes::Bytes;
use ed25519_dalek::{Signer, Verifier};

use crate::identity::{route_id_from_peer_id, ClientIdentity};
use crate::protocol::Frame;

pub type RouteId = [u8; 16];

pub const ROUTER_CONTROL_ID: RouteId = [0xEC; 16];
pub const ROUTE_REGISTER_MAGIC: &[u8; 4] = b"EMR1";
pub const ROUTE_REGISTERED_MAGIC: &[u8; 4] = b"EMA1";
pub const ROUTE_REGISTRATION_CONTEXT: &[u8] = b"EchoMesh route registration v2";

pub fn peer_route_id(peer_id: &[u8; 32]) -> RouteId {
    route_id_from_peer_id(peer_id)
}

pub fn registration_frame(identity: &ClientIdentity) -> Frame {
    let peer_id = identity.public_key();
    let route_id = identity.route_id();
    let mut signed = Vec::with_capacity(ROUTE_REGISTRATION_CONTEXT.len() + 48);
    signed.extend_from_slice(ROUTE_REGISTRATION_CONTEXT);
    signed.extend_from_slice(&route_id);
    signed.extend_from_slice(&peer_id);
    let signature = identity.signing_key().sign(&signed);

    let mut payload = Vec::with_capacity(116);
    payload.extend_from_slice(ROUTE_REGISTER_MAGIC);
    payload.extend_from_slice(&route_id);
    payload.extend_from_slice(&peer_id);
    payload.extend_from_slice(&signature.to_bytes());
    Frame::new(ROUTER_CONTROL_ID, [0u8; 8], Bytes::from(payload))
        .expect("signed route registration always fits in a frame")
}

pub fn registration_ack_route(frame: &Frame) -> Option<RouteId> {
    if frame.session_id != ROUTER_CONTROL_ID
        || frame.payload.len() != 20
        || &frame.payload[..4] != ROUTE_REGISTERED_MAGIC
    {
        return None;
    }
    let mut route_id = [0u8; 16];
    route_id.copy_from_slice(&frame.payload[4..20]);
    Some(route_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, VerifyingKey};

    #[test]
    fn registration_is_signed_and_bound_to_peer_route() {
        let identity = ClientIdentity::from_secret([0xA5; 32]);
        let frame = registration_frame(&identity);
        assert_eq!(frame.session_id, ROUTER_CONTROL_ID);
        assert_eq!(&frame.payload[..4], b"EMR1");
        assert_eq!(&frame.payload[4..20], &identity.route_id());
        assert_eq!(&frame.payload[20..52], &identity.public_key());
        assert_eq!(frame.payload.len(), 116);

        let mut signed = Vec::new();
        signed.extend_from_slice(ROUTE_REGISTRATION_CONTEXT);
        signed.extend_from_slice(&frame.payload[4..20]);
        signed.extend_from_slice(&frame.payload[20..52]);
        let key = VerifyingKey::from_bytes(&identity.public_key()).unwrap();
        let signature = Signature::from_slice(&frame.payload[52..116]).unwrap();
        key.verify(&signed, &signature).unwrap();
    }
}