use bytes::Bytes;

use crate::identity::route_id_from_peer_id;
use crate::protocol::Frame;

pub type RouteId = [u8; 16];

pub const ROUTER_CONTROL_ID: RouteId = [0xEC; 16];
pub const ROUTE_REGISTER_MAGIC: &[u8; 4] = b"EMR1";
pub const ROUTE_REGISTERED_MAGIC: &[u8; 4] = b"EMA1";

pub fn peer_route_id(peer_id: &[u8; 32]) -> RouteId {
    route_id_from_peer_id(peer_id)
}

pub fn registration_frame(route_id: RouteId) -> Frame {
    let mut payload = Vec::with_capacity(20);
    payload.extend_from_slice(ROUTE_REGISTER_MAGIC);
    payload.extend_from_slice(&route_id);
    Frame::new(ROUTER_CONTROL_ID, [0u8; 8], Bytes::from(payload))
        .expect("route registration always fits in a frame")
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

    #[test]
    fn registration_wire_format_is_stable() {
        let route = [0xA5; 16];
        let frame = registration_frame(route);
        assert_eq!(frame.session_id, ROUTER_CONTROL_ID);
        assert_eq!(&frame.payload[..4], b"EMR1");
        assert_eq!(&frame.payload[4..], &route);
    }
}
