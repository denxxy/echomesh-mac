use bytes::{BufMut, Bytes, BytesMut};
use std::fmt;
use tokio_util::codec::{Decoder, Encoder};

pub const FRAME_SIZE: usize = 1420;
pub const SESSION_ID_SIZE: usize = 16;
pub const NONCE_SIZE: usize = 8;
pub const PAYLOAD_LEN_SIZE: usize = 2;
pub const HEADER_SIZE: usize = SESSION_ID_SIZE + NONCE_SIZE + PAYLOAD_LEN_SIZE;
pub const MAX_PAYLOAD_SIZE: usize = FRAME_SIZE - HEADER_SIZE;

pub type SessionId = [u8; SESSION_ID_SIZE];
pub type Nonce = [u8; NONCE_SIZE];

pub const ECHO_PEER_ID: [u8; 32] = [0xEE; 32];
pub const ECHO_SERVICE_PEER_ID: [u8; 32] = ECHO_PEER_ID;

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("frame is too short: expected {expected} bytes, got {actual}")]
    FrameTooShort { expected: usize, actual: usize },
    #[error("payload length {actual} exceeds maximum allowed size of {max} bytes")]
    PayloadTooLarge { actual: usize, max: usize },
    #[error("I/O error occurred")]
    Io,
}

impl From<std::io::Error> for ProtocolError {
    fn from(_: std::io::Error) -> Self { Self::Io }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Frame {
    pub session_id: SessionId,
    pub nonce: Nonce,
    pub payload: Bytes,
}

impl fmt::Debug for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Frame")
            .field("session_id", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

impl Frame {
    pub fn new(session_id: SessionId, nonce: Nonce, payload: impl Into<Bytes>) -> Result<Self, ProtocolError> {
        let payload = payload.into();
        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::PayloadTooLarge { actual: payload.len(), max: MAX_PAYLOAD_SIZE });
        }
        Ok(Self { session_id, nonce, payload })
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, ProtocolError> {
        if slice.len() < FRAME_SIZE {
            return Err(ProtocolError::FrameTooShort { expected: FRAME_SIZE, actual: slice.len() });
        }
        let mut session_id = [0u8; SESSION_ID_SIZE];
        session_id.copy_from_slice(&slice[..SESSION_ID_SIZE]);
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&slice[SESSION_ID_SIZE..SESSION_ID_SIZE + NONCE_SIZE]);
        let payload_len = u16::from_be_bytes([slice[24], slice[25]]) as usize;
        if payload_len > MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::PayloadTooLarge { actual: payload_len, max: MAX_PAYLOAD_SIZE });
        }
        Ok(Self {
            session_id,
            nonce,
            payload: Bytes::copy_from_slice(&slice[HEADER_SIZE..HEADER_SIZE + payload_len]),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct FrameCodec;
impl FrameCodec { pub fn new() -> Self { Self } }

impl Encoder<Frame> for FrameCodec {
    type Error = ProtocolError;
    fn encode(&mut self, item: Frame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        if item.payload.len() > MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::PayloadTooLarge { actual: item.payload.len(), max: MAX_PAYLOAD_SIZE });
        }
        dst.reserve(FRAME_SIZE);
        dst.put_slice(&item.session_id);
        dst.put_slice(&item.nonce);
        dst.put_u16(item.payload.len() as u16);
        dst.put_slice(&item.payload);
        dst.put_bytes(0, FRAME_SIZE - HEADER_SIZE - item.payload.len());
        Ok(())
    }
}

impl Decoder for FrameCodec {
    type Item = Frame;
    type Error = ProtocolError;
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < FRAME_SIZE { return Ok(None); }
        let bytes = src.split_to(FRAME_SIZE);
        Ok(Some(Frame::from_slice(&bytes)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_size_round_trip() {
        let frame = Frame::new([1u8; 16], [2u8; 8], Bytes::from_static(b"hello")).unwrap();
        let mut codec = FrameCodec::new();
        let mut wire = BytesMut::new();
        codec.encode(frame.clone(), &mut wire).unwrap();
        assert_eq!(wire.len(), FRAME_SIZE);
        assert_eq!(codec.decode(&mut wire).unwrap(), Some(frame));
    }

    #[test]
    fn debug_never_contains_payload_or_route() {
        let frame = Frame::new([0xAB; 16], [0xCD; 8], Bytes::from_static(b"top-secret-message")).unwrap();
        let rendered = format!("{frame:?}");
        assert!(!rendered.contains("top-secret-message"));
        assert!(!rendered.contains("171"));
        assert!(rendered.contains("[REDACTED]"));
    }
}
