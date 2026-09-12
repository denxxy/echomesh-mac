use bytes::{BufMut, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

/// Fixed total size of a frame in bytes (MTU-friendly wire format).
pub const FRAME_SIZE: usize = 1420;

/// Size of the SessionId field in bytes.
pub const SESSION_ID_SIZE: usize = 16;

/// Size of the Nonce field in bytes.
pub const NONCE_SIZE: usize = 8;

/// Size of the PayloadLength field in bytes.
pub const PAYLOAD_LEN_SIZE: usize = 2;

/// Total size of the frame header in bytes (16 + 8 + 2 = 26).
pub const HEADER_SIZE: usize = SESSION_ID_SIZE + NONCE_SIZE + PAYLOAD_LEN_SIZE;

/// Maximum allowed payload size in bytes: 1420 - 16 - 8 - 2 = 1394.
pub const MAX_PAYLOAD_SIZE: usize = FRAME_SIZE - HEADER_SIZE;

pub type SessionId = [u8; SESSION_ID_SIZE];
pub type Nonce = [u8; NONCE_SIZE];

/// Static identifier of the internal echo loopback service (32 bytes of 0xEE).
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
    fn from(_: std::io::Error) -> Self {
        ProtocolError::Io
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Frame {
    pub session_id: SessionId,
    pub nonce: Nonce,
    pub payload: Bytes,
}

impl Frame {
    pub fn new(
        session_id: SessionId,
        nonce: Nonce,
        payload: impl Into<Bytes>,
    ) -> Result<Self, ProtocolError> {
        let payload = payload.into();
        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::PayloadTooLarge {
                actual: payload.len(),
                max: MAX_PAYLOAD_SIZE,
            });
        }
        Ok(Self {
            session_id,
            nonce,
            payload,
        })
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, ProtocolError> {
        if slice.len() < FRAME_SIZE {
            return Err(ProtocolError::FrameTooShort {
                expected: FRAME_SIZE,
                actual: slice.len(),
            });
        }

        let mut session_id = [0u8; SESSION_ID_SIZE];
        session_id.copy_from_slice(&slice[0..SESSION_ID_SIZE]);

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&slice[SESSION_ID_SIZE..SESSION_ID_SIZE + NONCE_SIZE]);

        let len_start = SESSION_ID_SIZE + NONCE_SIZE;
        let payload_len = u16::from_be_bytes([slice[len_start], slice[len_start + 1]]) as usize;

        if payload_len > MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::PayloadTooLarge {
                actual: payload_len,
                max: MAX_PAYLOAD_SIZE,
            });
        }

        let payload_end = HEADER_SIZE + payload_len;
        let payload = Bytes::copy_from_slice(&slice[HEADER_SIZE..payload_end]);

        Ok(Self {
            session_id,
            nonce,
            payload,
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct FrameCodec;

impl FrameCodec {
    pub fn new() -> Self {
        Self
    }
}

impl Encoder<Frame> for FrameCodec {
    type Error = ProtocolError;

    fn encode(&mut self, item: Frame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let payload_len = item.payload.len();
        if payload_len > MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::PayloadTooLarge {
                actual: payload_len,
                max: MAX_PAYLOAD_SIZE,
            });
        }

        dst.reserve(FRAME_SIZE);
        dst.put_slice(&item.session_id);
        dst.put_slice(&item.nonce);
        dst.put_u16(payload_len as u16);
        dst.put_slice(&item.payload);

        let padding_needed = FRAME_SIZE - (HEADER_SIZE + payload_len);
        dst.put_bytes(0, padding_needed);

        Ok(())
    }
}

impl Decoder for FrameCodec {
    type Item = Frame;
    type Error = ProtocolError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < FRAME_SIZE {
            return Ok(None);
        }

        let frame_bytes = src.split_to(FRAME_SIZE);
        let frame = Frame::from_slice(&frame_bytes)?;
        Ok(Some(frame))
    }
}
