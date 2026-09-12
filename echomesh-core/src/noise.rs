use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, error};

use crate::protocol::{Frame, FrameCodec, FRAME_SIZE};
use crate::EchoMeshError;

pub const NOISE_PATTERN: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2s";
pub const NOISE_TAG_LEN: usize = 16;
pub const ENCRYPTED_FRAME_SIZE: usize = FRAME_SIZE + NOISE_TAG_LEN;

pub struct NoiseSession {
    transport: snow::TransportState,
}

impl std::fmt::Debug for NoiseSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoiseSession")
            .field("pattern", &NOISE_PATTERN)
            .field("state", &"[ENCRYPTED]")
            .finish()
    }
}

impl NoiseSession {
    pub fn new(transport: snow::TransportState) -> Self {
        Self { transport }
    }

    pub fn encrypt_frame(&mut self, frame: &Frame) -> Result<Vec<u8>, EchoMeshError> {
        let mut raw_frame = bytes::BytesMut::with_capacity(FRAME_SIZE);
        let mut codec = FrameCodec::new();
        tokio_util::codec::Encoder::encode(&mut codec, frame.clone(), &mut raw_frame)
            .map_err(|e| EchoMeshError::ConnectionError(format!("Frame encoding error: {:?}", e)))?;

        let mut cipher_text = vec![0u8; raw_frame.len() + NOISE_TAG_LEN];
        let n = self
            .transport
            .write_message(&raw_frame, &mut cipher_text)
            .map_err(|e| EchoMeshError::NoiseError(e.to_string()))?;
        cipher_text.truncate(n);

        let mut packet = Vec::with_capacity(2 + cipher_text.len());
        packet.extend_from_slice(&(cipher_text.len() as u16).to_be_bytes());
        packet.extend_from_slice(&cipher_text);

        Ok(packet)
    }

    pub fn decrypt_frame(&mut self, cipher_text: &[u8]) -> Result<Frame, EchoMeshError> {
        let mut plain_buf = vec![0u8; cipher_text.len()];
        let n = self
            .transport
            .read_message(cipher_text, &mut plain_buf)
            .map_err(|e| EchoMeshError::NoiseError(e.to_string()))?;
        plain_buf.truncate(n);

        let frame = Frame::from_slice(&plain_buf)
            .map_err(|e| EchoMeshError::ConnectionError(format!("Frame decoding error: {:?}", e)))?;
        Ok(frame)
    }
}

pub const NOISE_PROLOGUE: &[u8] = b"";

pub async fn client_noise_handshake<S>(
    stream: &mut S,
    server_public_key: &[u8],
    timeout_duration: Duration,
) -> Result<NoiseSession, EchoMeshError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if server_public_key.len() != 32 {
        return Err(EchoMeshError::InvalidKeyLength {
            expected: 32,
            actual: server_public_key.len() as u32,
        });
    }

    let mut builder = snow::Builder::new(
        NOISE_PATTERN
            .parse()
            .map_err(|e: snow::Error| EchoMeshError::NoiseError(e.to_string()))?,
    );
    if !NOISE_PROLOGUE.is_empty() {
        builder = builder
            .prologue(NOISE_PROLOGUE)
            .map_err(|e| EchoMeshError::NoiseError(e.to_string()))?;
    }

    let mut initiator = builder
        .remote_public_key(server_public_key)
        .map_err(|e| EchoMeshError::NoiseError(e.to_string()))?
        .build_initiator()
        .map_err(|e| EchoMeshError::NoiseError(e.to_string()))?;

    // 1. Generate and send message 1 (-> e, es)
    let mut msg1 = vec![0u8; 128];
    let n1 = initiator
        .write_message(&[], &mut msg1)
        .map_err(|e| EchoMeshError::NoiseError(format!("initiator.write_message error: {}", e)))?;
    msg1.truncate(n1);

    debug!(msg1_len = n1, "generated first Noise handshake message (initiator.write_message)");

    let write_res = tokio::time::timeout(timeout_duration, async {
        stream.write_u16(n1 as u16).await?;
        stream.write_all(&msg1).await?;
        stream.flush().await?;
        Ok::<(), std::io::Error>(())
    })
    .await;

    match write_res {
        Ok(Ok(())) => debug!("sent Noise handshake message 1 to relay"),
        Ok(Err(e)) => return Err(EchoMeshError::ConnectionError(e.to_string())),
        Err(_) => {
            error!("Handshake timed out waiting for relay response");
            return Err(EchoMeshError::HandshakeTimeout(
                "Handshake timed out waiting for relay response".to_string(),
            ));
        }
    }

    // 2. Read message 2 from server (<- e, ee)
    let read_res = tokio::time::timeout(timeout_duration, async {
        let msg2_len = match stream.read_u16().await {
            Ok(l) => l as usize,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(EchoMeshError::HandshakeUnexpectedEof(
                    "Server closed connection during handshake (msg2 length)".to_string(),
                ));
            }
            Err(e) => return Err(EchoMeshError::ConnectionError(e.to_string())),
        };

        let mut msg2 = vec![0u8; msg2_len];
        if let Err(e) = stream.read_exact(&mut msg2).await {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                return Err(EchoMeshError::HandshakeUnexpectedEof(
                    "Server closed connection while reading message 2 payload".to_string(),
                ));
            }
            return Err(EchoMeshError::ConnectionError(e.to_string()));
        }
        Ok(msg2)
    })
    .await;

    let msg2 = match read_res {
        Ok(Ok(m)) => m,
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            error!("Handshake timed out waiting for relay response");
            return Err(EchoMeshError::HandshakeTimeout(
                "Handshake timed out waiting for relay response".to_string(),
            ));
        }
    };

    let mut dummy_payload = [0u8; 128];
    initiator
        .read_message(&msg2, &mut dummy_payload)
        .map_err(|e| {
            error!(error = ?e, "initiator.read_message failed on message 2");
            EchoMeshError::NoiseError(format!("Handshake verification failed: {}", e))
        })?;

    debug!("Noise handshake completed, transitioning to transport mode");
    let transport = initiator
        .into_transport_mode()
        .map_err(|e| EchoMeshError::NoiseError(e.to_string()))?;

    Ok(NoiseSession::new(transport))
}

pub struct NoiseFramedStream<S> {
    stream: S,
    session: NoiseSession,
}

impl<S> NoiseFramedStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(stream: S, session: NoiseSession) -> Self {
        Self { stream, session }
    }

    pub async fn send_frame(&mut self, frame: &Frame) -> Result<(), EchoMeshError> {
        let packet = self.session.encrypt_frame(frame)?;
        self.stream
            .write_all(&packet)
            .await
            .map_err(|e| EchoMeshError::ConnectionError(e.to_string()))?;
        self.stream
            .flush()
            .await
            .map_err(|e| EchoMeshError::ConnectionError(e.to_string()))?;
        Ok(())
    }

    pub async fn recv_frame(&mut self) -> Result<Option<Frame>, EchoMeshError> {
        let len = match self.stream.read_u16().await {
            Ok(len) => len as usize,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(EchoMeshError::ConnectionError(e.to_string())),
        };

        if len > ENCRYPTED_FRAME_SIZE {
            return Err(EchoMeshError::ConnectionError(format!(
                "Received frame size {} exceeds maximum allowed {}",
                len, ENCRYPTED_FRAME_SIZE
            )));
        }

        let mut buf = vec![0u8; len];
        self.stream
            .read_exact(&mut buf)
            .await
            .map_err(|e| EchoMeshError::ConnectionError(e.to_string()))?;
        let frame = self.session.decrypt_frame(&buf)?;
        Ok(Some(frame))
    }
}
