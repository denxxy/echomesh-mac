pub mod api;
pub mod client;
pub mod crypto;
pub mod noise;
pub mod protocol;
pub mod transport;

pub use api::EchoMeshClient;
pub use crypto::IdentityKeyPair;
pub use noise::{client_noise_handshake, NoiseFramedStream, NoiseSession};
pub use protocol::{Frame, FrameCodec, FRAME_SIZE, MAX_PAYLOAD_SIZE};
pub use transport::obfuscation::PseudoTlsBuilder;

uniffi::setup_scaffolding!();

#[derive(uniffi::Error, thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum EchoMeshError {
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: u32, actual: u32 },

    #[error("Handshake timeout connecting to relay: {0}")]
    HandshakeTimeout(String),

    #[error("Unexpected EOF during handshake with relay: {0}")]
    HandshakeUnexpectedEof(String),

    #[error("Noise cryptographic error during handshake: {0}")]
    NoiseError(String),

    #[error("Relay connection error: {0}")]
    ConnectionError(String),

    #[error("Tokio runtime error: {0}")]
    RuntimeError(String),

    #[error("Storage error: {0}")]
    StorageError(String),
}

#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkState {
    Offline,
    Connecting,
    ConnectedRealityRelay,
    ConnectedBleMeshFallback,
}

#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryStatus {
    Sent,
    Relayed,
    Delivered,
    Failed,
}

#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct MessagePayload {
    pub id: String,
    pub sender: String,
    pub recipient: String,
    pub content: String,
    pub timestamp: u64,
    pub status: DeliveryStatus,
}

#[uniffi::export(callback_interface)]
pub trait CoreEventsListener: Send + Sync {
    fn on_state_changed(&self, state: NetworkState);
    fn on_message_received(&self, message: MessagePayload);
    fn on_message_status_updated(&self, message_id: String, status: DeliveryStatus);
}

#[uniffi::export]
pub fn generate_identity_keypair() -> Result<IdentityKeyPair, EchoMeshError> {
    crypto::generate_identity_keypair_impl()
}

#[uniffi::export]
pub fn derive_public_key(private_key: Vec<u8>) -> Result<IdentityKeyPair, EchoMeshError> {
    crypto::derive_public_key_impl(private_key)
}
