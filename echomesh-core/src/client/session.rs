use std::sync::RwLock;

use crate::EchoMeshError;
pub use crate::protocol::{ECHO_PEER_ID, ECHO_SERVICE_PEER_ID};

#[derive(Debug, Clone)]
pub struct OutboundPacket {
    pub recipient: Vec<u8>,
    pub data: Vec<u8>,
}

pub enum SessionState {
    Disconnected,
    Handshake,
    Transport {
        outbound_tx: tokio::sync::mpsc::Sender<OutboundPacket>,
    },
}

pub struct ClientSessionManager {
    state: RwLock<SessionState>,
}

impl ClientSessionManager {
    pub fn new() -> Self {
        Self {
            state: RwLock::new(SessionState::Disconnected),
        }
    }

    pub fn set_handshake(&self) {
        *self.state.write().unwrap() = SessionState::Handshake;
    }

    pub fn set_transport(&self, outbound_tx: tokio::sync::mpsc::Sender<OutboundPacket>) {
        *self.state.write().unwrap() = SessionState::Transport { outbound_tx };
    }

    pub fn disconnect(&self) {
        *self.state.write().unwrap() = SessionState::Disconnected;
    }

    pub fn is_transport(&self) -> bool {
        matches!(*self.state.read().unwrap(), SessionState::Transport { .. })
    }

    pub fn get_outbound_tx(&self) -> Option<tokio::sync::mpsc::Sender<OutboundPacket>> {
        match &*self.state.read().unwrap() {
            SessionState::Transport { outbound_tx } => Some(outbound_tx.clone()),
            _ => None,
        }
    }

    pub fn send_packet(&self, recipient: Vec<u8>, data: Vec<u8>) -> Result<(), EchoMeshError> {
        match &*self.state.read().unwrap() {
            SessionState::Transport { outbound_tx } => outbound_tx
                .try_send(OutboundPacket { recipient, data })
                .map_err(|e| EchoMeshError::ConnectionError(format!("outbound queue unavailable: {e}"))),
            SessionState::Handshake | SessionState::Disconnected => Err(EchoMeshError::NotReady),
        }
    }
}

impl Default for ClientSessionManager {
    fn default() -> Self {
        Self::new()
    }
}
