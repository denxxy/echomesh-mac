use std::sync::{Arc, RwLock};
use crate::noise::NoiseSession;
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
        session: Arc<tokio::sync::Mutex<NoiseSession>>,
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
        let mut s = self.state.write().unwrap();
        *s = SessionState::Handshake;
    }

    pub fn set_transport(
        &self,
        session: Arc<tokio::sync::Mutex<NoiseSession>>,
        outbound_tx: tokio::sync::mpsc::Sender<OutboundPacket>,
    ) {
        let mut s = self.state.write().unwrap();
        *s = SessionState::Transport {
            session,
            outbound_tx,
        };
    }

    pub fn disconnect(&self) {
        let mut s = self.state.write().unwrap();
        *s = SessionState::Disconnected;
    }

    pub fn is_transport(&self) -> bool {
        matches!(*self.state.read().unwrap(), SessionState::Transport { .. })
    }

    pub fn get_outbound_tx(&self) -> Option<tokio::sync::mpsc::Sender<OutboundPacket>> {
        let state_guard = self.state.read().unwrap();
        match &*state_guard {
            SessionState::Transport { outbound_tx, .. } => Some(outbound_tx.clone()),
            _ => None,
        }
    }

    pub fn send_packet(&self, recipient: Vec<u8>, data: Vec<u8>) -> Result<(), EchoMeshError> {
        let state_guard = self.state.read().unwrap();
        match &*state_guard {
            SessionState::Transport { outbound_tx, .. } => {
                let packet = OutboundPacket { recipient, data };
                outbound_tx
                    .try_send(packet)
                    .map_err(|e| EchoMeshError::ConnectionError(format!("Outbound queue full or closed: {}", e)))?;
                Ok(())
            }
            SessionState::Handshake | SessionState::Disconnected => Err(EchoMeshError::NotReady),
        }
    }
}

impl Default for ClientSessionManager {
    fn default() -> Self {
        Self::new()
    }
}
