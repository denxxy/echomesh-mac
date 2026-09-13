use async_trait::async_trait;
use crate::EchoMeshError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportKind { Relay, Lan, Ble }

#[async_trait]
pub trait AsyncTransport: Send {
    fn kind(&self) -> TransportKind;
    async fn send(&mut self, packet: &[u8]) -> Result<(), EchoMeshError>;
    async fn recv(&mut self) -> Result<Option<Vec<u8>>, EchoMeshError>;
    async fn close(&mut self) -> Result<(), EchoMeshError> { Ok(()) }
}

/// Single async owner for whichever physical transport is active.
pub struct TransportCore { active: Option<Box<dyn AsyncTransport>> }
impl TransportCore {
    pub fn new() -> Self { Self { active: None } }
    pub fn install<T: AsyncTransport + 'static>(&mut self, transport: T) { self.active = Some(Box::new(transport)); }
    pub fn kind(&self) -> Option<TransportKind> { self.active.as_ref().map(|t| t.kind()) }
    pub async fn send(&mut self, packet: &[u8]) -> Result<(), EchoMeshError> { self.active.as_mut().ok_or(EchoMeshError::NotReady)?.send(packet).await }
    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>, EchoMeshError> { self.active.as_mut().ok_or(EchoMeshError::NotReady)?.recv().await }
    pub async fn disconnect(&mut self) -> Result<(), EchoMeshError> { if let Some(mut t)=self.active.take(){t.close().await?;} Ok(()) }
}
impl Default for TransportCore { fn default() -> Self { Self::new() } }
