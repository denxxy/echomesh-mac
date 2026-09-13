use async_trait::async_trait;
use tokio::sync::mpsc;

use super::core::{AsyncTransport, TransportKind};
use crate::EchoMeshError;

const HEADER: usize = 6;
const MAX_PACKET: usize = 64 * 1024;

pub struct BleTransport {
    mtu: usize,
    outgoing_chunks: mpsc::Sender<Vec<u8>>,
    incoming_chunks: mpsc::Receiver<Vec<u8>>,
    next_id: u16,
    assembly: Option<Assembly>,
}
struct Assembly { id: u16, total: u16, chunks: Vec<Option<Vec<u8>>> }

impl BleTransport {
    pub fn new(mtu: usize, outgoing_chunks: mpsc::Sender<Vec<u8>>, incoming_chunks: mpsc::Receiver<Vec<u8>>) -> Result<Self, EchoMeshError> {
        if mtu <= HEADER { return Err(EchoMeshError::ConnectionError("BLE MTU too small".into())); }
        Ok(Self { mtu, outgoing_chunks, incoming_chunks, next_id: 1, assembly: None })
    }
    fn encode_chunks(&mut self, packet: &[u8]) -> Result<Vec<Vec<u8>>, EchoMeshError> {
        if packet.len() > MAX_PACKET { return Err(EchoMeshError::ConnectionError("BLE packet exceeds 64 KiB".into())); }
        let per = self.mtu - HEADER; let total = packet.len().div_ceil(per).max(1);
        if total > u16::MAX as usize { return Err(EchoMeshError::ConnectionError("too many BLE fragments".into())); }
        let id=self.next_id; self.next_id=self.next_id.wrapping_add(1).max(1);
        Ok(packet.chunks(per).enumerate().map(|(i,p)| { let mut c=Vec::with_capacity(HEADER+p.len()); c.extend_from_slice(&id.to_be_bytes()); c.extend_from_slice(&(i as u16).to_be_bytes()); c.extend_from_slice(&(total as u16).to_be_bytes()); c.extend_from_slice(p); c }).collect())
    }
    fn accept_chunk(&mut self, chunk: &[u8]) -> Result<Option<Vec<u8>>, EchoMeshError> {
        if chunk.len()<HEADER { return Err(EchoMeshError::ConnectionError("truncated BLE fragment".into())); }
        let id=u16::from_be_bytes([chunk[0],chunk[1]]); let index=u16::from_be_bytes([chunk[2],chunk[3]]); let total=u16::from_be_bytes([chunk[4],chunk[5]]);
        if total==0 || index>=total { return Err(EchoMeshError::ConnectionError("invalid BLE fragment index".into())); }
        if self.assembly.as_ref().map(|a|a.id)!=Some(id) { self.assembly=Some(Assembly{id,total,chunks:vec![None;total as usize]}); }
        let a=self.assembly.as_mut().unwrap(); if a.total!=total { return Err(EchoMeshError::ConnectionError("BLE fragment total changed".into())); }
        a.chunks[index as usize]=Some(chunk[HEADER..].to_vec());
        if a.chunks.iter().all(Option::is_some) { let mut packet=Vec::new(); for p in &mut a.chunks { packet.extend_from_slice(p.take().unwrap().as_slice()); } self.assembly=None; if packet.len()>MAX_PACKET{return Err(EchoMeshError::ConnectionError("BLE reassembly exceeds limit".into()));} return Ok(Some(packet)); }
        Ok(None)
    }
}

#[async_trait]
impl AsyncTransport for BleTransport {
    fn kind(&self) -> TransportKind { TransportKind::Ble }
    async fn send(&mut self, packet: &[u8]) -> Result<(), EchoMeshError> { for c in self.encode_chunks(packet)? { self.outgoing_chunks.send(c).await.map_err(|_| EchoMeshError::ConnectionError("BLE output closed".into()))?; } Ok(()) }
    async fn recv(&mut self) -> Result<Option<Vec<u8>>, EchoMeshError> { while let Some(c)=self.incoming_chunks.recv().await { if let Some(p)=self.accept_chunk(&c)? { return Ok(Some(p)); } } Ok(None) }
}

#[cfg(test)] mod tests { use super::*; #[tokio::test] async fn fragments_and_reassembles() { let(a_tx,mut a_rx)=mpsc::channel(64);let(b_tx,b_rx)=mpsc::channel(64);let mut t=BleTransport::new(20,a_tx,b_rx).unwrap();let data=vec![7u8;137];t.send(&data).await.unwrap();let expected=data.len().div_ceil(14);for _ in 0..expected{let c=a_rx.recv().await.unwrap();b_tx.send(c).await.unwrap();}assert_eq!(t.recv().await.unwrap().unwrap(),data); }
    #[tokio::test]
    async fn out_of_order_fragments() {
        let (a_tx, mut a_rx) = mpsc::channel(64);
        let (b_tx, b_rx) = mpsc::channel(64);
        let mut t = BleTransport::new(20, a_tx, b_rx).unwrap();
        let data = vec![7u8; 40];
        t.send(&data).await.unwrap();
        let mut chunks = Vec::new();
        for _ in 0..data.len().div_ceil(14) { chunks.push(a_rx.recv().await.unwrap()); }
        // Send in reverse order
        for c in chunks.iter().rev() { b_tx.send(c.clone()).await.unwrap(); }
        assert_eq!(t.recv().await.unwrap().unwrap(), data);
    }
}
