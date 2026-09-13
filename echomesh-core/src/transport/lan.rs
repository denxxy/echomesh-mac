use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::core::{AsyncTransport, TransportKind};
use crate::EchoMeshError;

/// Length-prefixed direct LAN transport. E2EE is applied above this layer.
pub struct LanTransport { stream: TcpStream }
impl LanTransport {
    pub async fn connect(address: &str) -> Result<Self, EchoMeshError> {
        let stream = TcpStream::connect(address).await.map_err(|e| EchoMeshError::ConnectionError(format!("LAN connect failed: {}", e)))?;
        Ok(Self { stream })
    }
    pub fn from_stream(stream: TcpStream) -> Self { Self { stream } }
}

#[async_trait]
impl AsyncTransport for LanTransport {
    fn kind(&self) -> TransportKind { TransportKind::Lan }
    async fn send(&mut self, packet: &[u8]) -> Result<(), EchoMeshError> {
        if packet.len() > u32::MAX as usize { return Err(EchoMeshError::ConnectionError("LAN packet too large".into())); }
        self.stream.write_u32(packet.len() as u32).await.map_err(|e| EchoMeshError::ConnectionError(e.to_string()))?;
        self.stream.write_all(packet).await.map_err(|e| EchoMeshError::ConnectionError(e.to_string()))?;
        self.stream.flush().await.map_err(|e| EchoMeshError::ConnectionError(e.to_string()))
    }
    async fn recv(&mut self) -> Result<Option<Vec<u8>>, EchoMeshError> {
        let len = match self.stream.read_u32().await { Ok(v)=>v as usize, Err(e) if e.kind()==std::io::ErrorKind::UnexpectedEof=>return Ok(None), Err(e)=>return Err(EchoMeshError::ConnectionError(e.to_string())) };
        if len > 1024 * 1024 { return Err(EchoMeshError::ConnectionError("LAN packet exceeds 1 MiB".into())); }
        let mut packet=vec![0u8;len]; self.stream.read_exact(&mut packet).await.map_err(|e| EchoMeshError::ConnectionError(e.to_string()))?; Ok(Some(packet))
    }
    async fn close(&mut self) -> Result<(), EchoMeshError> { self.stream.shutdown().await.map_err(|e| EchoMeshError::ConnectionError(e.to_string())) }
}

#[cfg(test)]
mod tests {
    use super::*; use tokio::net::TcpListener;
    #[tokio::test]
    async fn lan_round_trip() {
        let l=TcpListener::bind("127.0.0.1:0").await.unwrap(); let addr=l.local_addr().unwrap();
        let server=tokio::spawn(async move { let (s,_)=l.accept().await.unwrap(); let mut t=LanTransport::from_stream(s); let p=t.recv().await.unwrap().unwrap(); t.send(&p).await.unwrap(); });
        let mut client=LanTransport::connect(&addr.to_string()).await.unwrap(); client.send(b"interoperable").await.unwrap(); assert_eq!(client.recv().await.unwrap().unwrap(),b"interoperable"); server.await.unwrap();
    }
}
