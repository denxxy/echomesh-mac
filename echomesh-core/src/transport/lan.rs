use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::transport::direct::{decode_direct_packet, encode_direct_packet, DIRECT_HEADER_LEN, DIRECT_MAX_PACKET, DIRECT_MAX_PAYLOAD};
use crate::EchoMeshError;

pub const LAN_DISCOVERY_MAGIC: &[u8; 4] = b"EML1";
pub const LAN_DISCOVERY_PORT: u16 = 47_777;
pub const LAN_MULTICAST_V4: Ipv4Addr = Ipv4Addr::new(239, 255, 77, 77);
pub const LAN_ANNOUNCEMENT_LEN: usize = 4 + 32 + 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LanAnnouncement {
    pub peer_id: [u8; 32],
    pub tcp_port: u16,
}

impl LanAnnouncement {
    pub fn encode(self) -> [u8; LAN_ANNOUNCEMENT_LEN] {
        let mut out = [0u8; LAN_ANNOUNCEMENT_LEN];
        out[..4].copy_from_slice(LAN_DISCOVERY_MAGIC);
        out[4..36].copy_from_slice(&self.peer_id);
        out[36..38].copy_from_slice(&self.tcp_port.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, EchoMeshError> {
        if bytes.len() != LAN_ANNOUNCEMENT_LEN || &bytes[..4] != LAN_DISCOVERY_MAGIC {
            return Err(EchoMeshError::ConnectionError("invalid LAN discovery announcement".to_string()));
        }
        let mut peer_id = [0u8; 32];
        peer_id.copy_from_slice(&bytes[4..36]);
        Ok(Self {
            peer_id,
            tcp_port: u16::from_be_bytes([bytes[36], bytes[37]]),
        })
    }
}

pub struct LanPeerStream {
    stream: TcpStream,
}

impl LanPeerStream {
    pub async fn connect(address: SocketAddr) -> Result<Self, EchoMeshError> {
        let stream = TcpStream::connect(address)
            .await
            .map_err(|e| EchoMeshError::ConnectionError(format!("LAN connect failed: {e}")))?;
        stream
            .set_nodelay(true)
            .map_err(|e| EchoMeshError::ConnectionError(format!("LAN TCP setup failed: {e}")))?;
        Ok(Self { stream })
    }

    pub fn from_stream(stream: TcpStream) -> Self {
        Self { stream }
    }

    pub async fn send_envelope(&mut self, envelope: &[u8]) -> Result<(), EchoMeshError> {
        let packet = encode_direct_packet(envelope)?;
        self.stream
            .write_all(&packet)
            .await
            .map_err(|e| EchoMeshError::ConnectionError(format!("LAN write failed: {e}")))?;
        self.stream
            .flush()
            .await
            .map_err(|e| EchoMeshError::ConnectionError(format!("LAN flush failed: {e}")))?;
        Ok(())
    }

    pub async fn recv_envelope(&mut self) -> Result<Option<Vec<u8>>, EchoMeshError> {
        let mut header = [0u8; DIRECT_HEADER_LEN];
        match self.stream.read_exact(&mut header).await {
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(err) => return Err(EchoMeshError::ConnectionError(format!("LAN read failed: {err}"))),
        }
        let len = u16::from_be_bytes([header[4], header[5]]) as usize;
        if &header[..4] != crate::transport::direct::DIRECT_MAGIC || len > DIRECT_MAX_PAYLOAD {
            return Err(EchoMeshError::ConnectionError("invalid LAN packet header".to_string()));
        }
        let mut wire = Vec::with_capacity(DIRECT_HEADER_LEN + len);
        wire.extend_from_slice(&header);
        wire.resize(DIRECT_HEADER_LEN + len, 0);
        self.stream
            .read_exact(&mut wire[DIRECT_HEADER_LEN..])
            .await
            .map_err(|e| EchoMeshError::ConnectionError(format!("LAN payload read failed: {e}")))?;
        Ok(Some(decode_direct_packet(&wire)?.to_vec()))
    }
}

pub struct LanListener {
    listener: TcpListener,
}

impl LanListener {
    pub async fn bind(address: SocketAddr) -> Result<Self, EchoMeshError> {
        let listener = TcpListener::bind(address)
            .await
            .map_err(|e| EchoMeshError::ConnectionError(format!("LAN bind failed: {e}")))?;
        Ok(Self { listener })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, EchoMeshError> {
        self.listener
            .local_addr()
            .map_err(|e| EchoMeshError::ConnectionError(format!("LAN local address failed: {e}")))
    }

    pub async fn accept(&self) -> Result<(LanPeerStream, SocketAddr), EchoMeshError> {
        let (stream, address) = self
            .listener
            .accept()
            .await
            .map_err(|e| EchoMeshError::ConnectionError(format!("LAN accept failed: {e}")))?;
        let _ = stream.set_nodelay(true);
        Ok((LanPeerStream::from_stream(stream), address))
    }
}

pub async fn discovery_socket() -> Result<UdpSocket, EchoMeshError> {
    let std_socket = std::net::UdpSocket::bind(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        LAN_DISCOVERY_PORT,
    ))
    .map_err(|e| EchoMeshError::ConnectionError(format!("LAN discovery bind failed: {e}")))?;
    std_socket
        .set_nonblocking(true)
        .map_err(|e| EchoMeshError::ConnectionError(format!("LAN discovery nonblocking failed: {e}")))?;
    std_socket
        .join_multicast_v4(&LAN_MULTICAST_V4, &Ipv4Addr::UNSPECIFIED)
        .map_err(|e| EchoMeshError::ConnectionError(format!("LAN multicast join failed: {e}")))?;
    UdpSocket::from_std(std_socket)
        .map_err(|e| EchoMeshError::ConnectionError(format!("LAN discovery socket failed: {e}")))
}

pub async fn announce(socket: &UdpSocket, announcement: LanAnnouncement) -> Result<(), EchoMeshError> {
    let destination = SocketAddr::new(IpAddr::V4(LAN_MULTICAST_V4), LAN_DISCOVERY_PORT);
    socket
        .send_to(&announcement.encode(), destination)
        .await
        .map_err(|e| EchoMeshError::ConnectionError(format!("LAN discovery send failed: {e}")))?;
    Ok(())
}

pub async fn receive_announcement(socket: &UdpSocket) -> Result<(LanAnnouncement, SocketAddr), EchoMeshError> {
    let mut buf = [0u8; LAN_ANNOUNCEMENT_LEN];
    let (len, source) = socket
        .recv_from(&mut buf)
        .await
        .map_err(|e| EchoMeshError::ConnectionError(format!("LAN discovery receive failed: {e}")))?;
    if len != LAN_ANNOUNCEMENT_LEN {
        return Err(EchoMeshError::ConnectionError("truncated LAN discovery frame".to_string()));
    }
    Ok((LanAnnouncement::decode(&buf)?, source))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn announcement_round_trip() {
        let original = LanAnnouncement { peer_id: [7u8; 32], tcp_port: 4242 };
        assert_eq!(LanAnnouncement::decode(&original.encode()).unwrap(), original);
    }

    #[tokio::test]
    async fn tcp_envelope_round_trip() {
        let listener = LanListener::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut peer, _) = listener.accept().await.unwrap();
            let data = peer.recv_envelope().await.unwrap().unwrap();
            peer.send_envelope(&data).await.unwrap();
        });
        let mut client = LanPeerStream::connect(addr).await.unwrap();
        client.send_envelope(b"opaque-e2ee").await.unwrap();
        assert_eq!(client.recv_envelope().await.unwrap().unwrap(), b"opaque-e2ee");
        server.await.unwrap();
    }

    #[test]
    fn direct_packet_bound_matches_transport_limit() {
        assert_eq!(DIRECT_MAX_PACKET, DIRECT_HEADER_LEN + DIRECT_MAX_PAYLOAD);
    }
}
