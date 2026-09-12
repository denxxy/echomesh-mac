use bytes::Bytes;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use echomesh_core::noise::{client_noise_handshake, NoiseFramedStream, NOISE_PATTERN, NOISE_TAG_LEN};
use echomesh_core::protocol::{Frame, FrameCodec, FRAME_SIZE};

#[tokio::test]
async fn test_end_to_end_noise_nk_handshake_and_frame_exchange() {
    // 1. Generate static keypair for server (Noise NK responder)
    let builder = snow::Builder::new(NOISE_PATTERN.parse().unwrap());
    let server_keypair = builder.generate_keypair().unwrap();
    let server_pub = server_keypair.public.clone();
    let server_priv = server_keypair.private.clone();

    // 2. Bind local TCP listener
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    // 3. Spawn server task
    let server_task = tokio::spawn(async move {
        let (mut stream, _peer_addr) = listener.accept().await.unwrap();

        // Server Noise NK handshake
        let builder = snow::Builder::new(NOISE_PATTERN.parse().unwrap());
        let mut responder = builder
            .local_private_key(&server_priv)
            .unwrap()
            .build_responder()
            .unwrap();

        // Read message 1 (-> e, es)
        let msg1_len = stream.read_u16().await.unwrap() as usize;
        let mut msg1 = vec![0u8; msg1_len];
        stream.read_exact(&mut msg1).await.unwrap();
        let mut dummy = [0u8; 128];
        responder.read_message(&msg1, &mut dummy).unwrap();

        // Write message 2 (<- e, ee)
        let mut msg2 = vec![0u8; 128];
        let n2 = responder.write_message(&[], &mut msg2).unwrap();
        msg2.truncate(n2);
        stream.write_u16(n2 as u16).await.unwrap();
        stream.write_all(&msg2).await.unwrap();
        stream.flush().await.unwrap();

        let mut transport = responder.into_transport_mode().unwrap();

        // Receive encrypted frame
        let frame_len = stream.read_u16().await.unwrap() as usize;
        let mut cipher_frame = vec![0u8; frame_len];
        stream.read_exact(&mut cipher_frame).await.unwrap();

        let mut plain_frame = vec![0u8; cipher_frame.len()];
        let n = transport.read_message(&cipher_frame, &mut plain_frame).unwrap();
        plain_frame.truncate(n);

        let received_frame = Frame::from_slice(&plain_frame).unwrap();
        assert_eq!(received_frame.payload, Bytes::from_static(b"Hello from echomesh-core client!"));

        // Echo frame back
        let reply_frame = Frame::new(
            received_frame.session_id,
            received_frame.nonce,
            Bytes::from_static(b"Hello from echomesh-relay server!"),
        )
        .unwrap();

        let mut raw_reply = bytes::BytesMut::with_capacity(FRAME_SIZE);
        let mut codec = FrameCodec::new();
        tokio_util::codec::Encoder::encode(&mut codec, reply_frame, &mut raw_reply).unwrap();

        let mut cipher_reply = vec![0u8; raw_reply.len() + NOISE_TAG_LEN];
        let n = transport.write_message(&raw_reply, &mut cipher_reply).unwrap();
        cipher_reply.truncate(n);

        stream.write_u16(n as u16).await.unwrap();
        stream.write_all(&cipher_reply).await.unwrap();
        stream.flush().await.unwrap();
    });

    // 4. Client task
    let mut client_stream = TcpStream::connect(server_addr).await.unwrap();
    let session = client_noise_handshake(&mut client_stream, &server_pub, Duration::from_secs(5))
        .await
        .unwrap();
    let mut framed = NoiseFramedStream::new(client_stream, session);

    let test_frame = Frame::new(
        [0x55; 16],
        [1, 2, 3, 4, 5, 6, 7, 8],
        Bytes::from_static(b"Hello from echomesh-core client!"),
    )
    .unwrap();

    framed.send_frame(&test_frame).await.unwrap();

    let reply = framed.recv_frame().await.unwrap().unwrap();
    assert_eq!(reply.payload, Bytes::from_static(b"Hello from echomesh-relay server!"));

    server_task.await.unwrap();
}

#[tokio::test]
async fn test_handshake_timeout_when_relay_does_not_respond() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let _server_task = tokio::spawn(async move {
        let (_stream, _peer_addr) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(10)).await;
    });

    let mut client_stream = TcpStream::connect(server_addr).await.unwrap();
    let dummy_key = [0x42u8; 32];
    let res = client_noise_handshake(&mut client_stream, &dummy_key, Duration::from_millis(200)).await;
    match res {
        Err(echomesh_core::EchoMeshError::HandshakeTimeout(msg)) => {
            assert_eq!(msg, "Handshake timed out waiting for relay response");
        }
        Err(other) => panic!("Expected HandshakeTimeout, got {:?}", other),
        Ok(_) => panic!("Expected HandshakeTimeout, got Ok"),
    }
}

