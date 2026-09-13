use std::env;
use std::process::exit;
use std::time::Duration;
use bytes::Bytes;
use tokio::net::TcpStream;
use base64::Engine;

use echomesh_core::noise::{client_noise_handshake, NoiseFramedStream};
use echomesh_core::protocol::{Frame, SessionId, Nonce};

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let mut relay_addr: Option<String> = None;
    let mut key_base64: Option<String> = None;
    let mut token_hex: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--relay" if i + 1 < args.len() => { relay_addr = Some(args[i + 1].clone()); i += 1; }
            "--key" if i + 1 < args.len() => { key_base64 = Some(args[i + 1].clone()); i += 1; }
            "--token" if i + 1 < args.len() => { token_hex = Some(args[i + 1].clone()); i += 1; }
            "-h" | "--help" => { print_usage(&args[0]); exit(0); }
            other if other.starts_with("--relay=") => relay_addr = Some(other.trim_start_matches("--relay=").to_string()),
            other if other.starts_with("--key=") => key_base64 = Some(other.trim_start_matches("--key=").to_string()),
            other if other.starts_with("--token=") => token_hex = Some(other.trim_start_matches("--token=").to_string()),
            _ => {}
        }
        i += 1;
    }

    let relay_addr = relay_addr.unwrap_or_else(|| { eprintln!("[ERROR] Missing required argument: --relay <IP:PORT>"); print_usage(&args[0]); exit(1); });
    let key_base64 = key_base64.unwrap_or_else(|| { eprintln!("[ERROR] Missing required argument: --key <BASE64_PUBLIC_KEY>"); print_usage(&args[0]); exit(1); });
    let token_text = token_hex.as_deref().map(str::trim).filter(|v| !v.is_empty()).unwrap_or_else(|| {
        eprintln!("[ERROR] Missing required argument: --token <HEX_OR_TEXT_SECRET_TOKEN>");
        print_usage(&args[0]);
        exit(1);
    });
    let secret_bytes = hex::decode(token_text).unwrap_or_else(|_| token_text.as_bytes().to_vec());
    if secret_bytes.is_empty() { eprintln!("[ERROR] Relay credential must not be empty"); exit(1); }

    let clean_addr = relay_addr.trim_start_matches("https://").trim_start_matches("http://").trim_start_matches("mesh://").to_string();
    let key_bytes = base64::engine::general_purpose::STANDARD.decode(key_base64.trim())
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(key_base64.trim()))
        .unwrap_or_else(|e| { eprintln!("[ERROR] Failed to decode Base64 public key: {}", e); exit(1); });
    if key_bytes.len() != 32 { eprintln!("[ERROR] Invalid public key length: expected 32 bytes, got {}", key_bytes.len()); exit(1); }

    println!("Attempting connection to relay: {}", clean_addr);
    let timeout_dur = Duration::from_secs(5);
    let mut tcp_stream = match tokio::time::timeout(timeout_dur, TcpStream::connect(&clean_addr)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => { eprintln!("[FAIL] TCP Connection failed: {}", e); exit(1); }
        Err(_) => { eprintln!("[FAIL] TCP Connection timed out after 5s"); exit(1); }
    };

    use tokio::io::AsyncWriteExt;
    let client_hello = echomesh_core::transport::PseudoTlsBuilder::new(secret_bytes, "cloudflare.com").build();
    tcp_stream.write_all(&client_hello).await.unwrap_or_else(|e| { eprintln!("[FAIL] Failed sending ClientHello: {}", e); exit(1); });
    tcp_stream.flush().await.unwrap_or_else(|e| { eprintln!("[FAIL] Failed flushing ClientHello: {}", e); exit(1); });

    let session = client_noise_handshake(&mut tcp_stream, &key_bytes, timeout_dur).await.unwrap_or_else(|e| { eprintln!("[FAIL] Noise handshake failed: {:?}", e); exit(1); });
    let mut framed = NoiseFramedStream::new(tcp_stream, session);
    let session_id: SessionId = [0xEE; 16];
    let nonce: Nonce = [0, 0, 0, 0, 0, 0, 0, 1];
    let ping_payload = Bytes::from_static(b"PING");
    let ping_frame = Frame::new(session_id, nonce, ping_payload.clone()).unwrap();
    framed.send_frame(&ping_frame).await.unwrap_or_else(|e| { eprintln!("[FAIL] Failed sending ping: {:?}", e); exit(1); });

    match tokio::time::timeout(timeout_dur, framed.recv_frame()).await {
        Ok(Ok(Some(reply))) if reply.payload == ping_payload => println!("[OK] TCP -> authenticated pseudo-TLS -> Noise -> echo"),
        Ok(Ok(Some(reply))) => { eprintln!("[FAIL] Unexpected reply: {:?}", reply.payload); exit(1); }
        Ok(Ok(None)) => { eprintln!("[FAIL] Relay closed stream"); exit(1); }
        Ok(Err(e)) => { eprintln!("[FAIL] Receive error: {:?}", e); exit(1); }
        Err(_) => { eprintln!("[FAIL] Timed out waiting for echo"); exit(1); }
    }
}

fn print_usage(prog: &str) {
    eprintln!("Usage: {} --relay <IP:PORT> --key <BASE64_PUBLIC_KEY> --token <HEX_OR_TEXT_SECRET_TOKEN>", prog);
}
