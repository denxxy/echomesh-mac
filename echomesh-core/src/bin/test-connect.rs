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
            "--relay" => {
                if i + 1 < args.len() {
                    relay_addr = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--key" => {
                if i + 1 < args.len() {
                    key_base64 = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--token" => {
                if i + 1 < args.len() {
                    token_hex = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-h" | "--help" => {
                print_usage(&args[0]);
                exit(0);
            }
            other if other.starts_with("--relay=") => {
                relay_addr = Some(other.trim_start_matches("--relay=").to_string());
            }
            other if other.starts_with("--key=") => {
                key_base64 = Some(other.trim_start_matches("--key=").to_string());
            }
            other if other.starts_with("--token=") => {
                token_hex = Some(other.trim_start_matches("--token=").to_string());
            }
            _ => {}
        }
        i += 1;
    }

    let relay_addr = match relay_addr {
        Some(a) => a,
        None => {
            eprintln!("\x1b[31m[ERROR]\x1b[0m Missing required argument: --relay <IP:PORT>");
            print_usage(&args[0]);
            exit(1);
        }
    };

    let key_base64 = match key_base64 {
        Some(k) => k,
        None => {
            eprintln!("\x1b[31m[ERROR]\x1b[0m Missing required argument: --key <BASE64_PUBLIC_KEY>");
            print_usage(&args[0]);
            exit(1);
        }
    };

    let clean_addr = relay_addr
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .to_string();

    // Decode public key
    let key_bytes = match base64::engine::general_purpose::STANDARD.decode(key_base64.trim()) {
        Ok(b) => b,
        Err(_) => match base64::engine::general_purpose::URL_SAFE.decode(key_base64.trim()) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("\x1b[31m[ERROR]\x1b[0m Failed to decode Base64 public key: {}", e);
                exit(1);
            }
        },
    };

    if key_bytes.len() != 32 {
        eprintln!(
            "\x1b[31m[ERROR]\x1b[0m Invalid public key length: expected 32 bytes, got {}",
            key_bytes.len()
        );
        exit(1);
    }

    println!("Attempting connection to relay: {}", clean_addr);

    // 1. TCP Connect
    let timeout_dur = Duration::from_secs(5);
    let mut tcp_stream = match tokio::time::timeout(timeout_dur, TcpStream::connect(&clean_addr)).await {
        Ok(Ok(stream)) => {
            println!("\x1b[32m[OK]\x1b[0m TCP Connected");
            stream
        }
        Ok(Err(e)) => {
            eprintln!("\x1b[31m[FAIL]\x1b[0m TCP Connection failed: {}", e);
            exit(1);
        }
        Err(_) => {
            eprintln!("\x1b[31m[FAIL]\x1b[0m TCP Connection timed out after 5s");
            exit(1);
        }
    };

    // 2. Send Pseudo-TLS ClientHello
    let secret_bytes = match token_hex.as_deref() {
        Some(s) if !s.trim().is_empty() => {
            hex::decode(s.trim()).unwrap_or_else(|_| s.trim().as_bytes().to_vec())
        }
        _ => vec![0u8; 32],
    };

    use tokio::io::AsyncWriteExt;
    let tls_builder = echomesh_core::transport::PseudoTlsBuilder::new(secret_bytes, "cloudflare.com");
    let client_hello = tls_builder.build();
    if let Err(e) = tcp_stream.write_all(&client_hello).await {
        eprintln!("\x1b[31m[FAIL]\x1b[0m Failed sending Pseudo-TLS ClientHello: {}", e);
        exit(1);
    }
    let _ = tcp_stream.flush().await;
    println!("\x1b[32m[OK]\x1b[0m Pseudo-TLS ClientHello Sent");

    // 3. Noise Handshake
    let session = match client_noise_handshake(&mut tcp_stream, &key_bytes, timeout_dur).await {
        Ok(s) => {
            println!("\x1b[32m[OK]\x1b[0m Handshake Completed");
            s
        }
        Err(e) => {
            eprintln!("\x1b[31m[FAIL]\x1b[0m Noise Handshake failed: {:?}", e);
            exit(1);
        }
    };

    // 3. Ping Frame Exchange
    let mut framed = NoiseFramedStream::new(tcp_stream, session);
    let session_id: SessionId = [0xAA; 16];
    let nonce: Nonce = [0, 0, 0, 0, 0, 0, 0, 1];
    let ping_payload = Bytes::from_static(b"PING");

    let ping_frame = match Frame::new(session_id, nonce, ping_payload.clone()) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("\x1b[31m[FAIL]\x1b[0m Failed to construct ping frame: {:?}", e);
            exit(1);
        }
    };

    if let Err(e) = framed.send_frame(&ping_frame).await {
        eprintln!("\x1b[31m[FAIL]\x1b[0m Failed sending ping frame: {:?}", e);
        exit(1);
    }

    let recv_res = tokio::time::timeout(timeout_dur, framed.recv_frame()).await;
    match recv_res {
        Ok(Ok(Some(reply_frame))) => {
            if reply_frame.payload == ping_payload {
                println!("\x1b[32m[OK]\x1b[0m Ping Ack Received");
            } else {
                eprintln!(
                    "\x1b[31m[FAIL]\x1b[0m Unexpected ping reply payload: {:?}",
                    reply_frame.payload
                );
                exit(1);
            }
        }
        Ok(Ok(None)) => {
            eprintln!("\x1b[31m[FAIL]\x1b[0m Relay closed stream before sending ping ack");
            exit(1);
        }
        Ok(Err(e)) => {
            eprintln!("\x1b[31m[FAIL]\x1b[0m Error receiving ping ack: {:?}", e);
            exit(1);
        }
        Err(_) => {
            eprintln!("\x1b[31m[FAIL]\x1b[0m Handshake timed out waiting for relay response");
            exit(1);
        }
    }

    println!("\n\x1b[1;32mSUMMARY:\x1b[0m [OK] TCP Connected -> [OK] Handshake Completed -> [OK] Ping Ack Received");
}

fn print_usage(prog: &str) {
    eprintln!("Usage: {} --relay <IP:PORT> --key <BASE64_PUBLIC_KEY> [--token <HEX_SECRET_TOKEN>]", prog);
}
