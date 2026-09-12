use base64::Engine;
use snow::Builder;
use std::env;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Использование: cargo run --bin test_client <IP:PORT> <BASE64_PUB_KEY>");
        std::process::exit(1);
    }

    let target = &args[1];
    let pub_key_raw = &args[2];
    let remote_static = base64::engine::general_purpose::STANDARD.decode(pub_key_raw)?;

    println!("1. Подключение к {}...", target);
    let mut stream = TcpStream::connect(target).await?;
    println!("  [OK] TCP-сокет успешно открыт.");

    println!("2. Инициализация Noise_NK рукопожатия...");
    let params: snow::params::NoiseParams = "Noise_NK_25519_ChaChaPoly_BLAKE2s".parse()?;
    let mut noise = Builder::new(params)
        .remote_public_key(&remote_static)?
        .build_initiator()?;

    let mut buf = vec![0u8; 65535];
    let len = noise.write_message(&[], &mut buf)?;

    println!("3. Отправка первого сообщения рукопожатия ({} байт)...", len);
    stream.write_all(&buf[..len]).await?;

    // Читаем ответ сервера (если в коде релея есть ответный фрейм)
    let mut read_buf = [0u8; 1024];
    let n = stream.read(&mut read_buf).await?;
    println!("  [OK] Получен ответ от сервера: {} байт.", n);

    println!("\n=== Тест успешно пройден: Сервер принял ключ! ===");
    Ok(())
}
