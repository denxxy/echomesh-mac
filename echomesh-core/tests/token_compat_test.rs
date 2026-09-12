use echomesh_core::transport::{DEFAULT_SECRET_TOKEN, PseudoTlsBuilder};

/// Extracts the 32-byte Client Random field from a TLS 1.3 ClientHello record.
/// Wire layout:
/// - 0..5: TLS Record Header (0x16 0x03 0x01 len_hi len_lo)
/// - 5..9: Handshake Header (0x01 len_hi len_mid len_lo)
/// - 9..11: Legacy Client Version (0x03 0x03)
/// - 11..43: Client Random (32 bytes)
fn extract_random_from_client_hello(buf: &[u8]) -> Option<&[u8]> {
    if buf.len() >= 43 && buf[0] == 0x16 && buf[5] == 0x01 {
        Some(&buf[11..43])
    } else {
        None
    }
}

/// Simulates the relay's TokenValidator: checks if the embedded token matches expected.
fn validate_token(client_hello: &[u8], expected_token: &[u8]) -> bool {
    if let Some(random) = extract_random_from_client_hello(client_hello) {
        if expected_token.len() <= random.len() {
            return &random[..expected_token.len()] == expected_token;
        }
    }
    false
}

#[test]
fn test_token_compat_client_to_relay() {
    // 1. Client builds Pseudo-TLS ClientHello using default secret token
    let tls_builder = PseudoTlsBuilder::new(DEFAULT_SECRET_TOKEN, "cloudflare.com");
    let client_hello_buf = tls_builder.build();

    // 2. Relay validates ClientHello using server's TokenValidator and DEFAULT_SECRET_TOKEN
    assert!(
        validate_token(&client_hello_buf, DEFAULT_SECRET_TOKEN),
        "Relay TokenValidator must successfully validate ClientHello built with client's PseudoTlsBuilder"
    );
}

#[test]
fn test_token_compat_with_empty_token_defaults_to_secret() {
    // When client passes empty token, it must default to DEFAULT_SECRET_TOKEN
    let tls_builder = PseudoTlsBuilder::new(Vec::<u8>::new(), "cloudflare.com");
    let client_hello_buf = tls_builder.build();

    assert!(
        validate_token(&client_hello_buf, DEFAULT_SECRET_TOKEN),
        "Client with empty secret token must default to DEFAULT_SECRET_TOKEN and be accepted by relay"
    );
}

#[test]
fn test_token_compat_custom_secret() {
    let custom_token = b"custom_secret_shared_token_9999";
    let tls_builder = PseudoTlsBuilder::new(custom_token.to_vec(), "cloudflare.com");
    let client_hello_buf = tls_builder.build();

    assert!(
        validate_token(&client_hello_buf, custom_token),
        "Relay TokenValidator must validate matching custom secret"
    );

    assert!(
        !validate_token(&client_hello_buf, b"wrong_secret_mismatch_12345678"),
        "Relay TokenValidator must reject invalid secret"
    );
}
