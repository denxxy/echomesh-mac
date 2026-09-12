use echomesh_core::transport::{DEFAULT_SECRET_TOKEN as CLIENT_DEFAULT_TOKEN, PseudoTlsBuilder};
use echomesh_relay::config::DEFAULT_SECRET_TOKEN as RELAY_DEFAULT_TOKEN;
use echomesh_relay::transport::{parse_client_hello, ClientHelloStatus, TokenValidator};

#[test]
fn test_token_compat_client_to_relay() {
    // 1. Client builds Pseudo-TLS ClientHello using default secret token
    let tls_builder = PseudoTlsBuilder::new(CLIENT_DEFAULT_TOKEN, "cloudflare.com");
    let client_hello_buf = tls_builder.build();

    // 2. Relay parses ClientHello record
    let status = parse_client_hello(&client_hello_buf);
    let parsed = match status {
        ClientHelloStatus::Complete(p) => p,
        other => panic!("Expected ClientHelloStatus::Complete, got {:?}", other),
    };

    // 3. Relay validates ClientHello using server's TokenValidator and DEFAULT_SECRET_TOKEN
    let validator = TokenValidator::new(RELAY_DEFAULT_TOKEN);
    let valid = validator.validate(&parsed);

    assert!(
        valid,
        "Relay TokenValidator must successfully validate ClientHello built with client's PseudoTlsBuilder"
    );
}

#[test]
fn test_token_compat_with_empty_token_defaults_to_secret() {
    // When client passes empty token, it must default to DEFAULT_SECRET_TOKEN
    let tls_builder = PseudoTlsBuilder::new(Vec::<u8>::new(), "cloudflare.com");
    let client_hello_buf = tls_builder.build();

    let status = parse_client_hello(&client_hello_buf);
    let parsed = match status {
        ClientHelloStatus::Complete(p) => p,
        other => panic!("Expected ClientHelloStatus::Complete, got {:?}", other),
    };

    let validator = TokenValidator::new(RELAY_DEFAULT_TOKEN);
    let valid = validator.validate(&parsed);
    assert!(
        valid,
        "Client with empty secret token must default to DEFAULT_SECRET_TOKEN and be accepted by relay"
    );
}

#[test]
fn test_token_compat_custom_secret() {
    let custom_token = b"custom_secret_shared_token_9999";
    let tls_builder = PseudoTlsBuilder::new(custom_token.to_vec(), "cloudflare.com");
    let client_hello_buf = tls_builder.build();

    let status = parse_client_hello(&client_hello_buf);
    let parsed = match status {
        ClientHelloStatus::Complete(p) => p,
        other => panic!("Expected ClientHelloStatus::Complete, got {:?}", other),
    };

    let validator = TokenValidator::new(custom_token);
    let valid = validator.validate(&parsed);
    assert!(valid, "Relay TokenValidator must validate matching custom secret");

    let wrong_validator = TokenValidator::new(b"wrong_secret_mismatch_12345678");
    assert!(!wrong_validator.validate(&parsed), "Relay TokenValidator must reject invalid secret");
}
