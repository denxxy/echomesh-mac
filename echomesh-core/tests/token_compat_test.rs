use echomesh_core::transport::{DEFAULT_SECRET_TOKEN, PseudoTlsBuilder};

fn extract_random_from_client_hello(buf: &[u8]) -> Option<&[u8]> {
    if buf.len() >= 43 && buf[0] == 0x16 && buf[5] == 0x01 { Some(&buf[11..43]) } else { None }
}

fn validate_token(client_hello: &[u8], expected_token: &[u8]) -> bool {
    if expected_token.is_empty() { return false; }
    extract_random_from_client_hello(client_hello)
        .map(|random| expected_token.len() <= random.len() && &random[..expected_token.len()] == expected_token)
        .unwrap_or(false)
}

#[test]
fn no_compiled_default_credential_exists() {
    assert!(DEFAULT_SECRET_TOKEN.is_empty());
}

#[test]
fn empty_credential_does_not_authenticate() {
    let hello = PseudoTlsBuilder::new(Vec::<u8>::new(), "cloudflare.com").build();
    assert!(!validate_token(&hello, DEFAULT_SECRET_TOKEN));
}

#[test]
fn explicit_client_and_relay_credentials_match() {
    let custom_token = b"custom_secret_shared_token_9999";
    let hello = PseudoTlsBuilder::new(custom_token.to_vec(), "cloudflare.com").build();
    assert!(validate_token(&hello, custom_token));
    assert!(!validate_token(&hello, b"wrong_secret_mismatch_12345678"));
}
