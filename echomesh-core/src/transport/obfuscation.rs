use bytes::{BufMut, BytesMut};

/// TLS Content Type for Handshake records.
pub const TLS_HANDSHAKE_CONTENT_TYPE: u8 = 0x16;

/// TLS Handshake Type for ClientHello.
pub const TLS_CLIENT_HELLO_HANDSHAKE_TYPE: u8 = 0x01;

/// Legacy TLS record version commonly sent in TLS 1.3 ClientHello (TLS 1.0 = 0x0301).
pub const TLS_LEGACY_RECORD_VERSION: u16 = 0x0301;

/// Legacy ClientHello version (TLS 1.2 = 0x0303).
pub const TLS_LEGACY_CLIENT_VERSION: u16 = 0x0303;

/// TLS 1.3 version identifier (0x0304).
pub const TLS_1_3_VERSION: u16 = 0x0304;

/// TLS Extension Type: Server Name Indication (SNI).
pub const TLS_EXT_SERVER_NAME: u16 = 0x0000;

/// TLS Extension Type: Supported Groups.
pub const TLS_EXT_SUPPORTED_GROUPS: u16 = 0x000a;

/// TLS Extension Type: Signature Algorithms.
pub const TLS_EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;

/// TLS Extension Type: Supported Versions.
pub const TLS_EXT_SUPPORTED_VERSIONS: u16 = 0x002b;

/// TLS Extension Type: Key Share.
pub const TLS_EXT_KEY_SHARE: u16 = 0x0033;

/// Standard TLS 1.3 Cipher Suites
pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
pub const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

/// Builder for generating authentic TLS 1.3 ClientHello messages (Pseudo-TLS Handshake)
/// with embedded secret tokens to bypass DPI inspection.
pub struct PseudoTlsBuilder {
    secret_token: Vec<u8>,
    sni_host: String,
    token_in_sni: bool,
    cipher_suites: Vec<u16>,
}

impl PseudoTlsBuilder {
    /// Creates a new builder with the given secret token and SNI disguise host (e.g. "cloudflare.com").
    pub fn new(secret_token: impl Into<Vec<u8>>, sni_host: impl Into<String>) -> Self {
        Self {
            secret_token: secret_token.into(),
            sni_host: sni_host.into(),
            token_in_sni: false,
            cipher_suites: vec![
                TLS_AES_128_GCM_SHA256,
                TLS_AES_256_GCM_SHA384,
                TLS_CHACHA20_POLY1305_SHA256,
            ],
        }
    }

    /// Configure embedding secret token into the SNI host (e.g. "<hex_token>.cloudflare.com").
    pub fn embed_in_sni(mut self, enabled: bool) -> Self {
        self.token_in_sni = enabled;
        self
    }

    /// Builds the complete binary TLS 1.3 ClientHello record ready for transmission over TCP.
    pub fn build(&self) -> Vec<u8> {
        let mut random = [0x5au8; 32];
        // Embed token in random if token_in_sni is false or token length <= 32
        if !self.token_in_sni && !self.secret_token.is_empty() {
            let copy_len = self.secret_token.len().min(32);
            random[..copy_len].copy_from_slice(&self.secret_token[..copy_len]);
        }

        let sni_string = if self.token_in_sni {
            let hex_token = hex::encode(&self.secret_token);
            format!("{}.{}", hex_token, self.sni_host)
        } else {
            self.sni_host.clone()
        };

        let mut hs_body = BytesMut::with_capacity(512);

        // legacy_version = 0x0303
        hs_body.put_u16(TLS_LEGACY_CLIENT_VERSION);

        // random (32 bytes)
        hs_body.put_slice(&random);

        // legacy_session_id (32 bytes middlebox compat)
        hs_body.put_u8(32);
        hs_body.put_bytes(0x22, 32);

        // cipher_suites
        hs_body.put_u16((self.cipher_suites.len() * 2) as u16);
        for cs in &self.cipher_suites {
            hs_body.put_u16(*cs);
        }

        // legacy_compression_methods (1 byte len, 0x00)
        hs_body.put_u8(1);
        hs_body.put_u8(0);

        // Build extensions
        let mut ext_buf = BytesMut::with_capacity(256);

        // 1. SNI extension (0x0000)
        let sni_bytes = sni_string.as_bytes();
        let sni_list_len = 1 + 2 + sni_bytes.len();
        let sni_ext_len = 2 + sni_list_len;
        ext_buf.put_u16(TLS_EXT_SERVER_NAME);
        ext_buf.put_u16(sni_ext_len as u16);
        ext_buf.put_u16(sni_list_len as u16);
        ext_buf.put_u8(0); // host_name type
        ext_buf.put_u16(sni_bytes.len() as u16);
        ext_buf.put_slice(sni_bytes);

        // 2. Supported Versions extension (0x002b) -> TLS 1.3 (0x0304) and TLS 1.2 (0x0303)
        ext_buf.put_u16(TLS_EXT_SUPPORTED_VERSIONS);
        ext_buf.put_u16(5); // ext len: 1 byte list len + 4 bytes versions
        ext_buf.put_u8(4); // 2 versions = 4 bytes
        ext_buf.put_u16(TLS_1_3_VERSION);
        ext_buf.put_u16(TLS_LEGACY_CLIENT_VERSION);

        // 3. Supported Groups extension (0x000a) -> x25519 (0x001d), secp256r1 (0x0017)
        ext_buf.put_u16(TLS_EXT_SUPPORTED_GROUPS);
        ext_buf.put_u16(6);
        ext_buf.put_u16(4);
        ext_buf.put_u16(0x001d); // x25519
        ext_buf.put_u16(0x0017); // secp256r1

        // 4. Signature Algorithms extension (0x000d)
        ext_buf.put_u16(TLS_EXT_SIGNATURE_ALGORITHMS);
        ext_buf.put_u16(8);
        ext_buf.put_u16(6);
        ext_buf.put_u16(0x0403); // ecdsa_secp256r1_sha256
        ext_buf.put_u16(0x0804); // rsa_pss_rsae_sha256
        ext_buf.put_u16(0x0807); // ed25519

        // 5. Key Share extension (0x0033) -> dummy x25519 public key (32 bytes)
        ext_buf.put_u16(TLS_EXT_KEY_SHARE);
        ext_buf.put_u16(2 + 2 + 2 + 32); // 38 bytes
        ext_buf.put_u16(2 + 2 + 32); // client_shares_len: 36 bytes
        ext_buf.put_u16(0x001d); // x25519 group
        ext_buf.put_u16(32); // key_exchange_len
        ext_buf.put_bytes(0x42, 32); // dummy public key share

        // Put extensions into hs_body
        hs_body.put_u16(ext_buf.len() as u16);
        hs_body.put_slice(&ext_buf);

        // Wrap Handshake message in TLS Record:
        let hs_len = hs_body.len();
        let total_record_len = 4 + hs_len;

        let mut record = Vec::with_capacity(5 + total_record_len);
        // Record header (5 bytes)
        record.push(TLS_HANDSHAKE_CONTENT_TYPE);
        record.extend_from_slice(&TLS_LEGACY_RECORD_VERSION.to_be_bytes());
        record.extend_from_slice(&(total_record_len as u16).to_be_bytes());

        // Handshake header (4 bytes: 1 byte type + 3 bytes length)
        record.push(TLS_CLIENT_HELLO_HANDSHAKE_TYPE);
        record.push(((hs_len >> 16) & 0xFF) as u8);
        record.push(((hs_len >> 8) & 0xFF) as u8);
        record.push((hs_len & 0xFF) as u8);

        // Handshake body
        record.extend_from_slice(&hs_body);

        record
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pseudo_tls_builder_embeds_token_in_random() {
        let token = b"abcdef0123456789abcdef0123456789";
        let builder = PseudoTlsBuilder::new(token.to_vec(), "cloudflare.com");
        let bytes = builder.build();

        assert!(bytes.len() > 40);
        assert_eq!(bytes[0], TLS_HANDSHAKE_CONTENT_TYPE);

        // Record header is 5 bytes.
        // Handshake header is 4 bytes: [0x01, len_24].
        // legacy_version is 2 bytes: [0x03, 0x03].
        // random begins at offset 5 + 4 + 2 = 11.
        let random_slice = &bytes[11..11 + 32];
        assert_eq!(&random_slice[..32], &token[..32]);
    }
}
