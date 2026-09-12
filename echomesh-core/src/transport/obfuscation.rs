use bytes::{BufMut, BytesMut};
use rand::RngCore;

pub const TLS_HANDSHAKE_CONTENT_TYPE: u8 = 0x16;
pub const TLS_CLIENT_HELLO_HANDSHAKE_TYPE: u8 = 0x01;
pub const TLS_LEGACY_RECORD_VERSION: u16 = 0x0301;
pub const TLS_LEGACY_CLIENT_VERSION: u16 = 0x0303;
pub const TLS_1_3_VERSION: u16 = 0x0304;
pub const TLS_EXT_SERVER_NAME: u16 = 0x0000;
pub const TLS_EXT_SUPPORTED_GROUPS: u16 = 0x000a;
pub const TLS_EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
pub const TLS_EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
pub const TLS_EXT_KEY_SHARE: u16 = 0x0033;
pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
pub const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

/// Kept as an empty compatibility constant so downstream code cannot silently
/// fall back to a repository-wide shared password.
pub const DEFAULT_SECRET_TOKEN: &[u8] = &[];

pub struct PseudoTlsBuilder {
    secret_token: Vec<u8>,
    sni_host: String,
    token_in_sni: bool,
    cipher_suites: Vec<u16>,
}

impl PseudoTlsBuilder {
    pub fn new(secret_token: impl Into<Vec<u8>>, sni_host: impl Into<String>) -> Self {
        Self {
            secret_token: secret_token.into(),
            sni_host: sni_host.into(),
            token_in_sni: false,
            cipher_suites: vec![TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256],
        }
    }

    pub fn embed_in_sni(mut self, enabled: bool) -> Self {
        self.token_in_sni = enabled;
        self
    }

    pub fn build(&self) -> Vec<u8> {
        let mut random = [0u8; 32];
        if !self.token_in_sni {
            let copy_len = self.secret_token.len().min(32);
            if copy_len > 0 {
                random[..copy_len].copy_from_slice(&self.secret_token[..copy_len]);
            }
            if copy_len < 32 {
                rand::thread_rng().fill_bytes(&mut random[copy_len..]);
            }
        } else {
            rand::thread_rng().fill_bytes(&mut random);
        }

        let sni_string = if self.token_in_sni && !self.secret_token.is_empty() {
            format!("{}.{}", hex::encode(&self.secret_token), self.sni_host)
        } else {
            self.sni_host.clone()
        };

        let mut hs_body = BytesMut::with_capacity(512);
        hs_body.put_u16(TLS_LEGACY_CLIENT_VERSION);
        hs_body.put_slice(&random);
        hs_body.put_u8(32);
        hs_body.put_bytes(0x22, 32);
        hs_body.put_u16((self.cipher_suites.len() * 2) as u16);
        for cs in &self.cipher_suites { hs_body.put_u16(*cs); }
        hs_body.put_u8(1);
        hs_body.put_u8(0);

        let mut ext_buf = BytesMut::with_capacity(256);
        let sni_bytes = sni_string.as_bytes();
        let sni_list_len = 1 + 2 + sni_bytes.len();
        let sni_ext_len = 2 + sni_list_len;
        ext_buf.put_u16(TLS_EXT_SERVER_NAME);
        ext_buf.put_u16(sni_ext_len as u16);
        ext_buf.put_u16(sni_list_len as u16);
        ext_buf.put_u8(0);
        ext_buf.put_u16(sni_bytes.len() as u16);
        ext_buf.put_slice(sni_bytes);

        ext_buf.put_u16(TLS_EXT_SUPPORTED_VERSIONS);
        ext_buf.put_u16(5);
        ext_buf.put_u8(4);
        ext_buf.put_u16(TLS_1_3_VERSION);
        ext_buf.put_u16(TLS_LEGACY_CLIENT_VERSION);

        ext_buf.put_u16(TLS_EXT_SUPPORTED_GROUPS);
        ext_buf.put_u16(6);
        ext_buf.put_u16(4);
        ext_buf.put_u16(0x001d);
        ext_buf.put_u16(0x0017);

        ext_buf.put_u16(TLS_EXT_SIGNATURE_ALGORITHMS);
        ext_buf.put_u16(8);
        ext_buf.put_u16(6);
        ext_buf.put_u16(0x0403);
        ext_buf.put_u16(0x0804);
        ext_buf.put_u16(0x0807);

        ext_buf.put_u16(TLS_EXT_KEY_SHARE);
        ext_buf.put_u16(38);
        ext_buf.put_u16(36);
        ext_buf.put_u16(0x001d);
        ext_buf.put_u16(32);
        ext_buf.put_bytes(0x42, 32);

        hs_body.put_u16(ext_buf.len() as u16);
        hs_body.put_slice(&ext_buf);

        let hs_len = hs_body.len();
        let total_record_len = 4 + hs_len;
        let mut record = Vec::with_capacity(5 + total_record_len);
        record.push(TLS_HANDSHAKE_CONTENT_TYPE);
        record.extend_from_slice(&TLS_LEGACY_RECORD_VERSION.to_be_bytes());
        record.extend_from_slice(&(total_record_len as u16).to_be_bytes());
        record.push(TLS_CLIENT_HELLO_HANDSHAKE_TYPE);
        record.push(((hs_len >> 16) & 0xFF) as u8);
        record.push(((hs_len >> 8) & 0xFF) as u8);
        record.push((hs_len & 0xFF) as u8);
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
        let bytes = PseudoTlsBuilder::new(token.to_vec(), "cloudflare.com").build();
        assert!(bytes.len() > 40);
        assert_eq!(bytes[0], TLS_HANDSHAKE_CONTENT_TYPE);
        assert_eq!(&bytes[11..43], &token[..32]);
    }

    #[test]
    fn empty_token_has_no_static_repository_secret() {
        assert!(DEFAULT_SECRET_TOKEN.is_empty());
        let first = PseudoTlsBuilder::new(Vec::<u8>::new(), "cloudflare.com").build();
        let second = PseudoTlsBuilder::new(Vec::<u8>::new(), "cloudflare.com").build();
        assert_ne!(&first[11..43], &second[11..43]);
    }
}
