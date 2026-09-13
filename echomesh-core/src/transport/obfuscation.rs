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

/// No production authorization credential is compiled into the client.
pub const DEFAULT_SECRET_TOKEN: &[u8] = b"";

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

    pub fn embed_in_sni(mut self, enabled: bool) -> Self { self.token_in_sni = enabled; self }

    pub fn build(&self) -> Vec<u8> {
        let mut random = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut random);
        if !self.token_in_sni && !self.secret_token.is_empty() {
            let copy_len = self.secret_token.len().min(32);
            random[..copy_len].copy_from_slice(&self.secret_token[..copy_len]);
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
        ext_buf.put_u16(TLS_EXT_SERVER_NAME);
        ext_buf.put_u16((2 + sni_list_len) as u16);
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
        let mut dummy_key_share = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut dummy_key_share);
        ext_buf.put_slice(&dummy_key_share);

        hs_body.put_u16(ext_buf.len() as u16);
        hs_body.put_slice(&ext_buf);

        let hs_len = hs_body.len();
        let total_record_len = 4 + hs_len;
        let mut record = Vec::with_capacity(5 + total_record_len);
        record.push(TLS_HANDSHAKE_CONTENT_TYPE);
        record.extend_from_slice(&TLS_LEGACY_RECORD_VERSION.to_be_bytes());
        record.extend_from_slice(&(total_record_len as u16).to_be_bytes());
        record.push(TLS_CLIENT_HELLO_HANDSHAKE_TYPE);
        record.push(((hs_len >> 16) & 0xff) as u8);
        record.push(((hs_len >> 8) & 0xff) as u8);
        record.push((hs_len & 0xff) as u8);
        record.extend_from_slice(&hs_body);
        record
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn embeds_explicit_token_in_random() {
        let token = b"abcdef0123456789abcdef0123456789";
        let bytes = PseudoTlsBuilder::new(token.to_vec(), "cloudflare.com").build();
        assert_eq!(&bytes[11..43], &token[..32]);
    }

    #[test]
    fn empty_token_is_not_a_shared_default() {
        assert!(DEFAULT_SECRET_TOKEN.is_empty());
        let a = PseudoTlsBuilder::new(Vec::<u8>::new(), "cloudflare.com").build();
        let b = PseudoTlsBuilder::new(Vec::<u8>::new(), "cloudflare.com").build();
        assert_ne!(&a[11..43], &b[11..43]);
    }
}
