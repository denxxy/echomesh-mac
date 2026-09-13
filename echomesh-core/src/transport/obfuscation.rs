use bytes::{BufMut, BytesMut};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

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

pub const DEFAULT_SECRET_TOKEN: &[u8] = &[];
const COVER_AUTH_CONTEXT: &[u8] = b"EchoMesh pseudo-TLS auth v1";
type HmacSha256 = Hmac<Sha256>;

pub struct PseudoTlsBuilder {
    secret_token: Vec<u8>,
    sni_host: String,
    cipher_suites: Vec<u16>,
}

impl PseudoTlsBuilder {
    pub fn new(secret_token: impl Into<Vec<u8>>, sni_host: impl Into<String>) -> Self {
        Self {
            secret_token: secret_token.into(),
            sni_host: sni_host.into().to_ascii_lowercase(),
            cipher_suites: vec![
                TLS_AES_128_GCM_SHA256,
                TLS_AES_256_GCM_SHA384,
                TLS_CHACHA20_POLY1305_SHA256,
            ],
        }
    }

    /// Retained for source compatibility. Secret-in-SNI mode is intentionally
    /// disabled; enabling this no longer changes the safe HMAC proof format.
    pub fn embed_in_sni(self, _enabled: bool) -> Self {
        self
    }

    pub fn build(&self) -> Vec<u8> {
        let mut random = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut random);

        let mut mac = HmacSha256::new_from_slice(&self.secret_token)
            .expect("HMAC accepts arbitrary key lengths");
        mac.update(COVER_AUTH_CONTEXT);
        mac.update(&random);
        mac.update(self.sni_host.as_bytes());
        let auth_tag = mac.finalize().into_bytes();

        let mut hs_body = BytesMut::with_capacity(512);
        hs_body.put_u16(TLS_LEGACY_CLIENT_VERSION);
        hs_body.put_slice(&random);
        hs_body.put_u8(32);
        hs_body.put_slice(&auth_tag);
        hs_body.put_u16((self.cipher_suites.len() * 2) as u16);
        for suite in &self.cipher_suites {
            hs_body.put_u16(*suite);
        }
        hs_body.put_u8(1);
        hs_body.put_u8(0);

        let mut extensions = BytesMut::with_capacity(256);
        let sni_bytes = self.sni_host.as_bytes();
        let sni_list_len = 1 + 2 + sni_bytes.len();
        extensions.put_u16(TLS_EXT_SERVER_NAME);
        extensions.put_u16((2 + sni_list_len) as u16);
        extensions.put_u16(sni_list_len as u16);
        extensions.put_u8(0);
        extensions.put_u16(sni_bytes.len() as u16);
        extensions.put_slice(sni_bytes);

        extensions.put_u16(TLS_EXT_SUPPORTED_VERSIONS);
        extensions.put_u16(5);
        extensions.put_u8(4);
        extensions.put_u16(TLS_1_3_VERSION);
        extensions.put_u16(TLS_LEGACY_CLIENT_VERSION);

        extensions.put_u16(TLS_EXT_SUPPORTED_GROUPS);
        extensions.put_u16(6);
        extensions.put_u16(4);
        extensions.put_u16(0x001d);
        extensions.put_u16(0x0017);

        extensions.put_u16(TLS_EXT_SIGNATURE_ALGORITHMS);
        extensions.put_u16(8);
        extensions.put_u16(6);
        extensions.put_u16(0x0403);
        extensions.put_u16(0x0804);
        extensions.put_u16(0x0807);

        let mut key_share = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key_share);
        extensions.put_u16(TLS_EXT_KEY_SHARE);
        extensions.put_u16(38);
        extensions.put_u16(36);
        extensions.put_u16(0x001d);
        extensions.put_u16(32);
        extensions.put_slice(&key_share);

        hs_body.put_u16(extensions.len() as u16);
        hs_body.put_slice(&extensions);

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
    fn cover_auth_does_not_serialize_reusable_secret() {
        let token = b"abcdef0123456789abcdef0123456789";
        let first = PseudoTlsBuilder::new(token.to_vec(), "cloudflare.com").build();
        let second = PseudoTlsBuilder::new(token.to_vec(), "cloudflare.com").build();
        assert_eq!(first[0], TLS_HANDSHAKE_CONTENT_TYPE);
        assert!(!first.windows(token.len()).any(|window| window == token));
        assert!(!second.windows(token.len()).any(|window| window == token));
        assert_ne!(first, second);
    }

    #[test]
    fn session_id_is_hmac_of_fresh_challenge_and_sni() {
        let token = b"client-relay-auth";
        let wire = PseudoTlsBuilder::new(token.to_vec(), "cloudflare.com").build();
        // TLS record(5) + handshake header(4) + legacy version(2).
        let random = &wire[11..43];
        assert_eq!(wire[43], 32);
        let proof = &wire[44..76];
        let mut mac = HmacSha256::new_from_slice(token).unwrap();
        mac.update(COVER_AUTH_CONTEXT);
        mac.update(random);
        mac.update(b"cloudflare.com");
        mac.verify_slice(proof).unwrap();
    }

    #[test]
    fn legacy_sni_switch_never_exposes_token() {
        let token = b"supersecret";
        let wire = PseudoTlsBuilder::new(token.to_vec(), "microsoft.com")
            .embed_in_sni(true)
            .build();
        assert!(!wire.windows(token.len()).any(|window| window == token));
        assert!(!String::from_utf8_lossy(&wire).contains(&hex::encode(token)));
    }

    #[test]
    fn empty_default_remains_non_shared() {
        assert!(DEFAULT_SECRET_TOKEN.is_empty());
    }
}