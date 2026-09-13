use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::EchoMeshError;

const VERSION: u8 = 1;
const EPHEMERAL_KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = 1 + EPHEMERAL_KEY_LEN + NONCE_LEN;
const HKDF_INFO: &[u8] = b"echomesh/client-e2ee/v1";

fn crypto_error(message: impl Into<String>) -> EchoMeshError { EchoMeshError::NoiseError(message.into()) }

pub fn encrypt_for_peer(recipient_public_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, EchoMeshError> {
    if recipient_public_key.len() != 32 { return Err(EchoMeshError::InvalidKeyLength { expected: 32, actual: recipient_public_key.len() as u32 }); }
    let recipient_arr: [u8; 32] = recipient_public_key.try_into().unwrap();
    let recipient = PublicKey::from(recipient_arr);
    let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    let shared = ephemeral_secret.diffie_hellman(&recipient);
    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut key).map_err(|_| crypto_error("HKDF expansion failed"))?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| crypto_error("invalid AEAD key"))?;
    let mut nonce_bytes = [0u8; NONCE_LEN]; OsRng.fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce_bytes), plaintext).map_err(|_| crypto_error("E2EE encryption failed"))?;
    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.push(VERSION); out.extend_from_slice(ephemeral_public.as_bytes()); out.extend_from_slice(&nonce_bytes); out.extend_from_slice(&ciphertext); Ok(out)
}

pub fn decrypt_from_peer(local_private_key: &[u8], envelope: &[u8]) -> Result<Vec<u8>, EchoMeshError> {
    if local_private_key.len() != 32 { return Err(EchoMeshError::InvalidKeyLength { expected: 32, actual: local_private_key.len() as u32 }); }
    if envelope.len() <= HEADER_LEN || envelope[0] != VERSION { return Err(crypto_error("invalid E2EE envelope")); }
    let private_arr: [u8; 32] = local_private_key.try_into().unwrap();
    let local_secret = StaticSecret::from(private_arr);
    let ephemeral_arr: [u8; 32] = envelope[1..33].try_into().unwrap();
    let ephemeral_public = PublicKey::from(ephemeral_arr);
    let shared = local_secret.diffie_hellman(&ephemeral_public);
    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut key).map_err(|_| crypto_error("HKDF expansion failed"))?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| crypto_error("invalid AEAD key"))?;
    cipher.decrypt(Nonce::from_slice(&envelope[33..45]), &envelope[HEADER_LEN..]).map_err(|_| crypto_error("E2EE authentication failed"))
}

#[cfg(test)] mod tests { use super::*; #[test] fn round_trip_between_two_clients() { let bob_secret=StaticSecret::random_from_rng(OsRng); let bob_public=PublicKey::from(&bob_secret); let plaintext=b"relay must never see this plaintext"; let envelope=encrypt_for_peer(bob_public.as_bytes(),plaintext).unwrap(); assert!(!envelope.windows(plaintext.len()).any(|w|w==plaintext)); let decrypted=decrypt_from_peer(&bob_secret.to_bytes(),&envelope).unwrap(); assert_eq!(decrypted,plaintext); } }
