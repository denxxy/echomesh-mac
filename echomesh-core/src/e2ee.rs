use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::EchoMeshError;

const LEGACY_VERSION: u8 = 1;
const AUTHENTICATED_VERSION: u8 = 3;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const V1_HEADER_LEN: usize = 1 + KEY_LEN + NONCE_LEN;
const V2_HEADER_LEN: usize = 1 + KEY_LEN + KEY_LEN + NONCE_LEN;
const HKDF_INFO_V1: &[u8] = b"echomesh/client-e2ee/v1";
const HKDF_INFO_V2: &[u8] = b"echomesh/client-e2ee/v3-authenticated";

fn crypto_error(message: impl Into<String>) -> EchoMeshError {
    EchoMeshError::NoiseError(message.into())
}

fn key_array(key: &[u8]) -> Result<[u8; 32], EchoMeshError> {
    key.try_into().map_err(|_| EchoMeshError::InvalidKeyLength {
        expected: 32,
        actual: key.len() as u32,
    })
}

/// Legacy recipient-confidential v1 envelope. Kept only for backwards decoding/tests.
pub fn encrypt_for_peer(recipient_public_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, EchoMeshError> {
    let recipient = PublicKey::from(key_array(recipient_public_key)?);
    let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    let shared = ephemeral_secret.diffie_hellman(&recipient);
    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(HKDF_INFO_V1, &mut key).map_err(|_| crypto_error("HKDF expansion failed"))?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| crypto_error("invalid AEAD key"))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|_| crypto_error("E2EE encryption failed"))?;
    let mut out = Vec::with_capacity(V1_HEADER_LEN + ciphertext.len());
    out.push(LEGACY_VERSION);
    out.extend_from_slice(ephemeral_public.as_bytes());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn decrypt_from_peer(local_private_key: &[u8], envelope: &[u8]) -> Result<Vec<u8>, EchoMeshError> {
    let local_secret = StaticSecret::from(key_array(local_private_key)?);
    if envelope.len() <= V1_HEADER_LEN || envelope[0] != LEGACY_VERSION {
        return Err(crypto_error("invalid legacy E2EE envelope"));
    }
    let ephemeral_public = PublicKey::from(key_array(&envelope[1..33])?);
    let shared = local_secret.diffie_hellman(&ephemeral_public);
    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(HKDF_INFO_V1, &mut key).map_err(|_| crypto_error("HKDF expansion failed"))?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| crypto_error("invalid AEAD key"))?;
    cipher
        .decrypt(Nonce::from_slice(&envelope[33..45]), &envelope[V1_HEADER_LEN..])
        .map_err(|_| crypto_error("E2EE authentication failed"))
}

/// Authenticated client-to-client envelope.
///
/// Key material combines an ephemeral->recipient DH and a sender-static->recipient
/// DH. The sender public key and recipient identity are authenticated as AEAD AAD,
/// so a relay can route/replay opaque bytes but cannot forge one client as another.
pub fn encrypt_authenticated(
    sender_private_key: &[u8],
    sender_public_key: &[u8],
    recipient_public_key: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, EchoMeshError> {
    let sender_secret = StaticSecret::from(key_array(sender_private_key)?);
    let sender_public = PublicKey::from(key_array(sender_public_key)?);
    if PublicKey::from(&sender_secret).as_bytes() != sender_public.as_bytes() {
        return Err(crypto_error("sender private/public identity mismatch"));
    }
    let recipient = PublicKey::from(key_array(recipient_public_key)?);
    let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    let ephemeral_shared = ephemeral_secret.diffie_hellman(&recipient);
    let static_shared = sender_secret.diffie_hellman(&recipient);
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(ephemeral_shared.as_bytes());
    ikm[32..].copy_from_slice(static_shared.as_bytes());
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut key = [0u8; 32];
    hk.expand(HKDF_INFO_V2, &mut key).map_err(|_| crypto_error("authenticated HKDF expansion failed"))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let mut aad = Vec::with_capacity(1 + 32 + 32 + 32);
    aad.push(AUTHENTICATED_VERSION);
    aad.extend_from_slice(sender_public.as_bytes());
    aad.extend_from_slice(ephemeral_public.as_bytes());
    aad.extend_from_slice(recipient.as_bytes());

    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| crypto_error("invalid AEAD key"))?;
    
    // V3: Prepend 8-byte timestamp to plaintext for replay protection
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
    let mut payload = Vec::with_capacity(8 + plaintext.len());
    payload.extend_from_slice(&now.to_be_bytes());
    payload.extend_from_slice(plaintext);

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), Payload { msg: &payload, aad: &aad })
        .map_err(|_| crypto_error("authenticated E2EE encryption failed"))?;

    let mut out = Vec::with_capacity(V2_HEADER_LEN + ciphertext.len());
    out.push(AUTHENTICATED_VERSION);
    out.extend_from_slice(sender_public.as_bytes());
    out.extend_from_slice(ephemeral_public.as_bytes());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Returns the cryptographically authenticated sender public key and plaintext.
pub fn decrypt_authenticated(
    local_private_key: &[u8],
    local_public_key: &[u8],
    envelope: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), EchoMeshError> {
    let local_secret = StaticSecret::from(key_array(local_private_key)?);
    let local_public = PublicKey::from(key_array(local_public_key)?);
    if PublicKey::from(&local_secret).as_bytes() != local_public.as_bytes() {
        return Err(crypto_error("local private/public identity mismatch"));
    }
    if envelope.len() <= V2_HEADER_LEN || envelope[0] != AUTHENTICATED_VERSION {
        return Err(crypto_error("invalid authenticated E2EE envelope"));
    }

    let sender_public = PublicKey::from(key_array(&envelope[1..33])?);
    let ephemeral_public = PublicKey::from(key_array(&envelope[33..65])?);
    let nonce = &envelope[65..77];
    let ciphertext = &envelope[V2_HEADER_LEN..];

    let ephemeral_shared = local_secret.diffie_hellman(&ephemeral_public);
    let static_shared = local_secret.diffie_hellman(&sender_public);
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(ephemeral_shared.as_bytes());
    ikm[32..].copy_from_slice(static_shared.as_bytes());
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut key = [0u8; 32];
    hk.expand(HKDF_INFO_V2, &mut key).map_err(|_| crypto_error("authenticated HKDF expansion failed"))?;

    let mut aad = Vec::with_capacity(1 + 32 + 32 + 32);
    aad.push(AUTHENTICATED_VERSION);
    aad.extend_from_slice(sender_public.as_bytes());
    aad.extend_from_slice(ephemeral_public.as_bytes());
    aad.extend_from_slice(local_public.as_bytes());

    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| crypto_error("invalid AEAD key"))?;
    let decrypted = cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad: &aad })
        .map_err(|_| crypto_error("authenticated E2EE verification failed"))?;
        
    if decrypted.len() < 8 {
        return Err(crypto_error("invalid E2EE payload length (missing timestamp)"));
    }
    
    let ts_bytes: [u8; 8] = decrypted[..8].try_into().unwrap();
    let msg_ts = u64::from_be_bytes(ts_bytes);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
    
    // Reject messages older than 2 hours or from the future (> 5 min)
    let two_hours = 2 * 60 * 60 * 1000;
    let five_min = 5 * 60 * 1000;
    if now.saturating_sub(msg_ts) > two_hours || msg_ts.saturating_sub(now) > five_min {
        return Err(crypto_error("E2EE payload rejected: timestamp out of bounds (replay protection)"));
    }
    
    let plaintext = decrypted[8..].to_vec();
    Ok((sender_public.as_bytes().to_vec(), plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticated_round_trip_and_sender_binding() {
        let alice_secret = StaticSecret::random_from_rng(OsRng);
        let alice_public = PublicKey::from(&alice_secret);
        let bob_secret = StaticSecret::random_from_rng(OsRng);
        let bob_public = PublicKey::from(&bob_secret);
        let plaintext = b"relay must never see or forge this plaintext";

        let envelope = encrypt_authenticated(
            &alice_secret.to_bytes(),
            alice_public.as_bytes(),
            bob_public.as_bytes(),
            plaintext,
        ).unwrap();
        assert!(!envelope.windows(plaintext.len()).any(|w| w == plaintext));

        let (sender, decoded) = decrypt_authenticated(
            &bob_secret.to_bytes(),
            bob_public.as_bytes(),
            &envelope,
        ).unwrap();
        assert_eq!(sender, alice_public.as_bytes());
        assert_eq!(decoded, plaintext);

        let mallory_secret = StaticSecret::random_from_rng(OsRng);
        let mallory_public = PublicKey::from(&mallory_secret);
        assert!(decrypt_authenticated(&bob_secret.to_bytes(), mallory_public.as_bytes(), &envelope).is_err());
    }
}

    #[test]
    fn wrong_key_decryption_fails() {
        let alice_secret = StaticSecret::random_from_rng(OsRng);
        let alice_public = PublicKey::from(&alice_secret);
        let bob_secret = StaticSecret::random_from_rng(OsRng);
        let bob_public = PublicKey::from(&bob_secret);
        let eve_secret = StaticSecret::random_from_rng(OsRng);
        let eve_public = PublicKey::from(&eve_secret);

        let envelope = encrypt_authenticated(
            &alice_secret.to_bytes(),
            alice_public.as_bytes(),
            bob_public.as_bytes(),
            b"secret message",
        ).unwrap();

        // Eve tries to decrypt
        assert!(decrypt_authenticated(&eve_secret.to_bytes(), eve_public.as_bytes(), &envelope).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let alice_secret = StaticSecret::random_from_rng(OsRng);
        let alice_public = PublicKey::from(&alice_secret);
        let bob_secret = StaticSecret::random_from_rng(OsRng);
        let bob_public = PublicKey::from(&bob_secret);

        let mut envelope = encrypt_authenticated(
            &alice_secret.to_bytes(),
            alice_public.as_bytes(),
            bob_public.as_bytes(),
            b"secret message",
        ).unwrap();

        // Flip a bit in the ciphertext
        let len = envelope.len();
        envelope[len - 1] ^= 0x01;

        assert!(decrypt_authenticated(&bob_secret.to_bytes(), bob_public.as_bytes(), &envelope).is_err());
    }

    #[test]
    fn tampered_sender_identity_fails() {
        let alice_secret = StaticSecret::random_from_rng(OsRng);
        let alice_public = PublicKey::from(&alice_secret);
        let bob_secret = StaticSecret::random_from_rng(OsRng);
        let bob_public = PublicKey::from(&bob_secret);

        let mut envelope = encrypt_authenticated(
            &alice_secret.to_bytes(),
            alice_public.as_bytes(),
            bob_public.as_bytes(),
            b"secret message",
        ).unwrap();

        // Tamper with the sender public key in the envelope header
        envelope[1] ^= 0x01;

        assert!(decrypt_authenticated(&bob_secret.to_bytes(), bob_public.as_bytes(), &envelope).is_err());
    }

    #[test]
    fn replay_protection_rejects_outdated_timestamps() {
        let alice_secret = StaticSecret::random_from_rng(OsRng);
        let alice_public = PublicKey::from(&alice_secret);
        let bob_secret = StaticSecret::random_from_rng(OsRng);
        let bob_public = PublicKey::from(&bob_secret);

        let recipient = PublicKey::from(key_array(bob_public.as_bytes()).unwrap());
        let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);

        let ephemeral_shared = ephemeral_secret.diffie_hellman(&recipient);
        let static_shared = alice_secret.diffie_hellman(&recipient);
        let mut ikm = [0u8; 64];
        ikm[..32].copy_from_slice(ephemeral_shared.as_bytes());
        ikm[32..].copy_from_slice(static_shared.as_bytes());
        let hk = Hkdf::<Sha256>::new(None, &ikm);
        let mut key = [0u8; 32];
        hk.expand(HKDF_INFO_V2, &mut key).unwrap();

        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let mut aad = Vec::with_capacity(1 + 32 + 32 + 32);
        aad.push(AUTHENTICATED_VERSION);
        aad.extend_from_slice(alice_public.as_bytes());
        aad.extend_from_slice(ephemeral_public.as_bytes());
        aad.extend_from_slice(bob_public.as_bytes());

        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        
        // Construct an OLD timestamp (3 hours ago)
        let old_time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64 - (3 * 3600 * 1000);
        let mut old_payload = Vec::new();
        old_payload.extend_from_slice(&old_time.to_be_bytes());
        old_payload.extend_from_slice(b"replayed message");

        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), Payload { msg: &old_payload, aad: &aad })
            .unwrap();

        let mut out = Vec::with_capacity(V2_HEADER_LEN + ciphertext.len());
        out.push(AUTHENTICATED_VERSION);
        out.extend_from_slice(alice_public.as_bytes());
        out.extend_from_slice(ephemeral_public.as_bytes());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);

        // Bob should reject this outdated envelope
        assert!(decrypt_authenticated(&bob_secret.to_bytes(), bob_public.as_bytes(), &out).is_err());
    }
