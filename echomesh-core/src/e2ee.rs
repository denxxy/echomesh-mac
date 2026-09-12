use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::identity::{ed25519_public_to_x25519, ClientIdentity};
use crate::route::{peer_route_id, RouteId};
use crate::EchoMeshError;

pub const E2EE_MAGIC: &[u8; 4] = b"EME1";
pub const E2EE_HEADER_LEN: usize = 4 + 32 + 32 + 32 + 24 + 2;
pub const E2EE_SIGNATURE_LEN: usize = 64;
pub const E2EE_AEAD_TAG_LEN: usize = 16;
pub const E2EE_OVERHEAD: usize = E2EE_HEADER_LEN + E2EE_SIGNATURE_LEN + E2EE_AEAD_TAG_LEN;
pub const E2EE_MAX_PLAINTEXT: usize = crate::protocol::MAX_PAYLOAD_SIZE - E2EE_OVERHEAD;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptedEnvelope {
    pub sender_peer_id: [u8; 32],
    pub plaintext: Vec<u8>,
}

pub fn encrypt_for_peer(
    identity: &ClientIdentity,
    recipient_peer_id: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>, EchoMeshError> {
    if plaintext.len() > E2EE_MAX_PLAINTEXT {
        return Err(EchoMeshError::CryptoError(format!(
            "E2EE payload too large: {} > {}",
            plaintext.len(),
            E2EE_MAX_PLAINTEXT
        )));
    }

    let sender_peer_id = identity.public_key();
    let recipient_x25519 = ed25519_public_to_x25519(recipient_peer_id)?;
    let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
    let shared = ephemeral_secret.diffie_hellman(&recipient_x25519);

    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext_len = plaintext.len() + E2EE_AEAD_TAG_LEN;

    let mut header = Vec::with_capacity(E2EE_HEADER_LEN);
    header.extend_from_slice(E2EE_MAGIC);
    header.extend_from_slice(&sender_peer_id);
    header.extend_from_slice(recipient_peer_id);
    header.extend_from_slice(ephemeral_public.as_bytes());
    header.extend_from_slice(&nonce);
    header.extend_from_slice(&(ciphertext_len as u16).to_be_bytes());

    let mut aead_key = derive_aead_key(
        shared.as_bytes(),
        &sender_peer_id,
        recipient_peer_id,
        ephemeral_public.as_bytes(),
    )?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&aead_key));
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &header,
            },
        )
        .map_err(|_| EchoMeshError::CryptoError("E2EE encryption failed".to_string()))?;
    aead_key.zeroize();

    let mut signed = Vec::with_capacity(header.len() + ciphertext.len());
    signed.extend_from_slice(&header);
    signed.extend_from_slice(&ciphertext);
    let signature = identity.signing_key().sign(&signed);

    let mut envelope = Vec::with_capacity(signed.len() + E2EE_SIGNATURE_LEN);
    envelope.extend_from_slice(&signed);
    envelope.extend_from_slice(&signature.to_bytes());
    Ok(envelope)
}

pub fn decrypt_from_peer(
    identity: &ClientIdentity,
    outer_sender_route: RouteId,
    envelope: &[u8],
) -> Result<DecryptedEnvelope, EchoMeshError> {
    decrypt_envelope(identity, Some(outer_sender_route), envelope)
}

/// Decrypts an E2EE envelope received over an authenticated direct bearer such
/// as LAN or BLE. Direct transports do not have a relay-supplied outer route,
/// so sender authenticity is established by the signed Ed25519 identity inside
/// the envelope itself.
pub fn decrypt_direct(
    identity: &ClientIdentity,
    envelope: &[u8],
) -> Result<DecryptedEnvelope, EchoMeshError> {
    decrypt_envelope(identity, None, envelope)
}

fn decrypt_envelope(
    identity: &ClientIdentity,
    expected_sender_route: Option<RouteId>,
    envelope: &[u8],
) -> Result<DecryptedEnvelope, EchoMeshError> {
    if envelope.len() < E2EE_OVERHEAD || &envelope[..4] != E2EE_MAGIC {
        return Err(EchoMeshError::CryptoError("invalid E2EE envelope".to_string()));
    }

    let mut sender_peer_id = [0u8; 32];
    sender_peer_id.copy_from_slice(&envelope[4..36]);
    let mut recipient_peer_id = [0u8; 32];
    recipient_peer_id.copy_from_slice(&envelope[36..68]);
    let mut ephemeral_public_bytes = [0u8; 32];
    ephemeral_public_bytes.copy_from_slice(&envelope[68..100]);
    let nonce = &envelope[100..124];
    let ciphertext_len = u16::from_be_bytes([envelope[124], envelope[125]]) as usize;

    let expected_len = E2EE_HEADER_LEN + ciphertext_len + E2EE_SIGNATURE_LEN;
    if ciphertext_len < E2EE_AEAD_TAG_LEN || expected_len != envelope.len() {
        return Err(EchoMeshError::CryptoError(
            "malformed E2EE ciphertext length".to_string(),
        ));
    }
    if recipient_peer_id != identity.public_key() {
        return Err(EchoMeshError::CryptoError(
            "E2EE envelope addressed to another peer".to_string(),
        ));
    }
    if let Some(expected_route) = expected_sender_route {
        if peer_route_id(&sender_peer_id) != expected_route {
            return Err(EchoMeshError::CryptoError(
                "relay sender route does not match signed sender identity".to_string(),
            ));
        }
    }

    let signed_len = E2EE_HEADER_LEN + ciphertext_len;
    let signed = &envelope[..signed_len];
    let signature = Signature::from_slice(&envelope[signed_len..])
        .map_err(|_| EchoMeshError::CryptoError("invalid E2EE signature encoding".to_string()))?;
    let sender_key = VerifyingKey::from_bytes(&sender_peer_id)
        .map_err(|_| EchoMeshError::CryptoError("invalid sender identity key".to_string()))?;
    sender_key
        .verify(signed, &signature)
        .map_err(|_| EchoMeshError::CryptoError("E2EE signature verification failed".to_string()))?;

    let local_secret = identity.x25519_secret();
    let ephemeral_public = X25519PublicKey::from(ephemeral_public_bytes);
    let shared = local_secret.diffie_hellman(&ephemeral_public);
    let mut aead_key = derive_aead_key(
        shared.as_bytes(),
        &sender_peer_id,
        &recipient_peer_id,
        &ephemeral_public_bytes,
    )?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&aead_key));
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: &envelope[E2EE_HEADER_LEN..signed_len],
                aad: &envelope[..E2EE_HEADER_LEN],
            },
        )
        .map_err(|_| EchoMeshError::CryptoError("E2EE authentication failed".to_string()))?;
    aead_key.zeroize();

    Ok(DecryptedEnvelope {
        sender_peer_id,
        plaintext,
    })
}

fn derive_aead_key(
    shared_secret: &[u8; 32],
    sender_peer_id: &[u8; 32],
    recipient_peer_id: &[u8; 32],
    ephemeral_public: &[u8; 32],
) -> Result<[u8; 32], EchoMeshError> {
    let hkdf = Hkdf::<Sha256>::new(Some(b"EchoMesh E2EE v1"), shared_secret);
    let mut info = Vec::with_capacity(96);
    info.extend_from_slice(sender_peer_id);
    info.extend_from_slice(recipient_peer_id);
    info.extend_from_slice(ephemeral_public);
    let mut key = [0u8; 32];
    hkdf.expand(&info, &mut key)
        .map_err(|_| EchoMeshError::CryptoError("E2EE key derivation failed".to_string()))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alice_to_bob_round_trip() {
        let alice = ClientIdentity::from_secret([1u8; 32]);
        let bob = ClientIdentity::from_secret([2u8; 32]);
        let encrypted = encrypt_for_peer(&alice, &bob.public_key(), b"hello bob").unwrap();
        let decrypted = decrypt_from_peer(&bob, alice.route_id(), &encrypted).unwrap();
        assert_eq!(decrypted.sender_peer_id, alice.public_key());
        assert_eq!(decrypted.plaintext, b"hello bob");
    }

    #[test]
    fn direct_round_trip_uses_signed_sender_identity() {
        let alice = ClientIdentity::from_secret([1u8; 32]);
        let bob = ClientIdentity::from_secret([2u8; 32]);
        let encrypted = encrypt_for_peer(&alice, &bob.public_key(), b"direct hello").unwrap();
        let decrypted = decrypt_direct(&bob, &encrypted).unwrap();
        assert_eq!(decrypted.sender_peer_id, alice.public_key());
        assert_eq!(decrypted.plaintext, b"direct hello");
    }

    #[test]
    fn rejects_relay_sender_route_substitution() {
        let alice = ClientIdentity::from_secret([1u8; 32]);
        let bob = ClientIdentity::from_secret([2u8; 32]);
        let mallory = ClientIdentity::from_secret([3u8; 32]);
        let encrypted = encrypt_for_peer(&alice, &bob.public_key(), b"secret").unwrap();
        assert!(decrypt_from_peer(&bob, mallory.route_id(), &encrypted).is_err());
    }

    #[test]
    fn rejects_ciphertext_or_signature_tampering() {
        let alice = ClientIdentity::from_secret([1u8; 32]);
        let bob = ClientIdentity::from_secret([2u8; 32]);
        let mut encrypted = encrypt_for_peer(&alice, &bob.public_key(), b"secret").unwrap();
        encrypted[E2EE_HEADER_LEN] ^= 0x01;
        assert!(decrypt_direct(&bob, &encrypted).is_err());
    }

    #[test]
    fn rejects_wrong_recipient() {
        let alice = ClientIdentity::from_secret([1u8; 32]);
        let bob = ClientIdentity::from_secret([2u8; 32]);
        let carol = ClientIdentity::from_secret([4u8; 32]);
        let encrypted = encrypt_for_peer(&alice, &bob.public_key(), b"secret").unwrap();
        assert!(decrypt_direct(&carol, &encrypted).is_err());
    }

    #[test]
    fn enforces_frame_payload_limit() {
        let alice = ClientIdentity::from_secret([1u8; 32]);
        let bob = ClientIdentity::from_secret([2u8; 32]);
        let plaintext = vec![0u8; E2EE_MAX_PLAINTEXT + 1];
        assert!(encrypt_for_peer(&alice, &bob.public_key(), &plaintext).is_err());
    }
}
