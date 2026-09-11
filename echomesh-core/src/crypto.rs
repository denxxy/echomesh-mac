use crate::EchoMeshError;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;

#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct IdentityKeyPair {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub public_key_hex: String,
    pub public_key_base58: String,
}

pub fn generate_identity_keypair_impl() -> Result<IdentityKeyPair, EchoMeshError> {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    let priv_bytes = signing_key.to_bytes();
    let pub_bytes = verifying_key.to_bytes();

    Ok(IdentityKeyPair {
        private_key: priv_bytes.to_vec(),
        public_key: pub_bytes.to_vec(),
        public_key_hex: hex::encode(pub_bytes),
        public_key_base58: bs58::encode(pub_bytes).into_string(),
    })
}

pub fn derive_public_key_impl(private_key: Vec<u8>) -> Result<IdentityKeyPair, EchoMeshError> {
    if private_key.len() != 32 {
        return Err(EchoMeshError::InvalidKeyLength {
            expected: 32,
            actual: private_key.len() as u32,
        });
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&private_key);

    let signing_key = SigningKey::from_bytes(&key_bytes);
    let verifying_key = signing_key.verifying_key();
    let pub_bytes = verifying_key.to_bytes();

    Ok(IdentityKeyPair {
        private_key,
        public_key: pub_bytes.to_vec(),
        public_key_hex: hex::encode(pub_bytes),
        public_key_base58: bs58::encode(pub_bytes).into_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_and_derive() {
        let pair = generate_identity_keypair_impl().expect("keygen failed");
        assert_eq!(pair.private_key.len(), 32);
        assert_eq!(pair.public_key.len(), 32);
        assert_eq!(pair.public_key_hex.len(), 64);
        assert!(!pair.public_key_base58.is_empty());

        let derived = derive_public_key_impl(pair.private_key.clone()).expect("derive failed");
        assert_eq!(pair.public_key, derived.public_key);
        assert_eq!(pair.public_key_hex, derived.public_key_hex);
        assert_eq!(pair.public_key_base58, derived.public_key_base58);
    }
}
