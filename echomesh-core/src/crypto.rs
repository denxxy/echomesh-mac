use crate::EchoMeshError;
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct IdentityKeyPair {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub public_key_hex: String,
    pub public_key_base58: String,
}

pub fn generate_identity_keypair_impl() -> Result<IdentityKeyPair, EchoMeshError> {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    let private_key = secret.to_bytes().to_vec();
    let public_key = public.as_bytes().to_vec();
    Ok(IdentityKeyPair {
        private_key,
        public_key: public_key.clone(),
        public_key_hex: hex::encode(&public_key),
        public_key_base58: bs58::encode(&public_key).into_string(),
    })
}

pub fn derive_public_key_impl(private_key: Vec<u8>) -> Result<IdentityKeyPair, EchoMeshError> {
    if private_key.len() != 32 {
        return Err(EchoMeshError::InvalidKeyLength { expected: 32, actual: private_key.len() as u32 });
    }
    let bytes: [u8; 32] = private_key.as_slice().try_into().unwrap();
    let secret = StaticSecret::from(bytes);
    let public = PublicKey::from(&secret);
    let public_key = public.as_bytes().to_vec();
    Ok(IdentityKeyPair {
        private_key,
        public_key: public_key.clone(),
        public_key_hex: hex::encode(&public_key),
        public_key_base58: bs58::encode(&public_key).into_string(),
    })
}

pub fn load_or_generate_identity(path: &std::path::Path) -> Result<IdentityKeyPair, EchoMeshError> {
    if path.exists() {
        let bytes = std::fs::read(path).map_err(|e| EchoMeshError::CryptoError(format!("identity read failed: {}", e)))?;
        return derive_public_key_impl(bytes);
    }
    let pair = generate_identity_keypair_impl()?;
    if let Some(parent) = path.parent() { std::fs::create_dir_all(parent).map_err(|e| EchoMeshError::CryptoError(e.to_string()))?; }
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = OpenOptions::new().create_new(true).write(true).mode(0o600).open(path)
            .map_err(|e| EchoMeshError::CryptoError(format!("identity create failed: {}", e)))?;
        f.write_all(&pair.private_key).map_err(|e| EchoMeshError::CryptoError(e.to_string()))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, &pair.private_key).map_err(|e| EchoMeshError::CryptoError(e.to_string()))?;
    }
    Ok(pair)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_keygen_and_derive() {
        let pair = generate_identity_keypair_impl().expect("keygen failed");
        assert_eq!(pair.private_key.len(), 32);
        assert_eq!(pair.public_key.len(), 32);
        let derived = derive_public_key_impl(pair.private_key.clone()).expect("derive failed");
        assert_eq!(pair.public_key, derived.public_key);
    }
}
