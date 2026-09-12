use std::path::{Path, PathBuf};

use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::EchoMeshError;

pub const IDENTITY_FILE: &str = "identity.key";

#[derive(Clone)]
pub struct ClientIdentity {
    secret: [u8; 32],
    public: [u8; 32],
    path: PathBuf,
}

impl std::fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientIdentity")
            .field("public", &hex::encode(self.public))
            .field("secret", &"[REDACTED]")
            .field("path", &self.path)
            .finish()
    }
}

impl Drop for ClientIdentity {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl ClientIdentity {
    pub fn load_or_generate(storage_dir: &Path) -> Result<Self, EchoMeshError> {
        std::fs::create_dir_all(storage_dir)
            .map_err(|e| EchoMeshError::StorageError(format!("identity directory: {e}")))?;
        let path = storage_dir.join(IDENTITY_FILE);

        let secret = if path.exists() {
            let raw = std::fs::read(&path)
                .map_err(|e| EchoMeshError::StorageError(format!("read identity: {e}")))?;
            if raw.len() != 32 {
                return Err(EchoMeshError::StorageError(
                    "identity key file has invalid length".to_string(),
                ));
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(&raw);
            out
        } else {
            let signing = SigningKey::generate(&mut OsRng);
            let secret = signing.to_bytes();
            write_private_file(&path, &secret)?;
            secret
        };

        let signing = SigningKey::from_bytes(&secret);
        let public = signing.verifying_key().to_bytes();
        Ok(Self { secret, public, path })
    }

    pub fn from_secret(secret: [u8; 32]) -> Self {
        let public = SigningKey::from_bytes(&secret).verifying_key().to_bytes();
        Self {
            secret,
            public,
            path: PathBuf::new(),
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }

    pub fn public_key_vec(&self) -> Vec<u8> {
        self.public.to_vec()
    }

    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.secret)
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key().verifying_key()
    }

    pub fn route_id(&self) -> [u8; 16] {
        route_id_from_peer_id(&self.public)
    }

    pub fn x25519_secret(&self) -> StaticSecret {
        ed25519_secret_to_x25519(&self.secret)
    }

    pub fn database_key(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"EchoMesh SQLCipher key v1");
        hasher.update(self.secret);
        hasher.finalize().into()
    }
}

pub fn route_id_from_peer_id(peer_id: &[u8; 32]) -> [u8; 16] {
    let digest = Sha256::digest(peer_id);
    let mut route = [0u8; 16];
    route.copy_from_slice(&digest[..16]);
    route
}

pub fn ed25519_secret_to_x25519(seed: &[u8; 32]) -> StaticSecret {
    let digest = Sha512::digest(seed);
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&digest[..32]);
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    StaticSecret::from(scalar)
}

pub fn ed25519_public_to_x25519(peer_id: &[u8; 32]) -> Result<X25519PublicKey, EchoMeshError> {
    let point = CompressedEdwardsY(*peer_id)
        .decompress()
        .ok_or_else(|| EchoMeshError::CryptoError("invalid Ed25519 public key".to_string()))?;
    if point.is_small_order() {
        return Err(EchoMeshError::CryptoError(
            "small-order public key rejected".to_string(),
        ));
    }
    Ok(X25519PublicKey::from(point.to_montgomery().to_bytes()))
}

fn write_private_file(path: &Path, data: &[u8]) -> Result<(), EchoMeshError> {
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| EchoMeshError::StorageError(format!("create identity: {e}")))?;
        file.write_all(data)
            .map_err(|e| EchoMeshError::StorageError(format!("write identity: {e}")))?;
        file.sync_all()
            .map_err(|e| EchoMeshError::StorageError(format!("sync identity: {e}")))?;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }

    #[cfg(not(unix))]
    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .map_err(|e| EchoMeshError::StorageError(format!("create identity: {e}")))?;
        file.write_all(data)
            .map_err(|e| EchoMeshError::StorageError(format!("write identity: {e}")))?;
        file.sync_all()
            .map_err(|e| EchoMeshError::StorageError(format!("sync identity: {e}")))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_id_is_stable_and_not_raw_peer_prefix() {
        let identity = ClientIdentity::from_secret([7u8; 32]);
        let route = identity.route_id();
        assert_eq!(route, route_id_from_peer_id(&identity.public_key()));
        assert_ne!(&route[..], &identity.public_key()[..16]);
    }

    #[test]
    fn ed25519_conversion_produces_matching_ecdh() {
        let alice = ClientIdentity::from_secret([1u8; 32]);
        let bob = ClientIdentity::from_secret([2u8; 32]);
        let alice_secret = alice.x25519_secret();
        let bob_secret = bob.x25519_secret();
        let alice_public = ed25519_public_to_x25519(&alice.public_key()).unwrap();
        let bob_public = ed25519_public_to_x25519(&bob.public_key()).unwrap();
        assert_eq!(alice_secret.diffie_hellman(&bob_public).as_bytes(), bob_secret.diffie_hellman(&alice_public).as_bytes());
    }
}
