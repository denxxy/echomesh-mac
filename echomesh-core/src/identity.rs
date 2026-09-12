use std::path::{Path, PathBuf};

use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::EchoMeshError;

pub const IDENTITY_FILE: &str = "identity.key";
const IDENTITY_KEYRING_SERVICE: &str = "com.echomesh.client.identity";

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
        let secret = load_or_generate_secret(storage_dir, &path)?;

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

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn load_or_generate_secret(storage_dir: &Path, legacy_path: &Path) -> Result<[u8; 32], EchoMeshError> {
    use keyring::v1::{Entry, Error as KeyringError};

    // Preserve the old per-storage-directory identity semantics without exposing
    // the directory itself in the credential store. Multiple EchoMesh profiles
    // therefore continue to receive independent identities.
    let profile_hash = Sha256::digest(storage_dir.to_string_lossy().as_bytes());
    let username = format!("identity-{}", hex::encode(profile_hash));
    let entry = Entry::new(IDENTITY_KEYRING_SERVICE, &username)
        .map_err(|e| EchoMeshError::StorageError(format!("open OS identity store: {e}")))?;

    match entry.get_secret() {
        Ok(secret) => {
            let stored = secret_from_slice(&secret, "OS identity store")?;
            if legacy_path.exists() {
                let legacy = std::fs::read(legacy_path)
                    .map_err(|e| EchoMeshError::StorageError(format!("read legacy identity: {e}")))?;
                let legacy_secret = secret_from_slice(&legacy, "legacy identity file")?;
                if legacy_secret != stored {
                    return Err(EchoMeshError::StorageError(
                        "OS identity and legacy identity file disagree; refusing silent identity replacement"
                            .to_string(),
                    ));
                }
                scrub_then_remove_identity_file(legacy_path)?;
            }
            Ok(stored)
        }
        Err(KeyringError::NoEntry) => {
            let secret = if legacy_path.exists() {
                let raw = std::fs::read(legacy_path)
                    .map_err(|e| EchoMeshError::StorageError(format!("read legacy identity: {e}")))?;
                secret_from_slice(&raw, "legacy identity file")?
            } else {
                SigningKey::generate(&mut OsRng).to_bytes()
            };

            entry
                .set_secret(&secret)
                .map_err(|e| EchoMeshError::StorageError(format!("store identity in OS credential store: {e}")))?;
            // Verify the credential before deleting the only existing legacy copy.
            let verified = entry
                .get_secret()
                .map_err(|e| EchoMeshError::StorageError(format!("verify OS identity store: {e}")))?;
            if secret_from_slice(&verified, "OS identity store verification")? != secret {
                return Err(EchoMeshError::StorageError(
                    "OS identity store verification returned different key material".to_string(),
                ));
            }
            if legacy_path.exists() {
                scrub_then_remove_identity_file(legacy_path)?;
            }
            Ok(secret)
        }
        Err(error) => Err(EchoMeshError::StorageError(format!(
            "read identity from OS credential store: {error}"
        ))),
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn load_or_generate_secret(_storage_dir: &Path, path: &Path) -> Result<[u8; 32], EchoMeshError> {
    if path.exists() {
        let raw = std::fs::read(path)
            .map_err(|e| EchoMeshError::StorageError(format!("read identity: {e}")))?;
        secret_from_slice(&raw, "identity key file")
    } else {
        let secret = SigningKey::generate(&mut OsRng).to_bytes();
        write_private_file(path, &secret)?;
        Ok(secret)
    }
}

fn secret_from_slice(raw: &[u8], source: &str) -> Result<[u8; 32], EchoMeshError> {
    if raw.len() != 32 {
        return Err(EchoMeshError::StorageError(format!(
            "{source} has invalid identity key length: expected 32 bytes, got {}",
            raw.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(raw);
    Ok(out)
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn scrub_then_remove_identity_file(path: &Path) -> Result<(), EchoMeshError> {
    use std::io::{Seek, SeekFrom, Write};

    let scrub_result = (|| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new().read(true).write(true).open(path)?;
        let len = file.metadata()?.len();
        file.seek(SeekFrom::Start(0))?;
        let zeros = [0u8; 64];
        let mut remaining = len;
        while remaining > 0 {
            let n = remaining.min(zeros.len() as u64) as usize;
            file.write_all(&zeros[..n])?;
            remaining -= n as u64;
        }
        file.sync_all()?;
        Ok(())
    })();

    std::fs::remove_file(path)
        .map_err(|e| EchoMeshError::StorageError(format!("remove legacy identity file: {e}")))?;
    // On copy-on-write/flash filesystems overwriting historical blocks is not a
    // cryptographic erasure guarantee. Removal is still required, and the new
    // authoritative copy is protected by the platform credential store.
    let _ = scrub_result;
    Ok(())
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

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
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
