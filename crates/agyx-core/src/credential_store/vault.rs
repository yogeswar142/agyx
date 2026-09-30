//! Encrypted vault: per-profile AES-256-GCM ciphertexts stored in a JSON
//! envelope on disk, keyed by a master key held in the OS credential store.
//!
//! # Blob size strategy
//! Windows Credential Manager limits generic credential blobs to 2,560 bytes.
//! The AGYX vault key (32 random bytes base64url-encoded = 43 chars) is tiny
//! and fits comfortably.  Per-profile credential blobs (~1,690 bytes raw from
//! AGY on this machine) are stored in the on-disk vault file as AES-GCM
//! ciphertexts, which grow by 12 bytes (nonce) + 16 bytes (tag) = 28 bytes
//! overhead.  They never touch the OS size-limited credential slot.
//!
//! # Vault file format
//! ```json
//! {
//!   "v": 1,
//!   "entries": {
//!     "<profile_name>": "<base64url(nonce || ciphertext)>"
//!   }
//! }
//! ```

use crate::{
    config::{atomic_write, vault_file_path},
    credential_store::os_keyring::load_or_create_vault_key,
    AgyxError,
};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Version tag written into the vault file.
const VAULT_VERSION: u32 = 1;
/// AES-256-GCM nonce length.
const NONCE_LEN: usize = 12;

#[derive(Serialize, Deserialize)]
struct VaultFile {
    v: u32,
    /// Profile name → base64url(nonce || ciphertext)
    entries: BTreeMap<String, String>,
}

/// The AGYX encrypted credential vault.
///
/// Loaded once from disk; all mutations are atomically flushed back to disk.
pub struct CredentialVault {
    key: [u8; 32],
    file: VaultFile,
}

impl CredentialVault {
    /// Load the vault from disk, creating a new empty vault if none exists.
    /// The master key is loaded from / created in the OS credential store.
    pub fn open() -> Result<Self, AgyxError> {
        let key = load_or_create_vault_key()?;
        let path = vault_file_path()?;
        let file = if path.exists() {
            let raw = std::fs::read(&path).map_err(|e| AgyxError::IoError {
                path: path.display().to_string(),
                source: e,
            })?;
            serde_json::from_slice(&raw)?
        } else {
            VaultFile {
                v: VAULT_VERSION,
                entries: BTreeMap::new(),
            }
        };
        if file.v != VAULT_VERSION {
            return Err(AgyxError::internal(format!(
                "Vault file version {} is not supported (expected {VAULT_VERSION}). \
                 Please upgrade agyx.",
                file.v
            )));
        }
        Ok(CredentialVault { key, file })
    }

    /// Encrypt `plaintext` and store it under `profile`.
    pub fn save(&mut self, profile: &str, plaintext: &[u8]) -> Result<(), AgyxError> {
        let ciphertext = self.encrypt(plaintext)?;
        self.file
            .entries
            .insert(profile.to_owned(), URL_SAFE_NO_PAD.encode(&ciphertext));
        self.flush()
    }

    /// Decrypt and return the stored blob for `profile`.
    pub fn load(&self, profile: &str) -> Result<Vec<u8>, AgyxError> {
        let b64 = self
            .file
            .entries
            .get(profile)
            .ok_or_else(|| AgyxError::ProfileNotFound {
                name: profile.to_owned(),
            })?;
        let ciphertext = URL_SAFE_NO_PAD.decode(b64).map_err(|_| {
            AgyxError::DecryptionError
        })?;
        self.decrypt(&ciphertext)
    }

    /// Remove a profile from the vault.
    pub fn remove(&mut self, profile: &str) -> Result<(), AgyxError> {
        if self.file.entries.remove(profile).is_none() {
            return Err(AgyxError::ProfileNotFound {
                name: profile.to_owned(),
            });
        }
        self.flush()
    }

    /// List all user profile names in the vault (excluding internal keys starting with `__`).
    pub fn list_profiles(&self) -> Vec<String> {
        self.file
            .entries
            .keys()
            .filter(|k| !k.starts_with("__"))
            .cloned()
            .collect()
    }

    /// List internal backup keys in the vault (keys starting with `__`).
    pub fn list_internal_backups(&self) -> Vec<String> {
        self.file
            .entries
            .keys()
            .filter(|k| k.starts_with("__"))
            .cloned()
            .collect()
    }

    /// Check if the vault contains an entry (including internal backup keys).
    pub fn contains_entry(&self, key: &str) -> bool {
        self.file.entries.contains_key(key)
    }

    /// Rename a profile entry.
    pub fn rename(&mut self, old: &str, new: &str) -> Result<(), AgyxError> {
        if !self.file.entries.contains_key(old) {
            return Err(AgyxError::ProfileNotFound {
                name: old.to_owned(),
            });
        }
        if self.file.entries.contains_key(new) {
            return Err(AgyxError::ProfileAlreadyExists {
                name: new.to_owned(),
            });
        }
        let val = self.file.entries.remove(old).unwrap();
        self.file.entries.insert(new.to_owned(), val);
        self.flush()
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    /// AES-256-GCM encrypt. Returns `nonce || ciphertext`.
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, AgyxError> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| AgyxError::EncryptionError("AES-GCM encrypt failed".into()))?;
        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// AES-256-GCM decrypt from `nonce || ciphertext` format.
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, AgyxError> {
        if data.len() < NONCE_LEN + 16 {
            return Err(AgyxError::DecryptionError);
        }
        let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
        let nonce = Nonce::from_slice(nonce_bytes);
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| AgyxError::DecryptionError)
    }

    /// Atomically write the vault file to disk.
    fn flush(&self) -> Result<(), AgyxError> {
        let path = vault_file_path()?;
        let dir = path.parent().expect("vault path has parent");
        let json = serde_json::to_vec_pretty(&self.file)?;
        atomic_write(dir, &path, &json)
    }
}

impl crate::credential_store::CredentialStore for CredentialVault {
    fn save(&mut self, profile: &str, blob: &[u8]) -> Result<(), AgyxError> {
        CredentialVault::save(self, profile, blob)
    }

    fn load(&self, profile: &str) -> Result<Vec<u8>, AgyxError> {
        CredentialVault::load(self, profile)
    }

    fn remove(&mut self, profile: &str) -> Result<(), AgyxError> {
        CredentialVault::remove(self, profile)
    }

    fn list_profiles(&self) -> Result<Vec<String>, AgyxError> {
        Ok(CredentialVault::list_profiles(self))
    }

    fn rename(&mut self, old: &str, new: &str) -> Result<(), AgyxError> {
        CredentialVault::rename(self, old, new)
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::Path;

    /// A standalone vault that uses a known 32-byte key and a temp directory,
    /// not the OS keyring — for unit testing.
    struct TestVault {
        key: [u8; 32],
        file: VaultFile,
        _path: std::path::PathBuf,
    }

    impl TestVault {
        fn new(dir: &Path) -> Self {
            let mut key = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut key);
            let path = dir.join("vault.enc");
            TestVault {
                key,
                file: VaultFile {
                    v: VAULT_VERSION,
                    entries: BTreeMap::new(),
                },
                _path: path,
            }
        }

        fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
            let mut nonce_bytes = [0u8; NONCE_LEN];
            rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes);
            let ct = cipher.encrypt(nonce, plaintext).unwrap();
            let mut out = Vec::new();
            out.extend_from_slice(&nonce_bytes);
            out.extend_from_slice(&ct);
            out
        }

        fn decrypt(&self, data: &[u8]) -> Vec<u8> {
            let (nonce_bytes, ct) = data.split_at(NONCE_LEN);
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
            let nonce = Nonce::from_slice(nonce_bytes);
            cipher.decrypt(nonce, ct).unwrap()
        }

        fn save_entry(&mut self, profile: &str, plaintext: &[u8]) {
            let ct = self.encrypt(plaintext);
            self.file
                .entries
                .insert(profile.to_owned(), URL_SAFE_NO_PAD.encode(&ct));
        }

        fn load_entry(&self, profile: &str) -> Vec<u8> {
            let b64 = self.file.entries.get(profile).unwrap();
            let ct = URL_SAFE_NO_PAD.decode(b64).unwrap();
            self.decrypt(&ct)
        }
    }

    #[test]
    fn round_trip_preserves_exact_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault = TestVault::new(dir.path());
        let original: Vec<u8> = (0u8..=255).cycle().take(1690).collect();
        vault.save_entry("personal", &original);
        let restored = vault.load_entry("personal");
        assert_eq!(original, restored, "round-trip must produce bit-identical bytes");
    }

    #[test]
    fn different_profiles_are_independent() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault = TestVault::new(dir.path());
        let blob_a: Vec<u8> = vec![0x41u8; 100]; // 'A' * 100
        let blob_b: Vec<u8> = vec![0x42u8; 100]; // 'B' * 100
        vault.save_entry("alice", &blob_a);
        vault.save_entry("bob", &blob_b);
        assert_eq!(vault.load_entry("alice"), blob_a);
        assert_eq!(vault.load_entry("bob"), blob_b);
    }

    #[test]
    fn tampered_ciphertext_fails_decryption() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault = TestVault::new(dir.path());
        let original = b"sensitive credential blob".to_vec();
        vault.save_entry("personal", &original);

        // Tamper: flip one byte in the stored ciphertext
        let b64 = vault.file.entries.get("personal").unwrap().clone();
        let mut ct = URL_SAFE_NO_PAD.decode(&b64).unwrap();
        ct[NONCE_LEN + 5] ^= 0xff;
        vault
            .file
            .entries
            .insert("personal".to_owned(), URL_SAFE_NO_PAD.encode(&ct));

        // Decryption must fail (AES-GCM authentication tag check)
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&vault.key));
        let (nonce_bytes, ciphertext_bytes) = ct.split_at(NONCE_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);
        assert!(
            cipher.decrypt(nonce, ciphertext_bytes).is_err(),
            "tampered ciphertext must not decrypt"
        );
    }

    #[test]
    fn max_windows_credential_size_fits_agt_blob() {
        // AGY's observed blob is ~1690 bytes on this machine.
        // Encrypted overhead is NONCE_LEN(12) + GCM_TAG(16) = 28 bytes.
        // Base64url adds ~33% overhead.
        // Total is stored in the AGYX vault file on disk (not in Credential Manager),
        // so the 2560-byte Windows limit does NOT apply here.
        // This test just documents that the AGY blob easily fits.
        let observed_blob_size = 1690usize;
        let encrypted_size = observed_blob_size + NONCE_LEN + 16; // +GCM tag
        assert!(
            encrypted_size < 2560,
            "encrypted AGY blob ({encrypted_size} bytes) exceeds Windows CM limit (2560)"
        );
        // If it does exceed the limit, we'd need a different architecture.
        // The vault key itself in CM is only ~43 bytes — well within limits.
    }
}
