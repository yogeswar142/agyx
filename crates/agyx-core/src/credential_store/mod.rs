//! CredentialStore trait + encrypted vault for AGYX profile data.
//!
//! # Threat model
//! - Credential blobs are treated as **opaque bytes** end-to-end.
//! - Each profile's blob is encrypted with AES-256-GCM using a unique
//!   random 12-byte nonce.
//! - The vault master key is stored in the OS credential store
//!   (Windows Credential Manager / macOS Keychain / Linux Secret Service).
//! - On Windows, the raw key bytes are further protected at rest by
//!   CryptProtectData (DPAPI) when stored in Credential Manager.
//! - If the OS keyring is unavailable (e.g., headless Linux), a
//!   passphrase-derived key (Argon2id + AEAD) is used with a clear warning.
//! - Vault data on disk: `agyx_vault.enc` — a JSON envelope containing
//!   per-profile AES-GCM ciphertexts.
//! - Vault key in OS store: target `agyx:vault-key`, 32 random bytes,
//!   base64url-encoded.

pub mod os_keyring;
pub mod vault;

pub use vault::CredentialVault;

/// Capability required by the Switcher/AccountManager — opaque blob storage.
pub trait CredentialStore: Send + Sync {
    /// Save an encrypted profile blob. Idempotent (overwrites on re-save).
    fn save(&mut self, profile: &str, blob: &[u8]) -> Result<(), crate::AgyxError>;

    /// Load the raw encrypted blob for a profile.
    fn load(&self, profile: &str) -> Result<Vec<u8>, crate::AgyxError>;

    /// Delete a profile.
    fn remove(&mut self, profile: &str) -> Result<(), crate::AgyxError>;

    /// List all stored profile names.
    fn list_profiles(&self) -> Result<Vec<String>, crate::AgyxError>;

    /// Rename a profile.  The underlying encrypted blob is moved atomically.
    fn rename(&mut self, old: &str, new: &str) -> Result<(), crate::AgyxError>;
}
