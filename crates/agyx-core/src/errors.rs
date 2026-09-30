//! Error types for agyx-core.

use thiserror::Error;

/// Every public error returned by agyx-core.
#[derive(Debug, Error)]
pub enum AgyxError {
    // ─── AGY adapter ────────────────────────────────────────────────────────
    /// The installed `agy` binary was not found on PATH or at a known location.
    #[error("AGY executable not found. Install AGY first.")]
    AgyNotFound,

    /// The `agy --version` output did not match the expected supported version.
    /// AGYX has only been tested against 1.2.14 on Windows ARM64.
    #[error("AGY version mismatch: expected {expected}, found {found}. AGYX may not work correctly with this version.")]
    AgyVersionMismatch { expected: String, found: String },

    /// `agy.exe` (or platform equivalent) is already running.
    #[error("AGY is already running (PIDs: {pids:?}). Stop AGY before switching accounts.")]
    AgyRunning { pids: Vec<u32> },

    // ─── Credential manager ─────────────────────────────────────────────────
    /// AGY has no credential currently stored in the OS credential store.
    #[error("No AGY credential found in the OS credential store.")]
    NoAgyCredential,

    /// The OS credential store returned an error.
    #[error("OS credential store error: {0}")]
    OsCredentialError(String),

    /// The credential blob exceeded the OS size limit (Windows Credential Manager
    /// caps generic credentials at 2,560 bytes).
    #[error("Credential blob size {size} bytes exceeds the OS limit of {limit} bytes. Cannot store this profile safely.")]
    BlobTooLarge { size: usize, limit: usize },

    // ─── Profile / account management ───────────────────────────────────────
    /// A profile with the given name already exists.
    #[error("A profile named '{name}' already exists. Use `agyx remove {name}` first or choose a different name.")]
    ProfileAlreadyExists { name: String },

    /// No profile with the given name exists.
    #[error("No profile named '{name}' found. Use `agyx accounts` to list profiles.")]
    ProfileNotFound { name: String },

    /// The Google `sub` from the new credential already belongs to an existing profile.
    #[error("The authenticated account (sub: {sub}) is already registered as profile '{profile}'. Did you log in to the same account twice?")]
    AccountAlreadyRegistered { sub: String, profile: String },

    /// The login flow did not change the credential (login did not complete).
    #[error("The AGY credential was not changed after login. The login flow may not have completed successfully.")]
    LoginNoChange,

    /// The live credential is not saved in the vault, and starting login could overwrite it.
    #[error("The currently active AGY account (email: {email}, sub: {sub}) is not saved in AGYX.\nRun `agyx save <name>` first to preserve it, or confirm to proceed.")]
    LiveCredentialNotSaved { sub: String, email: String },

    // ─── File / lock ────────────────────────────────────────────────────────
    /// Another agyx process holds the global lock.
    #[error("Another agyx operation is running. Please wait and retry.")]
    LockContended,

    /// A required directory could not be created or accessed.
    #[error("I/O error accessing '{path}': {source}")]
    IoError {
        path: String,
        #[source]
        source: std::io::Error,
    },

    // ─── Encryption / crypto ────────────────────────────────────────────────
    /// AEAD encryption failed.
    #[error("Encryption error: {0}")]
    EncryptionError(String),

    /// AEAD decryption failed (wrong key, corrupted data, or tampered blob).
    #[error("Decryption failed. The stored data may be corrupted or encrypted with a different master key.")]
    DecryptionError,

    // ─── Restore / safety ───────────────────────────────────────────────────
    /// A restore-original operation failed. Critical: manual recovery may be needed.
    #[error("CRITICAL: Failed to restore the original AGY credential: {reason}\n\nThe encrypted backup is kept at: {backup_path}\nRun to recover:\n  agyx restore-original")]
    RestoreFailed { reason: String, backup_path: String },

    // ─── Sync-back ──────────────────────────────────────────────────────────
    /// After AGY exited, the live credential `sub` does not match the active profile.
    /// The sync-back is skipped to avoid corrupting a different account's credential.
    #[error("Post-run sync skipped: live credential sub ({live_sub}) does not match active profile '{profile}' sub ({profile_sub}). No changes written.")]
    SyncSubMismatch {
        live_sub: String,
        profile: String,
        profile_sub: String,
    },

    // ─── Internal / other ───────────────────────────────────────────────────
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl AgyxError {
    pub fn internal(msg: impl Into<String>) -> Self {
        AgyxError::Internal(msg.into())
    }
}
