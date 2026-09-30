//! Crash-recovery journal for AGYX.
//!
//! Before AGYX modifies or clears the live AGY credential during a multi-step
//! operation (e.g. `login`), it writes a journal record to disk.
//! The journal record is removed ONLY after the original credential has been
//! safely restored and verified.
//!
//! If the process is hard-killed (e.g. `taskkill /F`, power loss, kernel panic),
//! the next invocation of ANY `agyx` command detects the stale journal,
//! restores the original credential byte-for-byte, reports what happened, and
//! removes the journal.

use crate::{
    adapter::AgyAdapter,
    config::{atomic_write, config_dir},
    credential_store::vault::CredentialVault,
    errors::AgyxError,
    identity::extract_identity,
    lock::AgyxLock,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use tracing::{info, warn};

pub const JOURNAL_FILE: &str = "agyx_journal.json";

/// The journal record persisted to disk before touching live credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryJournal {
    /// Timestamp of when the operation started (RFC 3339).
    pub timestamp: String,
    /// Operation name (e.g. "login").
    pub action: String,
    /// Whether an original credential existed in the OS store before the operation.
    pub had_original_credential: bool,
    /// The vault key where the raw original credential was saved encrypted.
    pub backup_vault_key: Option<String>,
    /// Expected Google `sub` of the original credential.
    pub original_sub: Option<String>,
    /// Expected email of the original credential (for user messaging).
    pub original_email: Option<String>,
}

/// Report returned when a crash recovery was performed.
#[derive(Debug, Clone)]
pub struct RecoveryReport {
    pub original_action: String,
    pub original_email: Option<String>,
    pub original_sub: Option<String>,
    pub timestamp: String,
}

pub fn journal_file_path() -> Result<PathBuf, AgyxError> {
    Ok(config_dir()?.join(JOURNAL_FILE))
}

/// Atomically write a new journal record to disk.
pub fn write_journal(journal: &RecoveryJournal) -> Result<(), AgyxError> {
    let path = journal_file_path()?;
    let dir = path.parent().expect("journal path has parent");
    let json = serde_json::to_vec_pretty(journal)?;
    atomic_write(dir, &path, &json)
}

/// Read the active journal record if one exists.
pub fn read_journal() -> Result<Option<RecoveryJournal>, AgyxError> {
    let path = journal_file_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read(&path).map_err(|e| AgyxError::IoError {
        path: path.display().to_string(),
        source: e,
    })?;
    let j: RecoveryJournal = serde_json::from_slice(&raw)?;
    Ok(Some(j))
}

/// Remove the journal record after a successful, verified restore.
pub fn remove_journal() -> Result<(), AgyxError> {
    let path = journal_file_path()?;
    if path.exists() {
        fs::remove_file(&path).map_err(|e| AgyxError::IoError {
            path: path.display().to_string(),
            source: e,
        })?;
    }
    Ok(())
}

/// Check for a crash recovery journal and perform automatic recovery if needed.
///
/// This function is called at startup by `agyx` before any command is executed.
pub fn check_and_recover_journal(
    adapter: &dyn AgyAdapter,
) -> Result<Option<RecoveryReport>, AgyxError> {
    let journal = match read_journal()? {
        Some(j) => j,
        None => return Ok(None),
    };

    warn!(
        "CRITICAL: Found interrupted session journal from {} (action: '{}'). Performing automatic recovery.",
        journal.timestamp, journal.action
    );

    // Acquire lock to avoid racing with another recovery attempt
    let lock_path = crate::config::lock_file_path()?;
    let _lock = AgyxLock::try_acquire(&lock_path)?;

    if journal.had_original_credential {
        let vault_key = journal.backup_vault_key.as_deref().unwrap_or("__pre_login_backup__");
        let vault = CredentialVault::open()?;
        let original_blob = vault.load(vault_key).map_err(|e| {
            AgyxError::RestoreFailed {
                reason: format!("Failed to load backup from vault during crash recovery: {e}"),
                backup_path: format!("vault key: {vault_key}"),
            }
        })?;

        // Write original blob back byte-for-byte
        adapter.write_credential(&original_blob).map_err(|e| {
            AgyxError::RestoreFailed {
                reason: format!("Failed to write credential during crash recovery: {e}"),
                backup_path: format!("vault key: {vault_key}"),
            }
        })?;

        // Verify sub matches
        let live = adapter.read_credential()?.ok_or_else(|| {
            AgyxError::RestoreFailed {
                reason: "Live credential missing after crash recovery restore".into(),
                backup_path: format!("vault key: {vault_key}"),
            }
        })?;
        let live_id = extract_identity(&live)?;
        if let Some(ref exp_sub) = journal.original_sub {
            if live_id.sub != *exp_sub {
                return Err(AgyxError::RestoreFailed {
                    reason: format!(
                        "Sub mismatch after crash recovery: expected '{}', got '{}'",
                        exp_sub, live_id.sub
                    ),
                    backup_path: format!("vault key: {vault_key}"),
                });
            }
        }
    } else {
        // No credential existed prior to interrupted operation — delete live credential
        adapter.delete_credential().or_else(|e| {
            if matches!(e, AgyxError::OsCredentialError(_)) {
                Ok(())
            } else {
                Err(e)
            }
        })?;
    }

    // Verified restore complete. Remove journal.
    remove_journal()?;

    info!("Crash recovery completed successfully.");
    Ok(Some(RecoveryReport {
        original_action: journal.action,
        original_email: journal.original_email,
        original_sub: journal.original_sub,
        timestamp: journal.timestamp,
    }))
}
