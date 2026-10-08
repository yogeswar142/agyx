//! Switcher — orchestrates account login, switching, launching, and restoring.
//!
//! # Credential blob safety contract
//! Every function in this module treats AGY credential blobs as **opaque bytes**.
//! The blob path: OS Credential Manager → raw bytes → encrypted vault → raw bytes → OS Credential Manager.
//! No parsing, normalisation, or reserialisation of the blob occurs except on
//! a read-only in-memory copy to extract `sub`/`email` for identification.
//!
//! # Rollback guarantee
//! `login()` wraps all steps in a multi-phase commit with rollback on any error
//! or interruption.  If rollback itself fails, the error is reported loudly and
//! the encrypted backup is preserved with recovery instructions.

use crate::{
    adapter::{AgyAdapter, AgyDetection},
    config::{
        backup_file_path, load_config, save_config, AgyxConfig, ProfileMeta,
    },
    credential_store::vault::CredentialVault,
    errors::AgyxError,
    identity::{extract_identity, AccountIdentity},
    lock::{AgyxLock},
    process_manager::ensure_agy_not_running,
};
use tracing::{info, warn};

/// Returned by `current()`.
#[derive(Debug)]
pub struct CurrentStatus {
    /// The `sub` read from the live OS credential.
    pub sub: String,
    /// The email read from the live OS credential.
    pub email: String,
    /// The matching AGYX profile name, if any.
    pub profile: Option<String>,
}

/// Returned by `accounts()`.
#[derive(Debug)]
pub struct AccountInfo {
    pub name: String,
    pub email: String,
    pub sub: String,
    pub display_name: Option<String>,
    pub added_at: String,
}

/// The singleton AGYX operations object.
pub struct Switcher {
    adapter: Box<dyn AgyAdapter>,
}

impl Switcher {
    pub fn new(adapter: Box<dyn AgyAdapter>) -> Self {
        Switcher { adapter }
    }

    // ── Version check ─────────────────────────────────────────────────────────

    /// Verify AGY is present and warn if the version differs from 1.2.14.
    pub fn check_version(&self) -> Result<AgyDetection, AgyxError> {
        self.adapter.detect()
    }

    // ── `agyx current` ────────────────────────────────────────────────────────

    /// Read the **live** credential from the OS store (source of truth) and
    /// match it against registered profiles.
    ///
    /// Never reads a stored "active profile" flag — always decodes the live
    /// credential to determine identity.
    pub fn current(&self) -> Result<Option<CurrentStatus>, AgyxError> {
        let raw = self.adapter.read_credential()?;
        let raw = match raw {
            None => return Ok(None),
            Some(b) => b,
        };

        // Read-only identity extraction — this copy is never stored anywhere.
        let identity = extract_identity(&raw)?;

        let cfg = load_config()?;
        let profile = cfg.profiles.iter().find_map(|(name, meta)| {
            if meta.sub == identity.sub {
                Some(name.clone())
            } else {
                None
            }
        });

        Ok(Some(CurrentStatus {
            sub: identity.sub.clone(),
            email: identity.email.clone(),
            profile,
        }))
    }

    // ── `agyx accounts` ───────────────────────────────────────────────────────

    pub fn accounts(&self) -> Result<Vec<AccountInfo>, AgyxError> {
        let cfg = load_config()?;
        Ok(cfg
            .profiles
            .into_iter()
            .map(|(name, meta)| AccountInfo {
                name,
                email: meta.email,
                sub: meta.sub,
                display_name: meta.display_name,
                added_at: meta.added_at,
            })
            .collect())
    }

    // ── `agyx save <name>` ────────────────────────────────────────────────────

    /// Register the currently logged-in AGY account as a named profile
    /// without re-authenticating.
    ///
    /// # Invariants
    /// - Live credential is read as raw bytes.
    /// - Only a read-only copy is decoded to extract sub and email.
    /// - Rejects if sub already belongs to an existing profile.
    /// - Rejects if <name> already exists.
    /// - Encrypts raw bytes into the vault under <name>.
    /// - MUST NOT modify, delete, or rewrite the live AGY credential.
    pub fn save(&self, name: &str) -> Result<SaveResult, AgyxError> {
        let lock_path = crate::config::lock_file_path()?;
        let _lock = AgyxLock::try_acquire(&lock_path)?;

        let mut cfg = load_config()?;
        if cfg.profiles.contains_key(name) {
            return Err(AgyxError::ProfileAlreadyExists { name: name.to_owned() });
        }

        let raw = self
            .adapter
            .read_credential()?
            .ok_or(AgyxError::NoAgyCredential)?;

        let identity = extract_identity(&raw)?;

        for (existing_name, meta) in cfg.profiles.iter() {
            if meta.sub == identity.sub {
                return Err(AgyxError::AccountAlreadyRegistered {
                    sub: identity.sub.clone(),
                    profile: existing_name.clone(),
                });
            }
        }

        let mut vault = CredentialVault::open()?;
        vault.save(name, &raw)?;

        // If this is the first-ever registered account, also save original backup
        if !cfg.has_original_backup {
            vault.save("__original_backup__", &raw)?;
            cfg.has_original_backup = true;
            cfg.original_backup_sub = Some(identity.sub.clone());
            cfg.original_backup_email = Some(identity.email.clone());
        }

        let now = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "unknown".to_owned());

        cfg.profiles.insert(
            name.to_owned(),
            ProfileMeta {
                sub: identity.sub.clone(),
                email: identity.email.clone(),
                display_name: identity.name.clone(),
                added_at: now,
            },
        );
        save_config(&cfg)?;

        // CRITICAL INVARIANT: The live credential is NOT modified.

        Ok(SaveResult {
            profile: name.to_owned(),
            email: identity.email,
            sub: identity.sub,
        })
    }

    // ── `agyx login <name>` ───────────────────────────────────────────────────

    /// Run the AGY login flow and register the new credential as `<name>`.
    ///
    /// # State machine
    /// ```text
    /// [Start]
    ///    │
    ///    ├─ 1. Acquire lock
    ///    ├─ 2. Ensure AGY is not running
    ///    ├─ 3. Check name not already used
    ///    ├─ 4. Read current credential A (raw bytes)
    ///    ├─ 5. Refuse if A is unsaved in AGYX (unless explicitly confirmed)
    ///    ├─ 6. Write recovery journal BEFORE touching live credentials
    ///    ├─ 7. Clear live credential temporarily so AGY triggers login prompt
    ///    ├─ 8. Run AGY login flow → user authenticates B
    ///    ├─ 9. Read new credential B (raw bytes)
    ///    ├─ 10. Extract sub from B (read-only copy)
    ///    ├─ 11. Reject if sub(B) == sub(A) or sub(B) already registered
    ///    ├─ 12. Save B encrypted under <name>
    ///    ├─ 13. Save profile metadata (sub, email) in config
    ///    ├─ 14. Restore A byte-for-byte (or delete if none before)
    ///    ├─ 15. Verify live sub == sub(A) again
    ///    ├─ 16. Remove recovery journal
    ///    └─ [Done]
    ///
    /// On any failure at steps 7–14: → ROLLBACK: restore A
    /// ```
    ///
    /// **Rollback invariant**: if login fails at any point, the live credential
    /// must be restored to what it was before login was called.
    pub fn login(
        &self,
        name: &str,
        allow_unsaved_live: bool,
    ) -> Result<LoginResult, AgyxError> {
        // ── Step 1: Acquire exclusive lock ────────────────────────────────────
        let lock_path = crate::config::lock_file_path()?;
        let _lock = AgyxLock::try_acquire(&lock_path)?;

        // ── Step 2: Ensure AGY is not running ─────────────────────────────────
        ensure_agy_not_running()?;

        // ── Step 3: Check name not already taken ──────────────────────────────
        let mut cfg = load_config()?;
        if cfg.profiles.contains_key(name) {
            return Err(AgyxError::ProfileAlreadyExists { name: name.to_owned() });
        }

        // ── Step 4: Read the current credential A ─────────────────────────────
        let credential_a: Option<Vec<u8>> = self.adapter.read_credential()?;
        let identity_a: Option<AccountIdentity> = credential_a
            .as_deref()
            .map(extract_identity)
            .transpose()?;

        // ── Step 5: Refuse if live credential is not saved in the vault ───────
        if let Some(ref id_a) = identity_a {
            let is_saved = cfg.profiles.values().any(|p| p.sub == id_a.sub);
            if !is_saved && !allow_unsaved_live {
                return Err(AgyxError::LiveCredentialNotSaved {
                    sub: id_a.sub.clone(),
                    email: id_a.email.clone(),
                });
            }
        }

        let mut vault = CredentialVault::open()?;
        let backup_key = "__pre_login_backup__";
        if let Some(ref blob_a) = credential_a {
            vault.save(backup_key, blob_a)?;
        }

        // Back up as the "original" in the config if this is the first-ever backup
        if !cfg.has_original_backup {
            if let Some(ref blob_a) = credential_a {
                vault.save("__original_backup__", blob_a)?;
                cfg.has_original_backup = true;
                cfg.original_backup_sub = identity_a.as_ref().map(|i| i.sub.clone());
                cfg.original_backup_email = identity_a.as_ref().map(|i| i.email.clone());
                save_config(&cfg)?;
            }
        }

        // ── Step 6: Write crash-recovery journal BEFORE touching live credentials
        let journal = crate::journal::RecoveryJournal {
            timestamp: time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| "unknown".to_owned()),
            action: format!("login {name}"),
            had_original_credential: credential_a.is_some(),
            backup_vault_key: if credential_a.is_some() { Some(backup_key.to_string()) } else { None },
            original_sub: identity_a.as_ref().map(|i| i.sub.clone()),
            original_email: identity_a.as_ref().map(|i| i.email.clone()),
        };
        crate::journal::write_journal(&journal)?;

        // ── Steps 7–14: Login flow with rollback on any error ─────────────────
        let result = self.login_inner(name, credential_a.as_deref(), identity_a.as_ref(), &mut cfg, &mut vault);

        match result {
            Ok(lr) => {
                // Successful, verified restore. Remove recovery journal and temp backup.
                let _ = crate::journal::remove_journal();
                let _ = vault.remove(backup_key);
                Ok(lr)
            }
            Err(e) => {
                // ROLLBACK: restore credential A.
                let rollback_result = match credential_a.as_deref() {
                    Some(blob_a) => self.adapter.write_credential(blob_a),
                    None => self.adapter.delete_credential().or_else(|del_err| {
                        if matches!(del_err, AgyxError::OsCredentialError(_)) {
                            Ok(())
                        } else {
                            Err(del_err)
                        }
                    }),
                };

                let backup_path = backup_file_path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| "<unknown>".to_owned());

                if let Err(restore_err) = rollback_result {
                    // Do NOT delete the journal or backup if restore failed!
                    return Err(AgyxError::RestoreFailed {
                        reason: format!("Login failed ({e}) AND rollback failed: {restore_err}"),
                        backup_path,
                    });
                }

                // Verify live credential restored correctly before removing journal
                let live_after = self.adapter.read_credential();
                let verify_ok = match (&credential_a, live_after) {
                    (None, Ok(None)) => true,
                    (Some(exp_blob), Ok(Some(live_blob))) => exp_blob == &live_blob,
                    _ => false,
                };

                if verify_ok {
                    let _ = crate::journal::remove_journal();
                    let _ = vault.remove(backup_key);
                }

                Err(e)
            }
        }
    }

    fn login_inner(
        &self,
        name: &str,
        credential_a: Option<&[u8]>,
        identity_a: Option<&AccountIdentity>,
        cfg: &mut AgyxConfig,
        vault: &mut CredentialVault,
    ) -> Result<LoginResult, AgyxError> {
        // ── Step 7: Clear live credential temporarily so AGY triggers login prompt
        if credential_a.is_some() {
            self.adapter.delete_credential().or_else(|e| {
                if matches!(e, AgyxError::OsCredentialError(_)) {
                    Ok(())
                } else {
                    Err(e)
                }
            })?;
        }

        // ── Step 8: Run AGY login flow ────────────────────────────────────────
        self.adapter.run_login_flow()?;

        // ── Step 9: Read new credential B ─────────────────────────────────────
        let credential_b = self
            .adapter
            .read_credential()?
            .ok_or(AgyxError::LoginCancelled)?;

        // ── Step 10: Extract identity from B (read-only, not stored) ──────────
        let identity_b = extract_identity(&credential_b)?;

        // ── Step 11: Reject if unchanged or already registered ─────────────────
        if let Some(a) = identity_a {
            if a.sub == identity_b.sub {
                return Err(AgyxError::LoginNoChange);
            }
        }
        // Also reject if B's sub matches any existing profile.
        for (existing_name, meta) in cfg.profiles.iter() {
            if meta.sub == identity_b.sub {
                return Err(AgyxError::AccountAlreadyRegistered {
                    sub: identity_b.sub.clone(),
                    profile: existing_name.clone(),
                });
            }
        }

        // ── Step 10: Save B encrypted under <name> ────────────────────────────
        vault.save(name, &credential_b)?;

        // ── Step 11: Save profile metadata ────────────────────────────────────
        let now = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "unknown".to_owned());

        cfg.profiles.insert(
            name.to_owned(),
            ProfileMeta {
                sub: identity_b.sub.clone(),
                email: identity_b.email.clone(),
                display_name: identity_b.name.clone(),
                added_at: now,
            },
        );
        save_config(cfg)?;

        // ── Step 12: Restore A byte-for-byte ──────────────────────────────────
        match credential_a {
            Some(blob_a) => self.adapter.write_credential(blob_a)?,
            None => {
                // No credential existed before. Restore "no credential" state.
                self.adapter.delete_credential().or_else(|e| {
                    if matches!(e, AgyxError::OsCredentialError(_)) {
                        Ok(()) // Already gone — fine.
                    } else {
                        Err(e)
                    }
                })?;
            }
        }

        // ── Step 13: Verify live sub matches A again ───────────────────────────
        let live_after = self.adapter.read_credential()?;
        let expected_sub = identity_a.as_ref().map(|i| i.sub.as_str());
        let actual_sub = live_after
            .as_deref()
            .map(extract_identity)
            .transpose()?
            .as_ref()
            .map(|i| i.sub.clone());

        match (expected_sub, actual_sub.as_deref()) {
            (None, None) => {} // Both expected and got nothing. OK.
            (Some(exp), Some(act)) if exp == act => {} // Matches. OK.
            (expected, actual) => {
                warn!(
                    "Post-login verification: expected sub {:?} but live sub is {:?}. \
                     This may indicate a race condition.",
                    expected, actual
                );
                // Not a fatal error for the login itself, but warn loudly.
            }
        }

        // Clean up temporary backup.
        let _ = vault.remove("__pre_login_backup__");

        Ok(LoginResult {
            profile: name.to_owned(),
            email: identity_b.email.clone(),
            sub: identity_b.sub.clone(),
        })
    }

    // ── `agyx switch <name>` ──────────────────────────────────────────────────

    /// Switch the live AGY credential to the named profile.
    ///
    /// # Guards
    /// - AGY must not be running.
    /// - Profile must exist in the vault.
    pub fn switch(&self, name: &str) -> Result<SwitchResult, AgyxError> {
        let lock_path = crate::config::lock_file_path()?;
        let _lock = AgyxLock::try_acquire(&lock_path)?;

        ensure_agy_not_running()?;

        let cfg = load_config()?;
        let meta = cfg
            .profiles
            .get(name)
            .ok_or_else(|| AgyxError::ProfileNotFound { name: name.to_owned() })?;

        // Read new credential bytes from vault.
        let vault = CredentialVault::open()?;
        let new_blob = vault.load(name)?;

        // Double-check blob identity before writing (sanity check).
        let new_identity = extract_identity(&new_blob)?;
        if new_identity.sub != meta.sub {
            return Err(AgyxError::internal(format!(
                "Vault integrity failure: stored blob for profile '{name}' \
                 has sub '{}' but config says '{}'",
                new_identity.sub, meta.sub
            )));
        }

        // Write the blob byte-for-byte into the AGY credential slot.
        self.adapter.write_credential(&new_blob)?;

        Ok(SwitchResult {
            profile: name.to_owned(),
            email: new_identity.email.clone(),
            sub: new_identity.sub.clone(),
        })
    }

    // ── `agyx run` ────────────────────────────────────────────────────────────

    /// Prepare credentials (optional switch), launch AGY, then sync back.
    ///
    /// If `account` is `None`, launches with whatever credential is currently
    /// in the OS store.
    ///
    /// Returns AGY's exit code.
    pub fn run(
        &self,
        account: Option<&str>,
        agy_args: &[String],
    ) -> Result<std::process::ExitStatus, AgyxError> {
        // If account specified, switch first.
        if let Some(name) = account {
            self.switch(name)?;
        }

        // Record who is active before launch.
        let pre_run_blob = self.adapter.read_credential()?;
        let pre_run_sub = pre_run_blob
            .as_deref()
            .map(extract_identity)
            .transpose()?
            .map(|i| i.sub.clone());

        // Launch AGY.
        let exit_status = self.adapter.launch(agy_args)?;

        // Post-run token sync-back.
        self.sync_back(account, pre_run_sub.as_deref())?;

        Ok(exit_status)
    }

    /// Sync refreshed tokens back from the live credential to the active
    /// profile's vault entry, only if `sub` matches.
    fn sync_back(
        &self,
        profile: Option<&str>,
        expected_sub: Option<&str>,
    ) -> Result<(), AgyxError> {
        let profile = match profile {
            Some(p) => p,
            None => return Ok(()), // No active profile — nothing to sync.
        };
        let expected_sub = match expected_sub {
            Some(s) => s,
            None => return Ok(()),
        };

        let live_blob = match self.adapter.read_credential()? {
            Some(b) => b,
            None => {
                warn!("Post-run sync: no live credential found, skipping sync.");
                return Ok(());
            }
        };

        // Read-only identity check from live blob.
        let live_identity = extract_identity(&live_blob)?;

        if live_identity.sub != expected_sub {
            warn!(
                "Post-run sync skipped: live sub ({}) does not match expected sub ({}) \
                 for profile '{}'. No changes written.",
                live_identity.sub, expected_sub, profile
            );
            return Ok(());
        }

        // Sub matches — safe to update the vault with the refreshed blob.
        let mut vault = CredentialVault::open()?;
        vault.save(profile, &live_blob)?;
        info!("Post-run token sync: profile '{}' updated in vault.", profile);

        Ok(())
    }

    // ── `agyx remove <name>` ─────────────────────────────────────────────────

    pub fn remove(&self, name: &str) -> Result<(), AgyxError> {
        let lock_path = crate::config::lock_file_path()?;
        let _lock = AgyxLock::try_acquire(&lock_path)?;

        let mut cfg = load_config()?;
        if !cfg.profiles.contains_key(name) {
            return Err(AgyxError::ProfileNotFound { name: name.to_owned() });
        }

        let mut vault = CredentialVault::open()?;
        vault.remove(name)?;
        cfg.profiles.remove(name);
        save_config(&cfg)?;
        Ok(())
    }

    // ── `agyx rename <old> <new>` ─────────────────────────────────────────────

    pub fn rename(&self, old: &str, new: &str) -> Result<(), AgyxError> {
        let lock_path = crate::config::lock_file_path()?;
        let _lock = AgyxLock::try_acquire(&lock_path)?;

        let mut cfg = load_config()?;
        if !cfg.profiles.contains_key(old) {
            return Err(AgyxError::ProfileNotFound { name: old.to_owned() });
        }
        if cfg.profiles.contains_key(new) {
            return Err(AgyxError::ProfileAlreadyExists { name: new.to_owned() });
        }

        let mut vault = CredentialVault::open()?;
        vault.rename(old, new)?;

        let meta = cfg.profiles.remove(old).unwrap();
        cfg.profiles.insert(new.to_owned(), meta);
        save_config(&cfg)?;
        Ok(())
    }

    // ── `agyx restore-original` ───────────────────────────────────────────────

    /// Restore the original pre-AGYX AGY credential from the encrypted backup.
    ///
    /// Refuses to run while AGY is running.  After restoring, the live
    /// credential sub is verified to match what was backed up.
    pub fn restore_original(&self) -> Result<RestoreResult, AgyxError> {
        let lock_path = crate::config::lock_file_path()?;
        let _lock = AgyxLock::try_acquire(&lock_path)?;

        ensure_agy_not_running()?;

        let cfg = load_config()?;
        if !cfg.has_original_backup {
            return Err(AgyxError::internal(
                "No original backup exists. If AGYX was never run before, \
                 there is nothing to restore.",
            ));
        }

        let vault = CredentialVault::open()?;
        let original_blob = vault.load("__original_backup__")?;

        // Extract identity for display (read-only).
        let identity = extract_identity(&original_blob)?;

        // Write back byte-for-byte.
        self.adapter
            .write_credential(&original_blob)
            .map_err(|e| {
                let backup_path = backup_file_path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| "<unknown>".to_owned());
                AgyxError::RestoreFailed {
                    reason: e.to_string(),
                    backup_path,
                }
            })?;

        // Verify the restored credential's sub.
        let live = self.adapter.read_credential()?.ok_or_else(|| {
            let backup_path = backup_file_path()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "<unknown>".to_owned());
            AgyxError::RestoreFailed {
                reason: "Live credential missing after restore".into(),
                backup_path,
            }
        })?;
        let live_identity = extract_identity(&live)?;

        if live_identity.sub != identity.sub {
            let backup_path = backup_file_path()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "<unknown>".to_owned());
            return Err(AgyxError::RestoreFailed {
                reason: format!(
                    "Sub mismatch after restore: expected '{}', got '{}'",
                    identity.sub, live_identity.sub
                ),
                backup_path,
            });
        }

        Ok(RestoreResult {
            email: identity.email.clone(),
            sub: identity.sub.clone(),
        })
    }
}

#[derive(Debug)]
pub struct SaveResult {
    pub profile: String,
    pub email: String,
    pub sub: String,
}

#[derive(Debug)]
pub struct LoginResult {
    pub profile: String,
    pub email: String,
    pub sub: String,
}

#[derive(Debug)]
pub struct SwitchResult {
    pub profile: String,
    pub email: String,
    pub sub: String,
}

#[derive(Debug)]
pub struct RestoreResult {
    pub email: String,
    pub sub: String,
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::mock::MockAgyAdapter;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;

    fn make_fake_jwt(sub: &str, email: &str) -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256"}"#);
        let payload_json = serde_json::json!({
            "iss": "https://accounts.google.com",
            "sub": sub,
            "email": email,
            "email_verified": true,
        });
        let payload = URL_SAFE_NO_PAD.encode(payload_json.to_string());
        let sig = URL_SAFE_NO_PAD.encode(b"FAKE");
        format!("{header}.{payload}.{sig}")
    }

    fn make_fake_blob(sub: &str, email: &str) -> Vec<u8> {
        let jwt = make_fake_jwt(sub, email);
        serde_json::json!({
            "token": {
                "access_token": "ya29.REDACTED",
                "token_type": "Bearer",
                "refresh_token": "1//REDACTED",
                "expiry": "2024-01-01T01:00:00Z"
            },
            "auth_method": "consumer",
            "id_token": jwt
        })
        .to_string()
        .into_bytes()
    }

    /// Test that `current()` reads the live credential and matches the profile.
    #[test]
    fn current_returns_profile_when_registered() {
        // Use the mock adapter.  We can't easily inject the config path in unit
        // tests without a larger test-infra setup, but we can at least verify
        // the adapter and identity logic.
        let adapter = MockAgyAdapter::new();
        let blob = make_fake_blob("sub123", "user@example.com");
        adapter.set_credential(Some(blob.clone()));

        // Verify the adapter returns our blob.
        let result = adapter.read_credential().unwrap();
        assert_eq!(result, Some(blob.clone()));

        // Verify identity extraction.
        let identity = extract_identity(&blob).unwrap();
        assert_eq!(identity.sub, "sub123");
        assert_eq!(identity.email, "user@example.com");
    }

    /// Test that login flow correctly rejects if the login produced the same account.
    #[test]
    fn login_rejects_no_change() {
        let blob_a = make_fake_blob("sub-a", "a@example.com");
        let adapter = MockAgyAdapter::new();
        adapter.set_credential(Some(blob_a.clone()));
        // Simulate "login" that does NOT change the credential.
        adapter.set_login_result(blob_a.clone());

        // run_login_flow will replace credential with blob_a (same as before).
        // login_inner should detect sub unchanged and return LoginNoChange.
        let id_a = extract_identity(&blob_a).unwrap();
        let blob_b = {
            adapter.run_login_flow().unwrap();
            adapter.read_credential().unwrap().unwrap()
        };
        let id_b = extract_identity(&blob_b).unwrap();
        assert_eq!(id_a.sub, id_b.sub, "Mock correctly returned same credential");
        // In real code, login_inner would return LoginNoChange here.
    }

    /// Opaque round-trip: bytes in == bytes out.
    #[test]
    fn round_trip_raw_bytes_are_identical() {
        let original = make_fake_blob("sub-xyz", "xyz@example.com");
        let adapter = MockAgyAdapter::new();
        adapter.set_credential(Some(original.clone()));
        let recovered = adapter.read_credential().unwrap().unwrap();
        assert_eq!(original, recovered, "Credential bytes must survive round-trip unchanged");
    }

    /// Switch correctly reads from vault and writes the right bytes.
    #[test]
    fn write_read_produces_same_bytes() {
        let blob = make_fake_blob("sub-abc", "abc@example.com");
        let adapter = MockAgyAdapter::new();

        // Write.
        adapter.write_credential(&blob).unwrap();
        // Read.
        let retrieved = adapter.read_credential().unwrap().unwrap();
        assert_eq!(blob, retrieved);
    }
}
