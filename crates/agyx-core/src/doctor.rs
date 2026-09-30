//! Diagnostic health checks for AGYX, AGY, OS credential stores, and configuration.
//!
//! Never prints or exposes secrets.

use crate::{
    adapter::AgyAdapter,
    config::{load_config, lock_file_path, vault_file_path},
    credential_store::{os_keyring::load_or_create_vault_key, vault::CredentialVault},
    identity::extract_identity,
    journal::read_journal,
    lock::AgyxLock,
};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Status of an individual diagnostic check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
}

/// An individual diagnostic check result.
#[derive(Debug, Clone)]
pub struct DoctorCheck {
    pub name: String,
    pub status: CheckStatus,
    pub message: String,
}

/// Overall report returned by [`run_doctor`].
#[derive(Debug, Clone)]
pub struct DoctorReport {
    pub checks: Vec<DoctorCheck>,
    pub overall_status: CheckStatus,
}

/// Run all diagnostic health checks and return the report.
///
/// If `redact` is true, emails are masked (e.g. `u***@example.com`),
/// paths are shortened, and subject IDs are masked for safe bug reporting.
pub fn run_doctor(adapter: &dyn AgyAdapter, redact: bool) -> DoctorReport {
    let mut checks = Vec::new();

    // 1. AGY Executable & Version
    match adapter.detect() {
        Ok(detection) => {
            let path_disp = if redact {
                redact_path(&detection.exe_path)
            } else {
                detection.exe_path.display().to_string()
            };

            if detection.version_matches {
                checks.push(DoctorCheck {
                    name: "AGY Executable".into(),
                    status: CheckStatus::Pass,
                    message: format!("Found AGY {} at {}", detection.version, path_disp),
                });
            } else {
                checks.push(DoctorCheck {
                    name: "AGY Executable".into(),
                    status: CheckStatus::Warn,
                    message: format!(
                        "Found AGY {} at {} (Tested against 1.2.14; newer/older versions may use different credential formats)",
                        detection.version, path_disp
                    ),
                });
            }
        }
        Err(e) => {
            checks.push(DoctorCheck {
                name: "AGY Executable".into(),
                status: CheckStatus::Fail,
                message: format!("AGY executable not found on PATH or known install locations: {e}"),
            });
        }
    }

    // 2. OS Keyring / Credential Manager Access
    match load_or_create_vault_key() {
        Ok(_) => {
            checks.push(DoctorCheck {
                name: "OS Keyring Access".into(),
                status: CheckStatus::Pass,
                message: "Successfully accessed OS Credential Store (target 'agyx:vault-key')".into(),
            });
        }
        Err(e) => {
            checks.push(DoctorCheck {
                name: "OS Keyring Access".into(),
                status: CheckStatus::Fail,
                message: format!("Cannot access OS Credential Store: {e}"),
            });
        }
    }

    // 3. Encrypted Vault Storage (separates user profiles from internal backups)
    let vault_res = CredentialVault::open();
    match &vault_res {
        Ok(vault) => {
            let user_profiles = vault.list_profiles();
            let internal_backups = vault.list_internal_backups();
            let count = user_profiles.len();
            let vault_path = vault_file_path()
                .map(|p| if redact { redact_path(&p) } else { p.display().to_string() })
                .unwrap_or_else(|_| "unknown".into());

            let backup_desc = if internal_backups.is_empty() {
                "no internal backups".to_owned()
            } else {
                format!("internal backup(s): {}", internal_backups.join(", "))
            };

            checks.push(DoctorCheck {
                name: "Vault Storage".into(),
                status: CheckStatus::Pass,
                message: format!(
                    "Vault file intact at {} ({} user profile(s); {})",
                    vault_path, count, backup_desc
                ),
            });
        }
        Err(e) => {
            checks.push(DoctorCheck {
                name: "Vault Storage".into(),
                status: CheckStatus::Fail,
                message: format!("Vault file corrupted or cannot be decrypted: {e}"),
            });
        }
    }

    // 4. Configuration File
    let cfg_res = load_config();
    match &cfg_res {
        Ok(cfg) => {
            let profile_count = cfg.profiles.len();
            let backup_str = if cfg.has_original_backup {
                "pre-AGYX backup recorded"
            } else {
                "no pre-AGYX backup recorded"
            };
            checks.push(DoctorCheck {
                name: "Configuration".into(),
                status: CheckStatus::Pass,
                message: format!("Loaded config with {profile_count} profile(s) ({backup_str})"),
            });
        }
        Err(e) => {
            checks.push(DoctorCheck {
                name: "Configuration".into(),
                status: CheckStatus::Fail,
                message: format!("Failed to read configuration file: {e}"),
            });
        }
    }

    // 5. Vault / Config Synchronization Check (Fix A)
    if let (Ok(vault), Ok(cfg)) = (&vault_res, &cfg_res) {
        let vault_profiles: BTreeSet<String> = vault.list_profiles().into_iter().collect();
        let config_profiles: BTreeSet<String> = cfg.profiles.keys().cloned().collect();

        let in_vault_not_cfg: Vec<_> = vault_profiles.difference(&config_profiles).cloned().collect();
        let in_cfg_not_vault: Vec<_> = config_profiles.difference(&vault_profiles).cloned().collect();
        let backup_in_vault = vault.contains_entry("__original_backup__");
        let backup_in_cfg = cfg.has_original_backup;

        if !in_vault_not_cfg.is_empty() || !in_cfg_not_vault.is_empty() || (backup_in_vault != backup_in_cfg) {
            let mut diffs = Vec::new();
            if !in_vault_not_cfg.is_empty() {
                diffs.push(format!("in vault but missing from config: {:?}", in_vault_not_cfg));
            }
            if !in_cfg_not_vault.is_empty() {
                diffs.push(format!("in config but missing from vault: {:?}", in_cfg_not_vault));
            }
            if backup_in_vault != backup_in_cfg {
                diffs.push(format!(
                    "pre-AGYX backup mismatch: vault={}, config={}",
                    backup_in_vault, backup_in_cfg
                ));
            }
            checks.push(DoctorCheck {
                name: "Vault/Config Sync".into(),
                status: CheckStatus::Warn,
                message: format!("Desync detected: {}", diffs.join("; ")),
            });
        } else {
            checks.push(DoctorCheck {
                name: "Vault/Config Sync".into(),
                status: CheckStatus::Pass,
                message: format!(
                    "In sync ({} user profile(s) match, pre-AGYX backup={})",
                    vault_profiles.len(),
                    backup_in_vault
                ),
            });
        }
    }

    // 6. Crash-Recovery Journal
    match read_journal() {
        Ok(None) => {
            checks.push(DoctorCheck {
                name: "Recovery Journal".into(),
                status: CheckStatus::Pass,
                message: "Clean state (no pending or interrupted recovery journal)".into(),
            });
        }
        Ok(Some(journal)) => {
            checks.push(DoctorCheck {
                name: "Recovery Journal".into(),
                status: CheckStatus::Warn,
                message: format!(
                    "Stale recovery journal detected from {} (action: '{}'). Run any agyx command to auto-restore.",
                    journal.timestamp, journal.action
                ),
            });
        }
        Err(e) => {
            checks.push(DoctorCheck {
                name: "Recovery Journal".into(),
                status: CheckStatus::Fail,
                message: format!("Error reading recovery journal: {e}"),
            });
        }
    }

    // 7. Advisory File Lock
    match lock_file_path() {
        Ok(lock_path) => {
            let test_lock_path = lock_path.with_extension("test_lock");
            match AgyxLock::try_acquire(&test_lock_path) {
                Ok(_l) => {
                    let _ = std::fs::remove_file(&test_lock_path);
                    checks.push(DoctorCheck {
                        name: "File Locking".into(),
                        status: CheckStatus::Pass,
                        message: "Advisory file locking operational".into(),
                    });
                }
                Err(e) => {
                    checks.push(DoctorCheck {
                        name: "File Locking".into(),
                        status: CheckStatus::Fail,
                        message: format!("Advisory lock acquisition failed: {e}"),
                    });
                }
            }
        }
        Err(e) => {
            checks.push(DoctorCheck {
                name: "File Locking".into(),
                status: CheckStatus::Fail,
                message: format!("Failed to resolve lock file path: {e}"),
            });
        }
    }

    // 8. Active AGY Live Credential
    match adapter.read_credential() {
        Ok(Some(raw)) => {
            match extract_identity(&raw) {
                Ok(id) => {
                    let disp_email = if redact {
                        redact_email(&id.email)
                    } else {
                        id.email.clone()
                    };
                    let disp_sub = if redact {
                        redact_sub(&id.sub)
                    } else {
                        truncate_sub(&id.sub)
                    };

                    let cfg = cfg_res.unwrap_or_default();
                    let profile_match = cfg.profiles.iter().find_map(|(name, meta)| {
                        if meta.sub == id.sub {
                            Some(name.clone())
                        } else {
                            None
                        }
                    });

                    match profile_match {
                        Some(pname) => {
                            checks.push(DoctorCheck {
                                name: "Active AGY Credential".into(),
                                status: CheckStatus::Pass,
                                message: format!(
                                    "Active session: email={}, sub={}, profile='{}'",
                                    disp_email, disp_sub, pname
                                ),
                            });
                        }
                        None => {
                            checks.push(DoctorCheck {
                                name: "Active AGY Credential".into(),
                                status: CheckStatus::Warn,
                                message: format!(
                                    "Active session: email={}, sub={}, profile=UNKNOWN. Run `agyx save <name>` to preserve it.",
                                    disp_email, disp_sub
                                ),
                            });
                        }
                    }
                }
                Err(e) => {
                    checks.push(DoctorCheck {
                        name: "Active AGY Credential".into(),
                        status: CheckStatus::Warn,
                        message: format!("Credential present but could not extract identity: {e}"),
                    });
                }
            }
        }
        Ok(None) => {
            checks.push(DoctorCheck {
                name: "Active AGY Credential".into(),
                status: CheckStatus::Warn,
                message: "No credential in OS store (run `agy` to authenticate or `agyx switch <name>`)".into(),
            });
        }
        Err(e) => {
            checks.push(DoctorCheck {
                name: "Active AGY Credential".into(),
                status: CheckStatus::Fail,
                message: format!("Failed to read active AGY credential from OS store: {e}"),
            });
        }
    }

    // 9. PATH Check
    match check_path_install() {
        PathCheckResult::InPath(path) => {
            let path_disp = if redact { redact_path(&path) } else { path.display().to_string() };
            checks.push(DoctorCheck {
                name: "PATH Installation".into(),
                status: CheckStatus::Pass,
                message: format!("agyx binary directory is in PATH ({})", path_disp),
            });
        }
        PathCheckResult::NotInPath(path) => {
            let path_disp = if redact { redact_path(&path) } else { path.display().to_string() };
            checks.push(DoctorCheck {
                name: "PATH Installation".into(),
                status: CheckStatus::Warn,
                message: format!(
                    "Current binary directory ({}) is not in PATH. Run install.ps1 to add it.",
                    path_disp
                ),
            });
        }
        PathCheckResult::Unknown => {
            checks.push(DoctorCheck {
                name: "PATH Installation".into(),
                status: CheckStatus::Warn,
                message: "Could not determine current executable path".into(),
            });
        }
    }

    // Compute overall status
    let mut overall_status = CheckStatus::Pass;
    for c in &checks {
        match c.status {
            CheckStatus::Fail => {
                overall_status = CheckStatus::Fail;
                break;
            }
            CheckStatus::Warn => {
                overall_status = CheckStatus::Warn;
            }
            CheckStatus::Pass => {}
        }
    }

    DoctorReport {
        checks,
        overall_status,
    }
}

/// Helper to truncate sub for display (e.g., "12345678901234567890" -> "12345...7890")
pub fn truncate_sub(sub: &str) -> String {
    if sub.len() <= 10 {
        sub.to_owned()
    } else {
        format!("{}...{}", &sub[..5], &sub[sub.len() - 4..])
    }
}

/// Mask email for bug reports (e.g. "nagukambhampati25@gmail.com" -> "n***@gmail.com")
pub fn redact_email(email: &str) -> String {
    if let Some((user, domain)) = email.split_once('@') {
        let first = user.chars().next().unwrap_or('*');
        format!("{first}***@{domain}")
    } else {
        "***@***".to_owned()
    }
}

/// Mask sub for bug reports (e.g. "1234567890" -> "12***90")
pub fn redact_sub(sub: &str) -> String {
    if sub.len() <= 4 {
        "***".to_owned()
    } else {
        format!("{}***{}", &sub[..2], &sub[sub.len() - 2..])
    }
}

/// Shorten paths to remove username / profile paths (e.g. "...\AppData\Local\agy\bin\agy.exe")
pub fn redact_path(path: &Path) -> String {
    let s = path.to_string_lossy();
    if let Some(idx) = s.to_lowercase().find("appdata") {
        format!("...\\{}", &s[idx..])
    } else if let Some(idx) = s.to_lowercase().find(".gemini") {
        format!("...\\{}", &s[idx..])
    } else if let Some(name) = path.file_name() {
        format!("...\\{}", name.to_string_lossy())
    } else {
        "...".to_owned()
    }
}

enum PathCheckResult {
    InPath(PathBuf),
    NotInPath(PathBuf),
    Unknown,
}

fn check_path_install() -> PathCheckResult {
    let current_exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return PathCheckResult::Unknown,
    };
    let exe_dir = match current_exe.parent() {
        Some(d) => d,
        None => return PathCheckResult::Unknown,
    };

    let path_var = std::env::var("PATH").unwrap_or_default();
    let in_path = std::env::split_paths(&path_var).any(|p| {
        if let (Ok(can1), Ok(can2)) = (p.canonicalize(), exe_dir.canonicalize()) {
            can1 == can2
        } else {
            p == exe_dir
        }
    });

    if in_path {
        PathCheckResult::InPath(exe_dir.to_path_buf())
    } else {
        PathCheckResult::NotInPath(exe_dir.to_path_buf())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::mock::MockAgyAdapter;

    #[test]
    fn doctor_runs_with_mock_adapter() {
        let adapter = MockAgyAdapter::new();
        let report = run_doctor(&adapter, false);
        assert!(!report.checks.is_empty());
        let agy_check = report.checks.iter().find(|c| c.name == "AGY Executable").unwrap();
        assert_eq!(agy_check.status, CheckStatus::Pass);
    }

    #[test]
    fn test_redaction_helpers() {
        assert_eq!(redact_email("testuser@gmail.com"), "t***@gmail.com");
        assert_eq!(redact_sub("1234567890"), "12***90");
        let p = PathBuf::from(r"C:\Users\SecretUser\AppData\Local\agy\bin\agy.exe");
        assert_eq!(redact_path(&p), r"...\AppData\Local\agy\bin\agy.exe");
    }
}
