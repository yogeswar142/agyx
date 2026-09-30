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
use std::path::PathBuf;

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
pub fn run_doctor(adapter: &dyn AgyAdapter) -> DoctorReport {
    let mut checks = Vec::new();

    // 1. AGY Executable & Version
    match adapter.detect() {
        Ok(detection) => {
            if detection.version_matches {
                checks.push(DoctorCheck {
                    name: "AGY Executable".into(),
                    status: CheckStatus::Pass,
                    message: format!(
                        "Found AGY {} at {}",
                        detection.version,
                        detection.exe_path.display()
                    ),
                });
            } else {
                checks.push(DoctorCheck {
                    name: "AGY Executable".into(),
                    status: CheckStatus::Warn,
                    message: format!(
                        "Found AGY {} at {} (Tested against 1.2.14; newer/older versions may use different credential formats)",
                        detection.version,
                        detection.exe_path.display()
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

    // 3. Encrypted Vault Storage
    match CredentialVault::open() {
        Ok(vault) => {
            let count = vault.list_profiles().len();
            let vault_path = vault_file_path()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "unknown".into());
            checks.push(DoctorCheck {
                name: "Vault Storage".into(),
                status: CheckStatus::Pass,
                message: format!("Vault file intact at {vault_path} ({count} profile(s) stored)"),
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
    match load_config() {
        Ok(cfg) => {
            let profile_count = cfg.profiles.len();
            let backup_str = if cfg.has_original_backup {
                "pre-AGYX backup present"
            } else {
                "no pre-AGYX backup yet"
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

    // 5. Crash-Recovery Journal
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

    // 6. Advisory File Lock
    match lock_file_path() {
        Ok(lock_path) => {
            // Test lock acquisition
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

    // 7. Active AGY Live Credential
    match adapter.read_credential() {
        Ok(Some(raw)) => {
            match extract_identity(&raw) {
                Ok(id) => {
                    // Truncate sub for safe display (e.g. 11050...7585)
                    let trunc_sub = truncate_sub(&id.sub);
                    let cfg = load_config().unwrap_or_default();
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
                                    id.email, trunc_sub, pname
                                ),
                            });
                        }
                        None => {
                            checks.push(DoctorCheck {
                                name: "Active AGY Credential".into(),
                                status: CheckStatus::Warn,
                                message: format!(
                                    "Active session: email={}, sub={}, profile=UNKNOWN. Run `agyx save <name>` to preserve it.",
                                    id.email, trunc_sub
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

    // 8. PATH Check
    match check_path_install() {
        PathCheckResult::InPath(path) => {
            checks.push(DoctorCheck {
                name: "PATH Installation".into(),
                status: CheckStatus::Pass,
                message: format!("agyx binary directory is in PATH ({})", path.display()),
            });
        }
        PathCheckResult::NotInPath(path) => {
            checks.push(DoctorCheck {
                name: "PATH Installation".into(),
                status: CheckStatus::Warn,
                message: format!(
                    "Current binary directory ({}) is not in PATH. Run install.ps1 to add it.",
                    path.display()
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

/// Helper to truncate sub for privacy / safety (e.g., "12345678901234567890" -> "12345...7890")
fn truncate_sub(sub: &str) -> String {
    if sub.len() <= 10 {
        sub.to_owned()
    } else {
        format!("{}...{}", &sub[..5], &sub[sub.len() - 4..])
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
        let report = run_doctor(&adapter);
        assert!(!report.checks.is_empty());
        // Verify no check panicked and AGY Executable passed with 1.2.14
        let agy_check = report.checks.iter().find(|c| c.name == "AGY Executable").unwrap();
        assert_eq!(agy_check.status, CheckStatus::Pass);
    }

    #[test]
    fn truncate_sub_works() {
        assert_eq!(truncate_sub("123456789012"), "12345...9012");
        assert_eq!(truncate_sub("short"), "short");
    }
}
