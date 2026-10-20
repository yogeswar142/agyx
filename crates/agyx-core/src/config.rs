//! Configuration file management.
//!
//! Non-secret metadata (profile names, active account, last-known subs) is
//! stored in the OS-standard config directory as a JSON file.
//! Secret data never lives here.

use crate::AgyxError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

/// Name of the config file inside the AGYX config directory.
const CONFIG_FILE: &str = "agyx.json";
/// Filename of the exclusive lock used for all mutations.
pub const LOCK_FILE: &str = "agyx.lock";
/// Filename of the encrypted profiles vault.
pub const VAULT_FILE: &str = "agyx_vault.enc";
/// Filename of the encrypted original-credential backup.
pub const BACKUP_FILE: &str = "agyx_original_backup.enc";
/// Filename of the active multi-terminal sessions tracking file.
pub const SESSIONS_FILE: &str = "agyx_sessions.json";

/// Per-profile metadata stored in the config file (no secrets).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileMeta {
    /// Stable Google `sub` identifier for duplicate detection.
    /// Not a security boundary — see `identity` module.
    pub sub: String,
    /// Display email at time of login (informational only).
    pub email: String,
    /// Human-readable display name at time of login.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// When this profile was first added (RFC 3339).
    pub added_at: String,
}

/// The root config file structure.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgyxConfig {
    /// Map from profile name to metadata.
    #[serde(default)]
    pub profiles: BTreeMap<String, ProfileMeta>,

    /// Whether an original (pre-AGYX) backup exists.
    #[serde(default)]
    pub has_original_backup: bool,

    /// The `sub` of the original account that was backed up (if any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_backup_sub: Option<String>,

    /// The email of the original account that was backed up (if any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_backup_email: Option<String>,
}

/// Returns the OS-standard config directory for AGYX.
///
/// - Windows:  `%APPDATA%\agyx\`
/// - macOS:    `~/Library/Application Support/agyx/`
/// - Linux:    `~/.config/agyx/`
pub fn config_dir() -> Result<PathBuf, AgyxError> {
    let base = dirs_base()?;
    let dir = base.join("agyx");
    if !dir.exists() {
        fs::create_dir_all(&dir).map_err(|e| AgyxError::IoError {
            path: dir.display().to_string(),
            source: e,
        })?;
    }
    Ok(dir)
}

/// Returns the path to `agyx.json` within the config directory.
pub fn config_file_path() -> Result<PathBuf, AgyxError> {
    Ok(config_dir()?.join(CONFIG_FILE))
}

/// Returns the path to the lock file.
pub fn lock_file_path() -> Result<PathBuf, AgyxError> {
    Ok(config_dir()?.join(LOCK_FILE))
}

/// Returns the path to the encrypted vault file.
pub fn vault_file_path() -> Result<PathBuf, AgyxError> {
    Ok(config_dir()?.join(VAULT_FILE))
}

/// Returns the path to the encrypted original backup file.
pub fn backup_file_path() -> Result<PathBuf, AgyxError> {
    Ok(config_dir()?.join(BACKUP_FILE))
}

/// Returns the path to the active multi-terminal sessions tracking file.
pub fn sessions_file_path() -> Result<PathBuf, AgyxError> {
    Ok(config_dir()?.join(SESSIONS_FILE))
}

/// Load the config from disk, returning a default if it does not exist.
pub fn load_config() -> Result<AgyxConfig, AgyxError> {
    let path = config_file_path()?;
    if !path.exists() {
        return Ok(AgyxConfig::default());
    }
    let raw = fs::read(&path).map_err(|e| AgyxError::IoError {
        path: path.display().to_string(),
        source: e,
    })?;
    let cfg: AgyxConfig = serde_json::from_slice(&raw)?;
    Ok(cfg)
}

/// Atomically save the config to disk.
///
/// Writes to a temp file beside the destination, then renames — ensuring no
/// partial write is ever visible.
pub fn save_config(cfg: &AgyxConfig) -> Result<(), AgyxError> {
    let path = config_file_path()?;
    let dir = path.parent().expect("config path has parent");
    let json = serde_json::to_vec_pretty(cfg)?;
    atomic_write(dir, &path, &json)
}

/// Atomically write `data` to `dest`, using a sibling temp file + rename.
pub fn atomic_write(
    dir: &std::path::Path,
    dest: &std::path::Path,
    data: &[u8],
) -> Result<(), AgyxError> {
    use std::io::Write;
    let tmp_path = dir.join(format!(
        ".agyx_tmp_{}.tmp",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let mut f = fs::File::create(&tmp_path).map_err(|e| AgyxError::IoError {
        path: tmp_path.display().to_string(),
        source: e,
    })?;
    f.write_all(data).map_err(|e| AgyxError::IoError {
        path: tmp_path.display().to_string(),
        source: e,
    })?;
    f.sync_all().map_err(|e| AgyxError::IoError {
        path: tmp_path.display().to_string(),
        source: e,
    })?;
    drop(f);
    fs::rename(&tmp_path, dest).map_err(|e| AgyxError::IoError {
        path: dest.display().to_string(),
        source: e,
    })?;
    Ok(())
}

/// Resolves the base config directory root (without the `agyx/` suffix).
#[cfg(target_os = "windows")]
fn dirs_base() -> Result<PathBuf, AgyxError> {
    // %APPDATA% = C:\Users\<name>\AppData\Roaming
    std::env::var("APPDATA")
        .map(PathBuf::from)
        .map_err(|_| AgyxError::internal("APPDATA environment variable not set"))
}

#[cfg(target_os = "macos")]
fn dirs_base() -> Result<PathBuf, AgyxError> {
    std::env::var("HOME")
        .map(|h| PathBuf::from(h).join("Library").join("Application Support"))
        .map_err(|_| AgyxError::internal("HOME environment variable not set"))
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn dirs_base() -> Result<PathBuf, AgyxError> {
    // XDG_CONFIG_HOME or ~/.config
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(xdg));
    }
    std::env::var("HOME")
        .map(|h| PathBuf::from(h).join(".config"))
        .map_err(|_| AgyxError::internal("HOME environment variable not set"))
}
