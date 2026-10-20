//! `AgyAdapter` — the **only** place with AGY-specific knowledge.
//!
//! # Interface stability guarantee
//! If AGY changes behaviour, add a new `AgyAdapterV2` (or a version enum)
//! without modifying the rest of agyx-core.  All AGY-specific assumptions
//! (binary name, credential target name, version string) are constants here.
//!
//! # Undocumented interfaces
//! The credential target `gemini:antigravity` in Windows Credential Manager is
//! an **undocumented interface** — it was discovered by binary inspection of
//! `agy.exe` v1.2.14 and confirmed by reading the Windows Credential Manager.
//! It is the only known stable way to identify and manipulate AGY's credential
//! on Windows.  It is isolated here behind this trait so the rest of the code
//! is shielded from any future changes.
//!
//! **Verified against**: AGY 1.2.14 on Windows ARM64 (`aarch64-pc-windows-msvc`).
//! **Not verified on**: macOS, Linux, or any other AGY version.

use crate::AgyxError;

/// The AGY versions this implementation has been validated against.
pub const SUPPORTED_AGY_VERSIONS: &[&str] = &["1.2.14", "1.3.2", "1.4.3"];

/// The latest AGY version this implementation has been validated against.
pub const SUPPORTED_AGY_VERSION: &str = "1.4.3";

/// Check if a given AGY version string matches any verified version.
pub fn is_supported_version(version: &str) -> bool {
    SUPPORTED_AGY_VERSIONS.contains(&version)
}

/// The Windows Credential Manager target for AGY's credential.
///
/// **UNDOCUMENTED INTERFACE** — discovered by binary inspection.
pub const AGY_CREDENTIAL_TARGET: &str = "gemini:antigravity";

/// Abstraction over the installed AGY binary.
///
/// The real implementation calls the actual `agy.exe`.
/// Tests inject a mock that never touches the OS.
pub trait AgyAdapter: Send + Sync {
    /// Find the AGY executable path and return its reported version string.
    fn detect(&self) -> Result<AgyDetection, AgyxError>;

    /// Read the raw credential blob currently stored by AGY in the OS store.
    ///
    /// Returns `None` if no credential exists (not yet logged in).
    /// Blob is treated as opaque bytes — not interpreted.
    fn read_credential(&self) -> Result<Option<Vec<u8>>, AgyxError>;

    /// Write raw bytes into AGY's credential slot in the OS store.
    ///
    /// The blob is written byte-for-byte without modification.
    fn write_credential(&self, blob: &[u8]) -> Result<(), AgyxError>;

    /// Delete AGY's credential entry from the OS store.
    /// Used to restore the state when the user had no credential before login.
    fn delete_credential(&self) -> Result<(), AgyxError>;

    /// Launch AGY with the given arguments, passing through stdin/stdout/stderr.
    ///
    /// Returns the exit code.  Signal handling and stdio passthrough are done
    /// in the caller (CLI layer) since they require platform-specific OS APIs.
    fn launch(&self, args: &[String]) -> Result<std::process::ExitStatus, AgyxError>;

    /// Open AGY's interactive login flow and wait for it to complete.
    ///
    /// This runs `agy` with no arguments in the user's terminal, allowing
    /// the normal Google OAuth2 browser-based login to proceed.  This method
    /// blocks until AGY exits, then returns.
    fn run_login_flow(&self) -> Result<(), AgyxError>;
}

/// Result of [`AgyAdapter::detect`].
#[derive(Debug, Clone)]
pub struct AgyDetection {
    /// Path to the AGY executable.
    pub exe_path: std::path::PathBuf,
    /// Version string reported by `agy --version`.
    pub version: String,
    /// `true` if the version exactly matches `SUPPORTED_AGY_VERSION`.
    pub version_matches: bool,
}

// ─── Real adapter ────────────────────────────────────────────────────────────

/// The production `AgyAdapter` that calls the real `agy` binary.
pub struct RealAgyAdapter {
    /// Resolved path to the AGY executable (set at construction time).
    exe_path: std::path::PathBuf,
}

impl RealAgyAdapter {
    /// Locate the AGY executable and construct the adapter.
    ///
    /// Looks in `%LOCALAPPDATA%\agy\bin\agy.exe` first (known install path),
    /// then falls back to PATH.
    pub fn new() -> Result<Self, AgyxError> {
        let exe_path = locate_agy_exe()?;
        Ok(RealAgyAdapter { exe_path })
    }
}

impl AgyAdapter for RealAgyAdapter {
    fn detect(&self) -> Result<AgyDetection, AgyxError> {
        let output = std::process::Command::new(&self.exe_path)
            .arg("--version")
            .output()
            .map_err(|e| AgyxError::internal(format!("Failed to run agy --version: {e}")))?;

        let version = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        let version_matches = is_supported_version(&version);

        if !version_matches {
            tracing::warn!(
                "AGY version mismatch: expected one of {:?}, found '{version}'. \
                 AGYX may not work correctly.",
                SUPPORTED_AGY_VERSIONS
            );
        }

        Ok(AgyDetection {
            exe_path: self.exe_path.clone(),
            version,
            version_matches,
        })
    }

    fn read_credential(&self) -> Result<Option<Vec<u8>>, AgyxError> {
        #[cfg(target_os = "windows")]
        {
            crate::credential_store::os_keyring::agt::read_raw()
        }
        #[cfg(not(target_os = "windows"))]
        {
            Err(AgyxError::internal(
                "read_credential not yet implemented on this platform",
            ))
        }
    }

    fn write_credential(&self, blob: &[u8]) -> Result<(), AgyxError> {
        #[cfg(target_os = "windows")]
        {
            crate::credential_store::os_keyring::agt::write_raw(blob)
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = blob;
            Err(AgyxError::internal(
                "write_credential not yet implemented on this platform",
            ))
        }
    }

    fn delete_credential(&self) -> Result<(), AgyxError> {
        #[cfg(target_os = "windows")]
        {
            crate::credential_store::os_keyring::agt::delete()
        }
        #[cfg(not(target_os = "windows"))]
        {
            Err(AgyxError::internal(
                "delete_credential not yet implemented on this platform",
            ))
        }
    }

    fn launch(&self, args: &[String]) -> Result<std::process::ExitStatus, AgyxError> {
        let profile_name = self.read_credential().ok().flatten().and_then(|blob| {
            crate::identity::extract_identity(&blob).ok().and_then(|id| {
                crate::config::load_config().ok().and_then(|cfg| {
                    cfg.profiles.into_iter().find(|(_, meta)| meta.sub == id.sub).map(|(name, _)| name)
                })
            })
        });

        let mut child = std::process::Command::new(&self.exe_path)
            .args(args)
            .spawn()
            .map_err(|e| AgyxError::internal(format!("Failed to launch agy: {e}")))?;

        let pid = child.id();
        let _ = crate::sessions::record_session(pid, profile_name.as_deref().unwrap_or("active"));

        let status = child
            .wait()
            .map_err(|e| AgyxError::internal(format!("Failed waiting for agy process: {e}")))?;

        let _ = crate::sessions::remove_session(pid);

        Ok(status)
    }

    fn run_login_flow(&self) -> Result<(), AgyxError> {
        // Run agy with no args — triggers the interactive TUI / login prompt.
        let status = std::process::Command::new(&self.exe_path)
            .status()
            .map_err(|e| AgyxError::internal(format!("Failed to run agy login flow: {e}")))?;

        if !status.success() {
            return Err(AgyxError::internal(format!(
                "AGY login flow exited with status: {status}"
            )));
        }
        Ok(())
    }
}

/// Locate the AGY executable.  Returns an error if not found.
fn locate_agy_exe() -> Result<std::path::PathBuf, AgyxError> {
    // 1. Known Windows install path.
    #[cfg(target_os = "windows")]
    {
        let local_appdata = std::env::var("LOCALAPPDATA").unwrap_or_default();
        let known_path =
            std::path::PathBuf::from(local_appdata).join("agy").join("bin").join("agy.exe");
        if known_path.exists() {
            return Ok(known_path);
        }
    }

    // 2. PATH fallback.
    which_agy()
}

fn which_agy() -> Result<std::path::PathBuf, AgyxError> {
    #[cfg(target_os = "windows")]
    let name = "agy.exe";
    #[cfg(not(target_os = "windows"))]
    let name = "agy";

    std::env::split_paths(&std::env::var("PATH").unwrap_or_default())
        .map(|p| p.join(name))
        .find(|p| p.exists())
        .ok_or(AgyxError::AgyNotFound)
}

// ─── Mock adapter for testing ────────────────────────────────────────────────

/// A mock `AgyAdapter` for unit tests.  Does not touch the OS credential store
/// or the real AGY binary.
#[cfg(any(test, feature = "mock-adapter"))]
pub mod mock {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    pub struct MockAgyAdapter {
        pub credential: Arc<Mutex<Option<Vec<u8>>>>,
        pub version: String,
        pub login_changes_credential_to: Arc<Mutex<Option<Vec<u8>>>>,
        pub login_error: Arc<Mutex<Option<String>>>,
        pub write_error: Arc<Mutex<Option<String>>>,
        pub launch_exit_code: i32,
    }

    impl MockAgyAdapter {
        pub fn new() -> Self {
            MockAgyAdapter {
                version: SUPPORTED_AGY_VERSION.to_owned(),
                launch_exit_code: 0,
                ..Default::default()
            }
        }

        /// Pre-populate the "OS credential store" with a blob.
        pub fn set_credential(&self, blob: Option<Vec<u8>>) {
            *self.credential.lock().unwrap() = blob;
        }

        /// Configure what credential the mock "login flow" will produce.
        pub fn set_login_result(&self, blob: Vec<u8>) {
            *self.login_changes_credential_to.lock().unwrap() = Some(blob);
        }

        /// Configure a simulated error during login.
        pub fn set_login_error(&self, err: String) {
            *self.login_error.lock().unwrap() = Some(err);
        }

        /// Configure a simulated error during write_credential.
        pub fn set_write_error(&self, err: String) {
            *self.write_error.lock().unwrap() = Some(err);
        }
    }

    impl AgyAdapter for MockAgyAdapter {
        fn detect(&self) -> Result<AgyDetection, AgyxError> {
            let version_matches = is_supported_version(&self.version);
            Ok(AgyDetection {
                exe_path: std::path::PathBuf::from("/mock/agy"),
                version: self.version.clone(),
                version_matches,
            })
        }

        fn read_credential(&self) -> Result<Option<Vec<u8>>, AgyxError> {
            Ok(self.credential.lock().unwrap().clone())
        }

        fn write_credential(&self, blob: &[u8]) -> Result<(), AgyxError> {
            if let Some(ref err) = *self.write_error.lock().unwrap() {
                return Err(AgyxError::OsCredentialError(err.clone()));
            }
            *self.credential.lock().unwrap() = Some(blob.to_vec());
            Ok(())
        }

        fn delete_credential(&self) -> Result<(), AgyxError> {
            *self.credential.lock().unwrap() = None;
            Ok(())
        }

        fn launch(&self, _args: &[String]) -> Result<std::process::ExitStatus, AgyxError> {
            // Return a fake "success" exit status.
            #[cfg(target_os = "windows")]
            {
                use std::os::windows::process::ExitStatusExt;
                Ok(std::process::ExitStatus::from_raw(self.launch_exit_code as u32))
            }
            #[cfg(not(target_os = "windows"))]
            {
                use std::os::unix::process::ExitStatusExt;
                Ok(std::process::ExitStatus::from_raw(self.launch_exit_code))
            }
        }

        fn run_login_flow(&self) -> Result<(), AgyxError> {
            if let Some(ref err) = *self.login_error.lock().unwrap() {
                return Err(AgyxError::internal(err.clone()));
            }
            // Simulate credential change after login.
            if let Some(new_cred) = self.login_changes_credential_to.lock().unwrap().clone() {
                *self.credential.lock().unwrap() = Some(new_cred);
            }
            Ok(())
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supported_versions() {
        assert!(is_supported_version("1.2.14"));
        assert!(is_supported_version("1.3.2"));
        assert!(is_supported_version("1.4.3"));
        assert!(!is_supported_version("1.0.0"));
        assert!(!is_supported_version("2.0.0"));
        assert_eq!(SUPPORTED_AGY_VERSION, "1.4.3");
    }
}
