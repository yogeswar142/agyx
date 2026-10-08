//! OS keyring abstraction for storing the vault master key.
//!
//! The vault master key is a random 32-byte secret encoded as base64url.
//! It is stored in the OS credential store under:
//!   service = "agyx"
//!   account = "vault-key"
//!
//! # Platform implementations
//! - Windows:  Windows Credential Manager (`CredWriteW` / `CredReadW`)
//! - macOS:    Keychain Services (future — requires macOS Phase 0 discovery)
//! - Linux:    Secret Service D-Bus (future — requires Linux Phase 0 discovery)

use crate::AgyxError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;

/// The OS keyring service name for AGYX.
const AGYX_SERVICE: &str = "agyx";
/// The OS keyring account name for the vault key.
const VAULT_KEY_ACCOUNT: &str = "vault-key";

/// Load the vault master key from the OS keyring, generating and storing a
/// new one if none exists.
///
/// Returns 32 raw bytes.
pub fn load_or_create_vault_key() -> Result<[u8; 32], AgyxError> {
    match os_read_vault_key()? {
        Some(key) => Ok(key),
        None => {
            let key = generate_key();
            os_write_vault_key(&key)?;
            Ok(key)
        }
    }
}

fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

// ─── Windows implementation ─────────────────────────────────────────────────

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::*;
    use windows::Win32::Foundation::ERROR_NOT_FOUND;
    use windows::Win32::Security::Credentials::{
        CredFree, CredReadW, CredWriteW,
        CREDENTIAL_ATTRIBUTEW, CREDENTIALW, CRED_FLAGS, CRED_PERSIST_LOCAL_MACHINE,
        CRED_TYPE_GENERIC,
    };
    use windows::core::PWSTR;

    fn target_name() -> String {
        format!("{}:{}", super::AGYX_SERVICE, super::VAULT_KEY_ACCOUNT)
    }

    pub fn read() -> Result<Option<[u8; 32]>, AgyxError> {
        let target = target_name();
        let target_wide: Vec<u16> = target.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            let mut pcred: *mut CREDENTIALW = std::ptr::null_mut();
            let ok = CredReadW(
                PWSTR(target_wide.as_ptr() as *mut u16),
                CRED_TYPE_GENERIC,
                Some(0),
                &mut pcred,
            );

            if ok.is_err() {
                let err = windows::Win32::Foundation::GetLastError();
                if err == ERROR_NOT_FOUND {
                    return Ok(None);
                }
                return Err(AgyxError::OsCredentialError(format!(
                    "CredReadW failed: {err:?}"
                )));
            }

            let cred = &*pcred;
            let blob_len = cred.CredentialBlobSize as usize;
            let blob_ptr = cred.CredentialBlob;
            let blob = std::slice::from_raw_parts(blob_ptr, blob_len);
            let b64 = std::str::from_utf8(blob).map_err(|_| {
                AgyxError::OsCredentialError("vault key blob is not valid UTF-8".into())
            })?;
            let key_bytes = URL_SAFE_NO_PAD.decode(b64).map_err(|e| {
                AgyxError::OsCredentialError(format!("vault key base64 decode error: {e}"))
            })?;

            CredFree(pcred as _);

            if key_bytes.len() != 32 {
                return Err(AgyxError::OsCredentialError(format!(
                    "vault key has wrong length: expected 32, got {}",
                    key_bytes.len()
                )));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&key_bytes);
            Ok(Some(arr))
        }
    }

    pub fn write(key: &[u8; 32]) -> Result<(), AgyxError> {
        let target = target_name();
        let target_wide: Vec<u16> = target.encode_utf16().chain(std::iter::once(0)).collect();
        let user_wide: Vec<u16> = "agyx"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let b64 = URL_SAFE_NO_PAD.encode(key);
        let blob_bytes = b64.as_bytes();

        unsafe {
            let cred = CREDENTIALW {
                Flags: CRED_FLAGS(0),
                Type: CRED_TYPE_GENERIC,
                TargetName: PWSTR(target_wide.as_ptr() as *mut u16),
                Comment: PWSTR::null(),
                LastWritten: Default::default(),
                CredentialBlobSize: blob_bytes.len() as u32,
                CredentialBlob: blob_bytes.as_ptr() as *mut u8,
                Persist: CRED_PERSIST_LOCAL_MACHINE,
                AttributeCount: 0,
                Attributes: std::ptr::null_mut() as *mut CREDENTIAL_ATTRIBUTEW,
                TargetAlias: PWSTR::null(),
                UserName: PWSTR(user_wide.as_ptr() as *mut u16),
            };

            CredWriteW(&cred, 0).map_err(|e| {
                AgyxError::OsCredentialError(format!("CredWriteW failed: {e}"))
            })?;
        }
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn os_read_vault_key() -> Result<Option<[u8; 32]>, AgyxError> {
    windows_impl::read()
}

#[cfg(target_os = "windows")]
fn os_write_vault_key(key: &[u8; 32]) -> Result<(), AgyxError> {
    windows_impl::write(key)
}

// ─── OS keyring functions for AGY's own credential slot ─────────────────────
//
// NOTE: These functions access the AGY credential, not AGYX's own vault key.
// They are used by the Switcher to read/write/backup the current credential.

/// The target name AGY uses in Windows Credential Manager.
///
/// **UNDOCUMENTED INTERFACE** — discovered by binary inspection of agy.exe v1.2.14.
pub const AGY_TARGET: &str = "gemini:antigravity";

/// The upper size limit for a Windows Credential Manager generic credential blob.
/// Per Microsoft docs: CRED_MAX_CREDENTIAL_BLOB_SIZE = 5 * 512 = 2,560 bytes.
/// Ref: https://learn.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw
pub const WINDOWS_CREDENTIAL_BLOB_MAX: usize = 2560;

#[cfg(target_os = "windows")]
pub mod agt {
    //! Access to AGY's `gemini:antigravity` credential in Windows Credential Manager.
    //! All operations are on raw bytes — no interpretation.

    use super::*;
    use windows::Win32::Foundation::ERROR_NOT_FOUND;
    use windows::Win32::Security::Credentials::{
        CredDeleteW, CredFree, CredReadW, CredWriteW,
        CREDENTIAL_ATTRIBUTEW, CREDENTIALW, CRED_FLAGS, CRED_PERSIST_LOCAL_MACHINE,
        CRED_TYPE_GENERIC,
    };
    use windows::core::PWSTR;

    fn target_wide() -> Vec<u16> {
        super::AGY_TARGET
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect()
    }

    /// Read AGY's raw credential blob. Returns `None` if no credential exists.
    pub fn read_raw() -> Result<Option<Vec<u8>>, AgyxError> {
        let tw = target_wide();
        unsafe {
            let mut pcred: *mut CREDENTIALW = std::ptr::null_mut();
            let result = CredReadW(
                PWSTR(tw.as_ptr() as *mut u16),
                CRED_TYPE_GENERIC,
                Some(0),
                &mut pcred,
            );
            if result.is_err() {
                let err = windows::Win32::Foundation::GetLastError();
                if err == ERROR_NOT_FOUND {
                    return Ok(None);
                }
                return Err(AgyxError::OsCredentialError(format!(
                    "CredReadW on 'gemini:antigravity' failed: {err:?}"
                )));
            }
            let cred = &*pcred;
            let blob = std::slice::from_raw_parts(
                cred.CredentialBlob,
                cred.CredentialBlobSize as usize,
            )
            .to_vec();
            CredFree(pcred as _);
            Ok(Some(blob))
        }
    }

    /// Write raw bytes into AGY's `gemini:antigravity` credential slot.
    ///
    /// The blob is written byte-for-byte without any modification.
    pub fn write_raw(blob: &[u8]) -> Result<(), AgyxError> {
        if blob.len() > WINDOWS_CREDENTIAL_BLOB_MAX {
            return Err(AgyxError::BlobTooLarge {
                size: blob.len(),
                limit: WINDOWS_CREDENTIAL_BLOB_MAX,
            });
        }
        let tw = target_wide();
        let user_wide: Vec<u16> = "antigravity"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        unsafe {
            let cred = CREDENTIALW {
                Flags: CRED_FLAGS(0),
                Type: CRED_TYPE_GENERIC,
                TargetName: PWSTR(tw.as_ptr() as *mut u16),
                Comment: PWSTR::null(),
                LastWritten: Default::default(),
                CredentialBlobSize: blob.len() as u32,
                CredentialBlob: blob.as_ptr() as *mut u8,
                Persist: CRED_PERSIST_LOCAL_MACHINE,
                AttributeCount: 0,
                Attributes: std::ptr::null_mut() as *mut CREDENTIAL_ATTRIBUTEW,
                TargetAlias: PWSTR::null(),
                UserName: PWSTR(user_wide.as_ptr() as *mut u16),
            };
            CredWriteW(&cred, 0).map_err(|e| {
                AgyxError::OsCredentialError(format!(
                    "CredWriteW on 'gemini:antigravity' failed: {e}"
                ))
            })?;
        }
        Ok(())
    }

    /// Delete AGY's `gemini:antigravity` credential entry.
    /// Used to restore the "no credential" state when the user had none before,
    /// or temporarily clear the active credential during `login`.
    pub fn delete() -> Result<(), AgyxError> {
        let tw = target_wide();
        unsafe {
            let res = CredDeleteW(PWSTR(tw.as_ptr() as *mut u16), CRED_TYPE_GENERIC, Some(0));
            if res.is_err() {
                let err = windows::Win32::Foundation::GetLastError();
                if err == ERROR_NOT_FOUND {
                    return Ok(());
                }
                return Err(AgyxError::OsCredentialError(format!(
                    "CredDeleteW on 'gemini:antigravity' failed: {err:?}"
                )));
            }
        }
        Ok(())
    }
}

// ─── macOS stub ─────────────────────────────────────────────────────────────
// UNVERIFIED: macOS discovery has not yet been performed.
#[cfg(target_os = "macos")]
fn os_read_vault_key() -> Result<Option<[u8; 32]>, AgyxError> {
    Err(AgyxError::internal(
        "macOS keychain support not yet implemented — run macOS Phase 0 discovery first",
    ))
}
#[cfg(target_os = "macos")]
fn os_write_vault_key(_key: &[u8; 32]) -> Result<(), AgyxError> {
    Err(AgyxError::internal(
        "macOS keychain support not yet implemented — run macOS Phase 0 discovery first",
    ))
}

// ─── Linux stub ─────────────────────────────────────────────────────────────
// UNVERIFIED: Linux discovery has not yet been performed.
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn os_read_vault_key() -> Result<Option<[u8; 32]>, AgyxError> {
    Err(AgyxError::internal(
        "Linux Secret Service support not yet implemented — run Linux Phase 0 discovery first",
    ))
}
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn os_write_vault_key(_key: &[u8; 32]) -> Result<(), AgyxError> {
    Err(AgyxError::internal(
        "Linux Secret Service support not yet implemented — run Linux Phase 0 discovery first",
    ))
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_size_constant_is_2560() {
        // Windows limit: CRED_MAX_CREDENTIAL_BLOB_SIZE = 5 * 512 = 2560 bytes.
        assert_eq!(WINDOWS_CREDENTIAL_BLOB_MAX, 2560);
    }

    #[test]
    fn agy_blob_fits_within_windows_limit() {
        // AGY's observed blob on this machine is ~1,690 bytes.
        // This test documents that it fits within the OS limit.
        let observed = 1690usize;
        assert!(
            observed < WINDOWS_CREDENTIAL_BLOB_MAX,
            "AGY blob size {observed} must fit in Windows CM limit {WINDOWS_CREDENTIAL_BLOB_MAX}"
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_credential_manager_lossless_round_trip() {
        use windows::Win32::Security::Credentials::{
            CredDeleteW, CredFree, CredReadW, CredWriteW,
            CREDENTIALW, CRED_FLAGS, CRED_PERSIST_LOCAL_MACHINE,
            CRED_TYPE_GENERIC, CREDENTIAL_ATTRIBUTEW,
        };
        use windows::core::PWSTR;

        let test_target = "agyx:test-lossless-roundtrip";
        let target_wide: Vec<u16> = test_target.encode_utf16().chain(std::iter::once(0)).collect();
        let user_wide: Vec<u16> = "test-user".encode_utf16().chain(std::iter::once(0)).collect();

        // Generate arbitrary 1,690-byte test payload with edge-case bytes (0x00, 0xFF, UTF-8 strings)
        let mut test_payload = Vec::with_capacity(1690);
        for i in 0..1690 {
            test_payload.push((i % 256) as u8);
        }

        unsafe {
            let cred = CREDENTIALW {
                Flags: CRED_FLAGS(0),
                Type: CRED_TYPE_GENERIC,
                TargetName: PWSTR(target_wide.as_ptr() as *mut u16),
                Comment: PWSTR::null(),
                LastWritten: Default::default(),
                CredentialBlobSize: test_payload.len() as u32,
                CredentialBlob: test_payload.as_ptr() as *mut u8,
                Persist: CRED_PERSIST_LOCAL_MACHINE,
                AttributeCount: 0,
                Attributes: std::ptr::null_mut() as *mut CREDENTIAL_ATTRIBUTEW,
                TargetAlias: PWSTR::null(),
                UserName: PWSTR(user_wide.as_ptr() as *mut u16),
            };

            // Write
            CredWriteW(&cred, 0).expect("CredWriteW failed in test");

            // Read back
            let mut pcred: *mut CREDENTIALW = std::ptr::null_mut();
            CredReadW(
                PWSTR(target_wide.as_ptr() as *mut u16),
                CRED_TYPE_GENERIC,
                Some(0),
                &mut pcred,
            ).expect("CredReadW failed in test");

            assert!(!pcred.is_null());
            let read_cred = &*pcred;
            let read_bytes = std::slice::from_raw_parts(
                read_cred.CredentialBlob,
                read_cred.CredentialBlobSize as usize,
            );

            // Assert exact byte-for-byte fidelity
            assert_eq!(test_payload.as_slice(), read_bytes, "CredReadW must match CredWriteW bit-for-bit");

            CredFree(pcred as _);

            // Teardown: delete test entry
            let _ = CredDeleteW(PWSTR(target_wide.as_ptr() as *mut u16), CRED_TYPE_GENERIC, Some(0));
        }
    }
}
