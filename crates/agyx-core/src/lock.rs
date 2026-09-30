//! File-based exclusive lock to prevent concurrent agyx operations.
//!
//! Uses `fs4` for cross-platform advisory file locking.  Two agyx instances
//! cannot hold the lock simultaneously.

use crate::AgyxError;
use fs4::fs_std::FileExt;
use std::fs::{File, OpenOptions};
use std::path::Path;

/// An RAII exclusive file lock. Dropped when scope exits.
#[derive(Debug)]
pub struct AgyxLock {
    _file: File,
}

impl AgyxLock {
    /// Try to acquire the exclusive lock immediately (non-blocking).
    ///
    /// Returns `Err(AgyxError::LockContended)` if another process holds it.
    pub fn try_acquire(lock_path: &Path) -> Result<Self, AgyxError> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(lock_path)
            .map_err(|e| AgyxError::IoError {
                path: lock_path.display().to_string(),
                source: e,
            })?;

        file.try_lock_exclusive()
            .map_err(|_| AgyxError::LockContended)?;

        Ok(AgyxLock { _file: file })
    }
}
// Lock is released automatically when `_file` is dropped, which closes the
// file and releases the advisory lock.
