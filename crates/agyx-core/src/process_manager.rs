//! Process manager — detect and (with confirmation) terminate AGY.

use crate::AgyxError;
use sysinfo::System;

/// The name of the AGY process executable (without extension on non-Windows).
#[cfg(target_os = "windows")]
const AGY_PROCESS_NAME: &str = "agy.exe";

#[cfg(not(target_os = "windows"))]
const AGY_PROCESS_NAME: &str = "agy";

#[cfg(any(test, feature = "mock-adapter"))]
static MOCK_RUNNING_PIDS: std::sync::RwLock<Option<Vec<u32>>> = std::sync::RwLock::new(None);

#[cfg(any(test, feature = "mock-adapter"))]
pub fn set_mock_running_pids(pids: Option<Vec<u32>>) {
    *MOCK_RUNNING_PIDS.write().unwrap() = pids;
}

/// Returns the PIDs of all running AGY processes, or an empty vec if none.
pub fn find_agy_pids() -> Vec<u32> {
    #[cfg(any(test, feature = "mock-adapter"))]
    {
        if let Some(ref mock_pids) = *MOCK_RUNNING_PIDS.read().unwrap() {
            return mock_pids.clone();
        }
    }

    let mut sys = System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    sys.processes()
        .values()
        .filter(|p| {
            p.name()
                .to_str()
                .map(|n| n.eq_ignore_ascii_case(AGY_PROCESS_NAME))
                .unwrap_or(false)
        })
        .map(|p| p.pid().as_u32())
        .collect()
}

/// Checks whether AGY is running and returns `Err(AgyxError::AgyRunning)`
/// if it is.  Returns `Ok(())` if AGY is not running.
pub fn ensure_agy_not_running() -> Result<(), AgyxError> {
    let pids = find_agy_pids();
    if pids.is_empty() {
        Ok(())
    } else {
        Err(AgyxError::AgyRunning { pids })
    }
}
