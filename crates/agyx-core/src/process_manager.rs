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

/// Returns a set containing the current process PID and all of its ancestor PIDs.
pub fn get_current_and_ancestor_pids(sys: &System) -> std::collections::HashSet<u32> {
    let mut ancestors = std::collections::HashSet::new();
    let current_pid = std::process::id();
    ancestors.insert(current_pid);

    let mut curr_pid = sysinfo::Pid::from_u32(current_pid);
    while let Some(proc) = sys.process(curr_pid) {
        if let Some(parent) = proc.parent() {
            let parent_u32 = parent.as_u32();
            if parent_u32 == 0 || !ancestors.insert(parent_u32) {
                break;
            }
            curr_pid = parent;
        } else {
            break;
        }
    }

    ancestors
}

/// Returns the PIDs of all running AGY processes (excluding current and ancestor processes),
/// or an empty vec if none.
pub fn find_agy_pids() -> Vec<u32> {
    #[cfg(any(test, feature = "mock-adapter"))]
    {
        if let Some(ref mock_pids) = *MOCK_RUNNING_PIDS.read().unwrap() {
            return mock_pids.clone();
        }
    }

    let mut sys = System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    let excluded = get_current_and_ancestor_pids(&sys);

    sys.processes()
        .values()
        .filter(|p| {
            p.name()
                .to_str()
                .map(|n| n.eq_ignore_ascii_case(AGY_PROCESS_NAME))
                .unwrap_or(false)
        })
        .map(|p| p.pid().as_u32())
        .filter(|pid| !excluded.contains(pid))
        .collect()
}

/// Returns the PIDs of any ancestor AGY processes that are running and excluded.
pub fn find_ancestor_agy_pids() -> Vec<u32> {
    let mut sys = System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    let ancestors = get_current_and_ancestor_pids(&sys);

    sys.processes()
        .values()
        .filter(|p| {
            p.name()
                .to_str()
                .map(|n| n.eq_ignore_ascii_case(AGY_PROCESS_NAME))
                .unwrap_or(false)
        })
        .map(|p| p.pid().as_u32())
        .filter(|pid| ancestors.contains(pid))
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

/// Terminates a single process by PID.
pub fn terminate_single_pid(pid: u32) -> bool {
    let mut sys = System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    if let Some(process) = sys.process(sysinfo::Pid::from_u32(pid)) {
        let _ = process.kill();
    }
    #[cfg(target_os = "windows")]
    {
        terminate_pid_windows(pid)
    }
    #[cfg(not(target_os = "windows"))]
    {
        true
    }
}

#[cfg(target_os = "windows")]
fn terminate_pid_windows(pid: u32) -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        OpenProcess, TerminateProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
    };

    unsafe {
        if let Ok(handle) = OpenProcess(PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, false, pid) {
            let res = TerminateProcess(handle, 1);
            let _ = WaitForSingleObject(handle, 2000);
            let _ = CloseHandle(handle);
            res.is_ok()
        } else {
            false
        }
    }
}

/// Terminates all running AGY processes.
///
/// Returns the list of PIDs that were terminated.
/// Polls until processes are confirmed exited, or returns an error on timeout.
pub fn terminate_agy_processes() -> Result<Vec<u32>, AgyxError> {
    #[cfg(any(test, feature = "mock-adapter"))]
    {
        let mut mock_guard = MOCK_RUNNING_PIDS.write().unwrap();
        if let Some(ref mock_pids) = *mock_guard {
            let killed = mock_pids.clone();
            *mock_guard = Some(Vec::new());
            return Ok(killed);
        }
    }

    let initial_pids = find_agy_pids();
    if initial_pids.is_empty() {
        return Ok(Vec::new());
    }

    let mut sys = System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    for &pid in &initial_pids {
        if let Some(process) = sys.process(sysinfo::Pid::from_u32(pid)) {
            let _ = process.kill();
        }
    }

    #[cfg(target_os = "windows")]
    {
        for &pid in &initial_pids {
            let _ = terminate_pid_windows(pid);
        }
    }

    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_millis(3000);
    while start.elapsed() < timeout {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if find_agy_pids().is_empty() {
            return Ok(initial_pids);
        }
    }

    let remaining = find_agy_pids();
    if remaining.is_empty() {
        Ok(initial_pids)
    } else {
        Err(AgyxError::internal(format!(
            "Failed to terminate AGY process(es) (PID{:?}). Please close them manually.",
            remaining
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_terminate_agy_processes() {
        set_mock_running_pids(Some(vec![4944, 5000]));
        assert_eq!(find_agy_pids(), vec![4944, 5000]);
        assert!(ensure_agy_not_running().is_err());

        let terminated = terminate_agy_processes().expect("terminate succeeds");
        assert_eq!(terminated, vec![4944, 5000]);
        assert_eq!(find_agy_pids(), Vec::<u32>::new());
        assert!(ensure_agy_not_running().is_ok());

        // Cleanup
        set_mock_running_pids(None);
    }

    #[test]
    fn test_terminate_when_none_running() {
        set_mock_running_pids(Some(vec![]));
        let terminated = terminate_agy_processes().expect("terminate succeeds");
        assert!(terminated.is_empty());
        // Cleanup
        set_mock_running_pids(None);
    }

    #[test]
    fn test_current_process_and_ancestors_excluded() {
        let mut sys = System::new();
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        let ancestors = get_current_and_ancestor_pids(&sys);
        assert!(ancestors.contains(&std::process::id()));
    }
}

