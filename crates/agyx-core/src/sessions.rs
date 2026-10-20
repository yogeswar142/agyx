//! Multi-terminal active session tracking for AGYX.

use crate::config::{config_dir, SESSIONS_FILE};
use crate::AgyxError;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use sysinfo::System;

/// Represents an active AGY process running in a terminal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActiveSession {
    /// Process ID of the running AGY process.
    pub pid: u32,
    /// Name of the profile this session was launched with.
    pub profile: String,
    /// Timestamp when this session was started (RFC 3339).
    pub started_at: String,
}

/// Returns the path to `agyx_sessions.json`.
pub fn sessions_file_path() -> Result<PathBuf, AgyxError> {
    Ok(config_dir()?.join(SESSIONS_FILE))
}

/// Checks if a PID is still actively running.
pub fn is_pid_alive(pid: u32) -> bool {
    let mut sys = System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    sys.process(sysinfo::Pid::from_u32(pid)).is_some()
}

/// Loads all active sessions from disk, automatically pruning stale sessions.
pub fn load_active_sessions() -> Result<Vec<ActiveSession>, AgyxError> {
    let path = sessions_file_path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }

    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return Ok(Vec::new()),
    };

    let sessions: Vec<ActiveSession> = serde_json::from_str(&content).unwrap_or_default();

    let mut sys = System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

    let mut live_sessions: Vec<ActiveSession> = Vec::new();
    let mut had_stale = false;

    for s in sessions {
        if sys.process(sysinfo::Pid::from_u32(s.pid)).is_some() {
            live_sessions.push(s);
        } else {
            had_stale = true;
        }
    }

    if had_stale {
        let _ = save_active_sessions(&live_sessions);
    }

    Ok(live_sessions)
}

fn save_active_sessions(sessions: &[ActiveSession]) -> Result<(), AgyxError> {
    let path = sessions_file_path()?;
    let json = serde_json::to_string_pretty(sessions)
        .map_err(|e| AgyxError::internal(format!("Failed to serialize sessions: {e}")))?;
    fs::write(&path, json).map_err(|e| AgyxError::IoError {
        path: path.display().to_string(),
        source: e,
    })?;
    Ok(())
}

/// Records a newly spawned AGY session.
pub fn record_session(pid: u32, profile: &str) -> Result<(), AgyxError> {
    let mut sessions = load_active_sessions().unwrap_or_default();
    sessions.retain(|s| s.pid != pid);

    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown".to_owned());

    sessions.push(ActiveSession {
        pid,
        profile: profile.to_owned(),
        started_at: now,
    });

    save_active_sessions(&sessions)
}

/// Removes a terminated session from tracking.
pub fn remove_session(pid: u32) -> Result<(), AgyxError> {
    let mut sessions = load_active_sessions().unwrap_or_default();
    sessions.retain(|s| s.pid != pid);
    save_active_sessions(&sessions)
}

/// Returns all active sessions for a specific profile name.
pub fn sessions_for_profile(profile: &str) -> Vec<ActiveSession> {
    load_active_sessions()
        .unwrap_or_default()
        .into_iter()
        .filter(|s| s.profile == profile)
        .collect()
}
