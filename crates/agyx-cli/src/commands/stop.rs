use crate::output::print_success;
use agyx_core::process_manager::{
    find_agy_pids, find_ancestor_agy_pids, terminate_agy_processes, terminate_single_pid,
};
use console::style;

pub fn run(account: Option<&str>) -> anyhow::Result<()> {
    if let Some(name) = account {
        let sessions = agyx_core::sessions::sessions_for_profile(name);
        if sessions.is_empty() {
            println!("No active terminal sessions found for profile '{}'.", name);
            return Ok(());
        }

        let pids: Vec<u32> = sessions.iter().map(|s| s.pid).collect();
        println!(
            "{} Found {} active session(s) for profile '{}' (PID{:?}). Terminating...",
            style("•").cyan().bold(),
            sessions.len(),
            name,
            pids
        );

        for &pid in &pids {
            let _ = terminate_single_pid(pid);
            let _ = agyx_core::sessions::remove_session(pid);
        }

        print_success(&format!(
            "Terminated {} AGY session(s) for profile '{}'.",
            pids.len(),
            name
        ));
        return Ok(());
    }

    let pids = find_agy_pids();
    if pids.is_empty() {
        let ancestor_pids = find_ancestor_agy_pids();
        if !ancestor_pids.is_empty() {
            println!(
                "No external AGY processes found (current session host PID{:?} excluded).",
                ancestor_pids
            );
        } else {
            println!("No running AGY processes found.");
        }
        return Ok(());
    }

    println!(
        "{} Found running AGY process{} (PID{}: {:?}). Terminating...",
        style("•").cyan().bold(),
        if pids.len() > 1 { "es" } else { "" },
        if pids.len() > 1 { "s" } else { "" },
        pids
    );

    let terminated = terminate_agy_processes()?;
    if terminated.is_empty() {
        println!("No AGY processes were terminated.");
    } else {
        // Also prune active sessions tracking
        for &pid in &terminated {
            let _ = agyx_core::sessions::remove_session(pid);
        }
        print_success(&format!(
            "Successfully terminated AGY process{} (PID{}: {:?}).",
            if terminated.len() > 1 { "es" } else { "" },
            if terminated.len() > 1 { "s" } else { "" },
            terminated
        ));
    }

    Ok(())
}
