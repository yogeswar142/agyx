use crate::output::{print_success, print_warning};
use agyx_core::{
    adapter::{AgyAdapter, RealAgyAdapter},
    process_manager::find_agy_pids,
    switcher::Switcher,
};
use console::style;
use dialoguer::Confirm;

pub fn run(name: &str) -> anyhow::Result<()> {
    let pids = find_agy_pids();
    if !pids.is_empty() {
        eprintln!(
            "{} AGY is running (PID{}: {:?}).",
            style("Warning:").yellow().bold(),
            if pids.len() > 1 { "s" } else { "" },
            pids
        );
        let restart = Confirm::new()
            .with_prompt("AGY must be closed to switch accounts. Close it now?")
            .default(false)
            .interact()?;
        if !restart {
            anyhow::bail!("Switch cancelled.");
        }
        if !find_agy_pids().is_empty() {
            anyhow::bail!(
                "AGY is still running. Please close AGY completely, then re-run `agyx switch {}`.",
                name
            );
        }
    }

    let adapter = RealAgyAdapter::new()?;
    let detection = adapter.detect()?;
    if !detection.version_matches {
        print_warning(&format!(
            "AGY version {} is not the tested version ({}).",
            detection.version,
            agyx_core::adapter::SUPPORTED_AGY_VERSION
        ));
    }

    let switcher = Switcher::new(Box::new(adapter));
    let result = switcher.switch(name)?;

    print_success(&format!("Switched to profile '{}'", result.profile));
    println!("  Email:    {}", result.email);
    println!("  Sub:      {}", result.sub);
    println!();
    println!("Run {} to launch AGY.", style("agyx run").bold());

    Ok(())
}
