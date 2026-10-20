use crate::output::{print_success, print_warning};
use agyx_core::{
    adapter::{AgyAdapter, RealAgyAdapter},
    process_manager::find_agy_pids,
    switcher::Switcher,
};
use console::style;
use dialoguer::Confirm;

pub fn run(name: &str) -> anyhow::Result<()> {
    // 1. Check if profile is already active in the OS credential store
    let cfg = agyx_core::config::load_config()?;
    if let Some(meta) = cfg.profiles.get(name) {
        if let Ok(Some(live_blob)) = RealAgyAdapter::new()?.read_credential() {
            if let Ok(live_id) = agyx_core::identity::extract_identity(&live_blob) {
                if live_id.sub == meta.sub {
                    print_success(&format!("Profile '{}' is already active in the OS credential store.", name));
                    println!("  Email:    {}", live_id.email);
                    println!("  Sub:      {}", live_id.sub);
                    println!();
                    println!("Run {} or {} to launch AGY.", style("agyx run").bold(), style(format!("agyx start {name}")).bold());
                    return Ok(());
                }
            }
        }
    }

    // 2. If not active, check if AGY is running
    let pids = find_agy_pids();
    if !pids.is_empty() {
        eprintln!(
            "{} AGY is running in other terminal(s) (PID{}: {:?}).",
            style("Notice:").yellow().bold(),
            if pids.len() > 1 { "s" } else { "" },
            pids
        );
        println!(
            "Tip: You can use `{}` to launch this account in this terminal without closing other terminals.",
            style(format!("agyx start {name}")).cyan().bold()
        );
        println!();
        let restart = Confirm::new()
            .with_prompt("Do you want to terminate running AGY processes and switch default account now?")
            .default(false)
            .interact()?;
        if !restart {
            anyhow::bail!(
                "Switch cancelled. Tip: Use `agyx start {}` to start without closing other terminals.",
                name
            );
        }
        let terminated = agyx_core::process_manager::terminate_agy_processes()?;
        if !terminated.is_empty() {
            println!(
                "{} Closed running AGY process{}: {:?}.",
                style("✓").green().bold(),
                if terminated.len() > 1 { "es" } else { "" },
                terminated
            );
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
            "AGY version {} is not among tested versions ({}).",
            detection.version,
            agyx_core::adapter::SUPPORTED_AGY_VERSIONS.join(", ")
        ));
    }

    let switcher = Switcher::new(Box::new(adapter));
    let result = switcher.switch(name)?;

    print_success(&format!("Switched to profile '{}'", result.profile));
    println!("  Email:    {}", result.email);
    println!("  Sub:      {}", result.sub);
    println!();
    println!("Run {} or {} to launch AGY.", style("agyx run").bold(), style(format!("agyx start {name}")).bold());

    Ok(())
}
