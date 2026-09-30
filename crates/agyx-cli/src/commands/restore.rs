use crate::output::print_success;
use agyx_core::{adapter::RealAgyAdapter, config::load_config, process_manager::find_agy_pids, switcher::Switcher};
use console::style;
use dialoguer::Confirm;

pub fn run() -> anyhow::Result<()> {
    let cfg = load_config()?;
    if !cfg.has_original_backup {
        anyhow::bail!(
            "No original backup exists. AGYX never captured a pre-AGYX credential on this machine."
        );
    }

    println!("{}", style("Restore Original AGY Credential").bold().cyan());
    println!("─────────────────────────────────────────────");
    println!(
        "Original account:  {} ({})",
        cfg.original_backup_email.as_deref().unwrap_or("unknown"),
        cfg.original_backup_sub.as_deref().unwrap_or("unknown"),
    );
    println!();

    let pids = find_agy_pids();
    if !pids.is_empty() {
        eprintln!(
            "{} AGY is running. It must be closed before restoring.",
            style("Warning:").yellow().bold()
        );
        let confirm = Confirm::new()
            .with_prompt("Close AGY and proceed?")
            .default(false)
            .interact()?;
        if !confirm {
            anyhow::bail!("Restore cancelled.");
        }
        if !find_agy_pids().is_empty() {
            anyhow::bail!("AGY is still running. Please close it and re-run `agyx restore-original`.");
        }
    }

    let confirm = Confirm::new()
        .with_prompt("Restore the original credential? This will overwrite the current live credential.")
        .default(false)
        .interact()?;
    if !confirm {
        anyhow::bail!("Restore cancelled.");
    }

    let adapter = RealAgyAdapter::new()?;
    let switcher = Switcher::new(Box::new(adapter));

    let result = switcher.restore_original()?;
    print_success("Original AGY credential restored.");
    println!("  Email:    {}", result.email);
    println!("  Sub:      {}", result.sub);

    Ok(())
}
