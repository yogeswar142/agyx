use crate::output::{print_success, print_warning};
use agyx_core::{
    adapter::{AgyAdapter, RealAgyAdapter},
    process_manager::find_agy_pids,
    switcher::Switcher,
    AgyxError,
};
use console::style;
use dialoguer::Confirm;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub fn run(name: &str) -> anyhow::Result<()> {
    // 1. Version check
    let adapter = RealAgyAdapter::new()?;
    {
        let detection = adapter.detect()?;
        if !detection.version_matches {
            print_warning(&format!(
                "AGY version {} is not the tested version ({}). Proceed with caution.",
                detection.version,
                agyx_core::adapter::SUPPORTED_AGY_VERSION
            ));
        }
    }

    // 2. Running instance guard
    let pids = find_agy_pids();
    if !pids.is_empty() {
        eprintln!(
            "{} AGY is running (PID{}: {:?}).",
            style("Warning:").yellow().bold(),
            if pids.len() > 1 { "s" } else { "" },
            pids
        );
        eprintln!("Login requires AGY to be closed.");
        let restart = Confirm::new()
            .with_prompt("Close AGY now and continue?")
            .default(false)
            .interact()?;
        if !restart {
            anyhow::bail!("Login cancelled.");
        }
        if !find_agy_pids().is_empty() {
            anyhow::bail!(
                "AGY is still running. Please close AGY completely, then re-run `agyx login {}`.",
                name
            );
        }
    }

    // 3. Register Ctrl+C handler to restore original credential on interruption
    let active = Arc::new(AtomicBool::new(true));
    let active_clone = active.clone();
    let _ = ctrlc::set_handler(move || {
        if active_clone.swap(false, Ordering::SeqCst) {
            eprintln!();
            eprintln!("{}", style("Interrupted by Ctrl+C! Restoring original credential...").yellow().bold());
            if let Ok(adapter) = RealAgyAdapter::new() {
                match agyx_core::journal::check_and_recover_journal(&adapter) {
                    Ok(Some(rep)) => {
                        eprintln!(
                            "{} Successfully restored prior credential (sub: {:?})",
                            style("✓").green().bold(),
                            rep.original_sub
                        );
                    }
                    Ok(None) => {}
                    Err(e) => {
                        eprintln!(
                            "{} Could not automatically restore credential: {}",
                            style("CRITICAL:").red().bold(),
                            e
                        );
                        eprintln!("Run `agyx restore-original` to recover manually.");
                    }
                }
            }
            std::process::exit(130);
        }
    });

    let switcher = Switcher::new(Box::new(adapter));

    println!();
    println!("{}", style("AGYX Login").bold().cyan());
    println!("─────────────────────────────────────────────");
    println!("Profile name:  {}", style(name).bold());
    println!();
    println!(
        "AGYX will launch AGY's login flow to authenticate a NEW account."
    );
    println!(
        "When finished authenticating, {} AGY to return to AGYX.",
        style("exit").italic()
    );
    println!(
        "AGYX will save the new account as '{}' and restore your previous active account.",
        name
    );
    println!();

    // 4. Check if live account is saved in AGYX
    let mut allow_unsaved = false;
    if let Some(cur) = switcher.current()? {
        if cur.profile.is_none() {
            eprintln!(
                "{} The currently active AGY account is not registered in AGYX:",
                style("Warning:").yellow().bold()
            );
            eprintln!("  Email: {}", cur.email);
            eprintln!("  Sub:   {}", cur.sub);
            eprintln!();
            eprintln!("To preserve this account permanently before logging in to another, run:");
            eprintln!("  {}", style(format!("agyx save <profile-name>")).cyan().bold());
            eprintln!();
            let proceed = Confirm::new()
                .with_prompt("Do you want to proceed without saving this account first?")
                .default(false)
                .interact()?;
            if !proceed {
                active.store(false, Ordering::SeqCst);
                anyhow::bail!("Login aborted. Run `agyx save <name>` first to preserve your current account.");
            }
            allow_unsaved = true;
        }
    }

    let confirm = Confirm::new()
        .with_prompt("Ready to start login?")
        .default(true)
        .interact()?;
    if !confirm {
        active.store(false, Ordering::SeqCst);
        anyhow::bail!("Login cancelled.");
    }

    match switcher.login(name, allow_unsaved) {
        Ok(result) => {
            active.store(false, Ordering::SeqCst);
            print_login_success(&result);
        }
        Err(AgyxError::LoginCancelled) => {
            active.store(false, Ordering::SeqCst);
            anyhow::bail!(
                "No AGY credential was found after the login flow. \
                 Did you complete authentication in the browser and close AGY?"
            );
        }
        Err(AgyxError::LoginNoChange) => {
            active.store(false, Ordering::SeqCst);
            anyhow::bail!(
                "The authenticated account matches your previously active account. \
                 To add an additional account, log in with a different Google account."
            );
        }
        Err(AgyxError::AccountAlreadyRegistered { sub, profile }) => {
            active.store(false, Ordering::SeqCst);
            anyhow::bail!(
                "This account (sub: {}) is already registered as profile '{}'.",
                sub,
                profile
            );
        }
        Err(AgyxError::RestoreFailed { reason, backup_path }) => {
            active.store(false, Ordering::SeqCst);
            eprintln!();
            eprintln!("{}", style("CRITICAL ERROR").red().bold());
            eprintln!("Login failed and the original credential could not be restored.");
            eprintln!("Reason: {}", reason);
            eprintln!();
            eprintln!("The encrypted backup is kept at:");
            eprintln!("  {}", backup_path);
            eprintln!();
            eprintln!("To recover, run:");
            eprintln!("  agyx restore-original");
            anyhow::bail!("Login and rollback failed. See above for recovery instructions.");
        }
        Err(e) => {
            active.store(false, Ordering::SeqCst);
            return Err(e.into());
        }
    }

    Ok(())
}

fn print_login_success(result: &agyx_core::switcher::LoginResult) {
    println!();
    print_success(&format!(
        "Profile '{}' registered for account: {}",
        result.profile, result.email
    ));
    println!("  Email:    {}", result.email);
    println!("  Sub:      {}", result.sub);
    println!();
    println!(
        "Previous credential has been restored. \
         AGY is now logged in as before."
    );
}
