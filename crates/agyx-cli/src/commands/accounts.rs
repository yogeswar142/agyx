use crate::output::{print_account_block, print_warning};
use agyx_core::{adapter::RealAgyAdapter, switcher::Switcher};
use console::style;

pub fn run() -> anyhow::Result<()> {
    let adapter = RealAgyAdapter::new()?;
    let switcher = Switcher::new(Box::new(adapter));

    let accounts = switcher.accounts()?;
    let current = switcher.current()?;
    let active_sub = current.as_ref().map(|c| c.sub.as_str());

    if accounts.is_empty() {
        if current.is_some() {
            println!(
                "No profiles registered. Run {} to register your current account.",
                style("agyx save <name>").bold()
            );
        } else {
            println!(
                "No profiles registered. Run {} to authenticate and add one.",
                style("agyx login <name>").bold()
            );
        }
        return Ok(());
    }

    println!("{}", style("Registered profiles").bold());
    println!("─────────────────────────────────────────────");
    for acc in &accounts {
        let is_active = active_sub.map(|s| s == acc.sub).unwrap_or(false);
        print_account_block(&acc.name, &acc.email, &acc.sub, is_active);
        println!();
    }

    if let Some(live) = &current {
        if live.profile.is_none() {
            print_warning(
                "The currently active AGY account is not registered with AGYX.",
            );
            println!(
                "  Run {} to save it as a profile.",
                style("agyx save <name>").bold()
            );
        }
    }

    Ok(())
}
