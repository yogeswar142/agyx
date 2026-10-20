use crate::output::{print_field, print_warning};
use agyx_core::{adapter::RealAgyAdapter, switcher::Switcher};
use console::style;

pub fn run() -> anyhow::Result<()> {
    let adapter = RealAgyAdapter::new()?;
    let switcher = Switcher::new(Box::new(adapter));

    match switcher.current()? {
        None => {
            println!("No AGY credential is currently stored in the OS credential store.");
            println!("Run {} to authenticate.", style("agy").bold());
        }
        Some(status) => {
            println!("{}", style("Active AGY account").bold());
            println!("─────────────────────────────────────────────");
            print_field("Email:", &status.email);
            print_field("Sub:", &status.sub);
            match &status.profile {
                Some(name) => {
                    print_field("Profile:", name);
                }
                None => {
                    print_field("Profile:", "UNKNOWN");
                    println!();
                    print_warning("This account is not registered with AGYX.");
                    println!("  Run {} to register it.", style("agyx save <name>").bold());
                }
            }

            let sessions = agyx_core::sessions::load_active_sessions().unwrap_or_default();
            if !sessions.is_empty() {
                println!();
                println!("{}", style("Running Terminal Sessions").bold());
                for s in sessions {
                    println!("  PID {:<7} Profile: {:<12} Started: {}", s.pid, s.profile, s.started_at);
                }
            }
        }
    }

    Ok(())
}
