use crate::output::print_success;
use agyx_core::{
    adapter::RealAgyAdapter,
    switcher::Switcher,
    AgyxError,
};
use console::style;

pub fn run(name: &str) -> anyhow::Result<()> {
    let adapter = RealAgyAdapter::new()?;
    let switcher = Switcher::new(Box::new(adapter));

    match switcher.save(name) {
        Ok(result) => {
            print_success(&format!(
                "Profile '{}' registered for currently logged-in account:",
                result.profile
            ));
            println!("  Email:    {}", result.email);
            println!("  Sub:      {}", result.sub);
            println!();
            println!(
                "{} Live AGY credential was not modified.",
                style("✓").green().bold()
            );
        }
        Err(AgyxError::NoAgyCredential) => {
            anyhow::bail!(
                "No live AGY credential found in the OS credential store.\n\
                 Log in with AGY first (`agy`), or run `agyx login {}`.",
                name
            );
        }
        Err(AgyxError::ProfileAlreadyExists { name }) => {
            anyhow::bail!(
                "A profile named '{}' already exists. Choose a different name or remove it first.",
                name
            );
        }
        Err(AgyxError::AccountAlreadyRegistered { sub, profile }) => {
            anyhow::bail!(
                "The currently active account (sub: {}) is already registered as profile '{}'.",
                sub,
                profile
            );
        }
        Err(e) => return Err(e.into()),
    }

    Ok(())
}
