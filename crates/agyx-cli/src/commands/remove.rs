use crate::output::print_success;
use agyx_core::{adapter::RealAgyAdapter, switcher::Switcher};
use dialoguer::Confirm;

pub fn run(name: &str) -> anyhow::Result<()> {
    let confirm = Confirm::new()
        .with_prompt(format!(
            "Remove profile '{}'? This does not affect the live AGY credential.",
            name
        ))
        .default(false)
        .interact()?;
    if !confirm {
        anyhow::bail!("Remove cancelled.");
    }

    let adapter = RealAgyAdapter::new()?;
    let switcher = Switcher::new(Box::new(adapter));
    switcher.remove(name)?;
    print_success(&format!("Profile '{}' removed.", name));
    Ok(())
}
