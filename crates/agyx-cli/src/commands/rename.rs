use crate::output::print_success;
use agyx_core::{adapter::RealAgyAdapter, switcher::Switcher};

pub fn run(old: &str, new: &str) -> anyhow::Result<()> {
    let adapter = RealAgyAdapter::new()?;
    let switcher = Switcher::new(Box::new(adapter));
    switcher.rename(old, new)?;
    print_success(&format!("Renamed profile '{}' → '{}'", old, new));
    Ok(())
}
