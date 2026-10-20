use crate::output::print_warning;
use agyx_core::{
    adapter::{AgyAdapter, RealAgyAdapter},
    switcher::Switcher,
};
use console::style;

pub fn run(name: &str, args: &[String]) -> anyhow::Result<()> {
    let adapter = RealAgyAdapter::new()?;
    let detection = adapter.detect()?;
    if !detection.version_matches {
        print_warning(&format!(
            "AGY version {} is not among tested versions ({}). Proceed with caution.",
            detection.version,
            agyx_core::adapter::SUPPORTED_AGY_VERSIONS.join(", ")
        ));
    }

    let switcher = Switcher::new(Box::new(adapter));

    println!(
        "{} Starting AGY session with account '{}'...",
        style("▶").cyan().bold(),
        style(name).green().bold()
    );

    let exit_status = switcher.start(name, args)?;

    let code = exit_status.code().unwrap_or(1);
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}
