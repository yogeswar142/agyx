use agyx_core::{adapter::RealAgyAdapter, switcher::Switcher};

pub fn run(account: Option<&str>, args: &[String]) -> anyhow::Result<()> {
    let adapter = RealAgyAdapter::new()?;
    let switcher = Switcher::new(Box::new(adapter));

    let exit_status = switcher.run(account, args)?;

    // Pass AGY's exit code through.
    let code = exit_status.code().unwrap_or(1);
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}
