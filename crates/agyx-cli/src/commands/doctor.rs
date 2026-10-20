use agyx_core::{
    adapter::RealAgyAdapter,
    doctor::{run_doctor, CheckStatus},
};
use console::style;

pub fn run(redact: bool) -> anyhow::Result<()> {
    if redact {
        println!("{} (Redacted mode)", style("AGYX System Doctor").bold().cyan());
    } else {
        println!("{}", style("AGYX System Doctor").bold().cyan());
    }
    println!("─────────────────────────────────────────────────────────────────────────────");

    let adapter = RealAgyAdapter::new()?;
    let report = run_doctor(&adapter, redact);

    for check in &report.checks {
        let badge = match check.status {
            CheckStatus::Pass => style("[ PASS ]").green().bold(),
            CheckStatus::Warn => style("[ WARN ]").yellow().bold(),
            CheckStatus::Fail => style("[ FAIL ]").red().bold(),
        };

        println!("{} {:<25} {}", badge, style(&check.name).bold(), check.message);
    }

    println!("─────────────────────────────────────────────────────────────────────────────");
    match report.overall_status {
        CheckStatus::Pass => {
            println!(
                "{} Your AGYX environment is healthy and ready to use.",
                style("✓ All checks passed.").green().bold()
            );
        }
        CheckStatus::Warn => {
            println!(
                "{} Review the warning messages above.",
                style("▲ System operational with warnings.").yellow().bold()
            );
        }
        CheckStatus::Fail => {
            println!(
                "{} Fix the failed components above before continuing.",
                style("✗ One or more critical checks failed.").red().bold()
            );
        }
    }

    Ok(())
}
