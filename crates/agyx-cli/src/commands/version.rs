use crate::output::print_warning;
use agyx_core::adapter::{AgyAdapter, RealAgyAdapter, SUPPORTED_AGY_VERSIONS};
use console::style;

pub fn run() -> anyhow::Result<()> {
    let adapter = RealAgyAdapter::new()?;
    let detection = adapter.detect()?;

    println!("{}", style("AGYX Version Information").bold());
    println!("─────────────────────────────────────────────");
    println!("  AGYX version:     {}", env!("CARGO_PKG_VERSION"));
    println!("  AGY version:      {}", detection.version);
    println!("  Tested against:   {}", SUPPORTED_AGY_VERSIONS.join(", "));
    println!("  AGY path:         {}", detection.exe_path.display());
    println!("  Platform:         {}", std::env::consts::OS);
    println!("  Architecture:     {}", std::env::consts::ARCH);

    if !detection.version_matches {
        println!();
        print_warning(&format!(
            "AGY version {} has not been tested with this build of AGYX.\n  \
             Tested versions: {}\n  \
             Credential format changes in newer versions could cause issues.\n  \
             Proceed carefully and report any problems.",
            detection.version,
            SUPPORTED_AGY_VERSIONS.join(", ")
        ));
    } else {
        println!();
        println!("{} AGY version is compatible.", style("✓").green().bold());
    }

    Ok(())
}
