use console::style;

pub fn run() -> anyhow::Result<()> {
    println!("{}", style("agyx quota").bold());
    println!("─────────────────────────────────────────────");
    println!("  Status:   {}", style("unknown").yellow());
    println!();
    println!("Reason: AGY CLI (tested up to 1.3.2) does not expose a public command or flag for");
    println!("quota checking. Quota is managed internally via gRPC and shown only");
    println!("in AGY's interactive TUI status bar. No reliable programmatic interface");
    println!("was found during discovery.");
    println!();
    println!("Phase 2 will investigate and report options and risks before any");
    println!("implementation. No calls to internal AGY gRPC endpoints without");
    println!("explicit approval.");
    Ok(())
}
