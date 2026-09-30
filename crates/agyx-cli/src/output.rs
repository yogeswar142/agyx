use console::style;

/// Print an error in a consistent, readable format.
pub fn print_error(err: &anyhow::Error) {
    eprintln!("{} {:#}", style("Error:").red().bold(), err);
}

/// Print a success banner.
pub fn print_success(msg: &str) {
    println!("{} {}", style("✓").green().bold(), msg);
}

/// Print a warning.
pub fn print_warning(msg: &str) {
    eprintln!("{} {}", style("Warning:").yellow().bold(), msg);
}

/// Print a table row with a label and value.
pub fn print_field(label: &str, value: &str) {
    println!("  {:<14} {}", style(label).dim(), value);
}

/// Print an account info block.
pub fn print_account_block(
    name: &str,
    email: &str,
    sub: &str,
    is_active: bool,
) {
    let bullet = if is_active {
        style("●").cyan().bold()
    } else {
        style("○").dim()
    };
    let active_label = if is_active { "  (active)" } else { "" };
    println!("{} {}{}", bullet, style(name).bold(), style(active_label).cyan());
    println!("    Email:  {}", email);
    println!("    Sub:    {}", sub);
}
