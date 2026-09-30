//! agyx — multi-account AGY manager CLI.
//!
//! This is a thin command-dispatching layer over `agyx-core`.
//! All business logic lives in `agyx-core`.

mod commands;
mod output;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "agyx",
    about = "Cross-platform multi-account switcher for the AGY CLI",
    long_about = "\
AGYX manages multiple already-authenticated AGY CLI accounts, switches between \
them without repeating Google browser login, and launches your installed AGY binary \
with the selected account.\n\n\
Credential blobs are treated as opaque bytes and encrypted with AES-256-GCM. \
The master key is held in your OS Credential Store (Windows Credential Manager). \
Tokens are never printed or logged.",
    after_help = "\
QUICK-START WORKFLOW:
  1. agyx save personal       Register your already-authenticated account as 'personal'
  2. agyx login college       Authenticate a 2nd Google account in AGY as 'college'
  3. agyx accounts            List all registered profiles and view active status
  4. agyx switch personal     Swap active OS credential to 'personal'
  5. agyx run                 Launch AGY using the selected account
  6. agyx current             Inspect live active account in OS store

COMMAND SUMMARY:
  save <name>                 Save currently active account as a profile (zero live modification)
  login <name>                Perform a new AGY authentication flow for an additional account
  accounts, ls                List all saved accounts and mark active profile
  current                     Show live account in OS credential store (source of truth)
  switch <name>               Switch live AGY credentials to the specified profile
  run [-a <name>] [-- <args>] Launch AGY with active or specified profile, syncing refreshed tokens
  doctor                      Run system health and environment diagnostics
  rename <old> <new>          Rename a saved profile
  remove <name>, rm           Delete a profile from the vault (leaves live session untouched)
  restore-original            Restore the original pre-AGYX credential backup
  quota                       Show quota status (Phase 1: reports 'unknown')
  version                     Display version, tested target, and executable path

RECOVERY:
  • Journal Auto-Restore: Interrupted operations (power failure, taskkill /F, terminal crash)
    write a journal record to disk before modifying credentials. Any subsequent agyx command
    automatically detects the journal and restores your prior credential byte-for-byte.
  • Pre-AGYX Backup: 'agyx restore-original' restores the backup captured before your first swap.
  • Native AGY Re-Login: AGYX never alters AGY binaries or Google servers. You can run 'agy'
    directly at any time to re-authenticate normally.

LIMITATIONS & SAFETY:
  • One Active Account: Only one AGY credential slot exists system-wide (target 'gemini:antigravity').
  • AGY Must Be Closed: AGY must be closed before switching to avoid token overwrite and race conditions.
  • Platform Support: Verified against AGY 1.2.14 on Windows ARM64 (Qualcomm Snapdragon X2).
    macOS and Linux backends are unverified stubs pending Phase 2 discovery.
  • Non-Cryptographic Identity: OIDC id_token sub/email are parsed for identification only;
    JWT signatures are NOT verified. Do not use them as a security boundary.
  • Zero Token Leakage: Access tokens, refresh tokens, and JWTs are never printed or logged.",
    version,
)]
struct Cli {
    /// Enable verbose debug output.
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Register the currently logged-in AGY account as a named profile without re-authenticating.
    #[command(
        long_about = "\
Registers the currently logged-in AGY account as a named profile without re-authenticating.\n\n\
Reads the live credential as opaque raw bytes, decodes a read-only copy solely to extract \
email and sub for identification, and encrypts the blob into the vault. The live AGY \
credential is NEVER modified, deleted, or rewritten.",
        after_help = "EXAMPLES:\n  agyx save personal\n  agyx save work"
    )]
    Save {
        /// Profile name (e.g. 'personal', 'college').
        name: String,
    },

    /// Authenticate a new account via AGY and save it as a named profile.
    #[command(
        long_about = "\
Authenticates a NEW account via AGY and saves it as a named profile.\n\n\
Launches AGY's native authentication flow. Before touching credentials, AGYX writes a \
crash-recovery journal and backs up the prior credential. Once authentication completes, \
AGYX saves the new profile and restores your prior account. Handles Ctrl+C and crash recovery.",
        after_help = "EXAMPLES:\n  agyx login college\n  agyx login work-secondary"
    )]
    Login {
        /// Profile name (e.g. 'personal', 'college').
        name: String,
    },

    /// List all registered profiles.
    #[command(
        alias = "ls",
        long_about = "\
Lists all registered profiles stored in the AGYX vault, showing profile names, emails, \
Google subs, and which profile is currently active in the OS credential store.",
        after_help = "EXAMPLES:\n  agyx accounts\n  agyx ls"
    )]
    Accounts,

    /// Show the currently active AGY account (reads live OS credential).
    #[command(
        long_about = "\
Inspects the live OS credential (gemini:antigravity) as the sole source of truth and \
reports the active account identity. Never assumes or trusts a cached 'active profile' flag.",
        after_help = "EXAMPLES:\n  agyx current"
    )]
    Current,

    /// Switch the live AGY credential to a named profile.
    #[command(
        long_about = "\
Swaps the live AGY credential to the specified profile.\n\n\
AGY must be closed before switching to prevent session corruption and mid-flight token \
overwrites. Checks the process table and prompts if AGY is running.",
        after_help = "EXAMPLES:\n  agyx switch personal\n  agyx switch college"
    )]
    Switch {
        /// Profile name to switch to.
        name: String,
    },

    /// Launch AGY, optionally with a specific account.
    #[command(
        long_about = "\
Launches AGY with the active account (or switches to a specified account first), \
passing through stdin, stdout, and exit codes. Automatically syncs any refreshed \
tokens back to the vault after AGY exits (only if sub matches).",
        after_help = "EXAMPLES:\n  agyx run\n  agyx run --account college\n  agyx run -- --prompt \"Explain this code\"\n  agyx run -a personal -- models"
    )]
    Run {
        /// Switch to this profile before launching.
        #[arg(short, long, value_name = "NAME")]
        account: Option<String>,

        /// Arguments to pass through to AGY.
        #[arg(last = true, value_name = "AGY_ARGS")]
        args: Vec<String>,
    },

    /// Run diagnostic health checks on AGY, OS credential store, and vault.
    #[command(
        long_about = "\
Runs comprehensive health checks on AGY installation, version compatibility, \
Windows Credential Manager access, vault encryption, recovery journal, file locking, \
and PATH setup. Never prints secrets.",
        after_help = "EXAMPLES:\n  agyx doctor"
    )]
    Doctor,

    /// Rename a profile.
    #[command(
        long_about = "Renames a saved profile in the vault and config file atomically.",
        after_help = "EXAMPLES:\n  agyx rename old-name new-name"
    )]
    Rename {
        /// Current profile name.
        old: String,
        /// New profile name.
        new: String,
    },

    /// Remove a profile (does not affect the live credential).
    #[command(
        alias = "rm",
        long_about = "Removes a profile from the AGYX vault and config. Does not affect the live AGY credential in the OS store.",
        after_help = "EXAMPLES:\n  agyx remove college\n  agyx rm test-profile"
    )]
    Remove {
        /// Profile name to remove.
        name: String,
    },

    /// Restore the original AGY credential from the encrypted backup.
    #[command(
        long_about = "\
Restores the original pre-AGYX credential that was captured before the first account swap. \
Verifies sub match and requires AGY to be closed.",
        after_help = "EXAMPLES:\n  agyx restore-original"
    )]
    RestoreOriginal,

    /// Show quota information (Phase 2 — currently reports 'unknown').
    #[command(
        long_about = "\
Shows quota information. In Phase 1, reports 'unknown' honestly because AGY 1.2.14 does not \
expose a public CLI quota interface. Phase 2 will investigate safe options.",
        after_help = "EXAMPLES:\n  agyx quota"
    )]
    Quota,

    /// Check the AGY version and AGYX adapter compatibility.
    #[command(
        long_about = "Displays AGYX version, detected AGY version, tested version (1.2.14), executable path, and OS platform/architecture.",
        after_help = "EXAMPLES:\n  agyx version"
    )]
    Version,
}

fn main() {
    let cli = Cli::parse();

    // Set up tracing: AGYX_LOG or --verbose.
    let filter = if cli.verbose {
        "agyx=debug,agyx_core=debug"
    } else {
        "agyx=info,agyx_core=warn"
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("AGYX_LOG")
                .unwrap_or_else(|_| EnvFilter::new(filter)),
        )
        .without_time()
        .with_target(false)
        .init();

    let result = dispatch(cli);
    if let Err(e) = result {
        output::print_error(&e);
        std::process::exit(1);
    }
}

fn dispatch(cli: Cli) -> anyhow::Result<()> {
    // Startup check: detect and recover from any stale crash-recovery journal
    if let Ok(adapter) = agyx_core::adapter::RealAgyAdapter::new() {
        if let Ok(Some(recovery)) = agyx_core::journal::check_and_recover_journal(&adapter) {
            eprintln!("{}", console::style("CRITICAL RECOVERY NOTICE").yellow().bold());
            eprintln!(
                "Detected an interrupted AGYX session from {} (operation: '{}').",
                recovery.timestamp, recovery.original_action
            );
            eprintln!(
                "The original AGY credential has been safely restored (email: {}, sub: {}).",
                recovery.original_email.as_deref().unwrap_or("unknown"),
                recovery.original_sub.as_deref().unwrap_or("unknown")
            );
            eprintln!();
        }
    }

    match cli.command {
        Commands::Save { name } => commands::save::run(&name),
        Commands::Login { name } => commands::login::run(&name),
        Commands::Accounts => commands::accounts::run(),
        Commands::Current => commands::current::run(),
        Commands::Switch { name } => commands::switch::run(&name),
        Commands::Run { account, args } => commands::run_agy::run(account.as_deref(), &args),
        Commands::Doctor => commands::doctor::run(),
        Commands::Rename { old, new } => commands::rename::run(&old, &new),
        Commands::Remove { name } => commands::remove::run(&name),
        Commands::RestoreOriginal => commands::restore::run(),
        Commands::Quota => commands::quota::run(),
        Commands::Version => commands::version::run(),
    }
}
