# AGYX (Antigravity Account Switcher)

AGYX is a fast, secure, cross-platform CLI tool for switching between multiple legitimately authenticated Google accounts for the [Antigravity](https://antigravity.google) CLI (`agy`) without repeating browser login.

---

## Architecture & System Invariants

1. **One Active AGY Credential System-Wide**:
   The installed AGY CLI stores its active session credentials in a single fixed OS location:
   - **Windows**: Windows Credential Manager under Generic Credential `gemini:antigravity` (user: `antigravity`).
   - **macOS**: Keychain under service `gemini`, account `antigravity` (*Not yet verified*).
   - **Linux**: Secret Service (D-Bus) under service `gemini`, account `antigravity` (*Not yet verified*).
2. **AGYX Reads the Live Credential as Source of Truth**:
   AGYX **never assumes** or trusts a local "active profile" flag. Running `agyx current` directly inspects the live credential in the OS credential store and extracts the active account's identity.
3. **AGY Must Be Closed to Switch**:
   AGY holds token state in memory and asynchronously syncs refreshed credentials back to the OS store. To prevent data corruption, race conditions, or session pollution, **AGY must be closed before switching accounts**. AGYX checks the process table and will refuse to switch while `agy.exe` is running (unless restart is confirmed).
4. **Verified Against AGY 1.2.14 on Windows ARM64 Only**:
   > [!IMPORTANT]
   > This release has been verified and tested against `agy` version **1.2.14** running on Windows 11 ARM64 (`aarch64-pc-windows-msvc`, Qualcomm Snapdragon X2).
   > **macOS and Linux builds are provided as unverified builds.** Discovery on those platforms must be performed before running on macOS or Linux.
   > If an unknown or newer AGY version is detected, AGYX emits a prominent warning because credential formats and targets are undocumented internal interfaces that could change across AGY releases.

---

## Security Model & Threat Boundaries

### Vault-Key Threat Model
- **What it protects against**:
  Profile credential blobs are stored in an encrypted vault (`agyx_vault.enc`) using **AES-256-GCM** with random 12-byte nonces. The master key is a random 256-bit key stored in the OS credential store (`agyx:vault-key`). This protects against copied files, cold disk theft, and cloud backup inspection.
- **What it does NOT protect against**:
  It **does NOT protect against malware or malicious scripts running as the same OS user account**. Any process executing with the same user privileges can read Windows Credential Manager and decrypt the vault.

### Opaque Byte Preservation
Credential blobs are treated as **opaque bytes**. AGYX does **not** interpret, modify, normalize, or re-serialize credential blobs during backup, restore, or account switching.
```text
OS Credential Manager ──> Raw Bytes ──> AES-256-GCM Encrypted Vault ──> Raw Bytes ──> OS Credential Manager
```
Unit and integration tests prove that `original bytes == restored bytes` bit-for-bit.

### Account Identification & JWT Signature Limitation
Accounts are identified by decoding the base64url payload of the OpenID Connect `id_token` present in the credential blob to extract `sub` (Google account unique ID) and `email`.
> [!WARNING]
> **The JWT signature is NOT cryptographically verified by AGYX.**
> `sub` and `email` are account identifiers used exclusively for profile matching and display. They are **not a security boundary**. Do not rely on them for authorization or access control decisions.

### Crash-Recovery Journal
Before touching or clearing the live credential during multi-step operations like `agyx login`, AGYX writes an atomic recovery journal (`agyx_journal.json`) to the AGYX data directory. The journal record is removed only after a verified restore. If the process is hard-killed (`taskkill /F`, power loss, or terminal crash), the very next invocation of `agyx` detects the stale journal, restores the prior credential byte-for-byte, and reports loudly to the user.

### Signal Handling (Ctrl+C)
If `Ctrl+C` is pressed while `agyx login` is waiting for user authentication, AGYX catches the interrupt, restores the previous live credential immediately, cleans up the journal, and exits cleanly with code 130.

### Token Redaction
Tokens (`access_token`, `refresh_token`, `id_token`) are **never printed, logged, or exposed in error messages**. Only `email` and `sub` are displayed.

---

## Installation & Setup

### Option 1: Automated Script (`install.ps1`) [Recommended on Windows]
Run the automated installer script from PowerShell:
```powershell
.\install.ps1
```
- Copies `agyx.exe` to `%LOCALAPPDATA%\Programs\agyx\agyx.exe`.
- Adds `%LOCALAPPDATA%\Programs\agyx` to the **User PATH** in `HKCU\Environment` without administrator privileges.
- Preserves the existing `REG_EXPAND_SZ` registry type and avoids the 1024-character truncation of `setx`.
- Idempotent and broadcasts the environment change to all top-level windows.
- Open a fresh terminal window after installation to use `agyx` from anywhere.

To uninstall:
```powershell
.\uninstall.ps1
```
Removes the binary and the exact User PATH entry, leaving your vault, configuration, and credentials untouched. Pass `-PurgeData` if you explicitly want to erase stored profiles after a confirmation prompt.

### Option 2: Cargo Install
If you have the Rust toolchain installed:
```powershell
cargo install --path crates/agyx-cli
```
This places `agyx` in `%USERPROFILE%\.cargo\bin`, which is typically already in your `PATH`.

### Option 3: Download Pre-built Release
Download the archive for your architecture from [GitHub Releases](https://github.com/yogeswar142/agyx/releases):
- **Windows ARM64**: `agyx-v*-aarch64-pc-windows-msvc.zip` (Verified on Snapdragon X2)
- **Windows x64**: `agyx-v*-x86_64-pc-windows-msvc.zip`
- **macOS Apple Silicon**: `agyx-v*-aarch64-apple-darwin-unverified.tar.gz` (Unverified)
- **Linux x64**: `agyx-v*-x86_64-unknown-linux-gnu-unverified.tar.gz` (Unverified)

Every release includes SHA256 checksums (`.sha256`).

> [!NOTE]
> Release binaries are currently unsigned. On Windows, Windows SmartScreen may display an "Unknown Publisher" warning upon first launch. Click **More info** -> **Run anyway**.

---

## Command Reference

| Command | Description | Example |
|---|---|---|
| `agyx save <name>` | Save current AGY account as a named profile without re-login | `agyx save personal` |
| `agyx login <name>` | Log into a new AGY account via browser and save profile | `agyx login college` |
| `agyx switch <name>` | Switch the active AGY account to a saved profile | `agyx switch college` |
| `agyx current` | Inspect and display the active AGY account from OS storage | `agyx current` |
| `agyx accounts` | List all saved profiles in the vault | `agyx accounts` |
| `agyx run [-- <args>]` | Launch AGY with the active account, syncing refreshed tokens | `agyx run -- --help` |
| `agyx rename <old> <new>` | Rename a saved profile | `agyx rename work enterprise` |
| `agyx remove <name>` | Remove a profile from the vault | `agyx remove old-account` |
| `agyx restore-original` | Restore the backup made before AGYX first swapped credentials | `agyx restore-original` |
| `agyx quota` | Check remaining daily/weekly quota for profiles | `agyx quota` |
| `agyx doctor [--redact]` | Check installation, keyring, vault, and system health | `agyx doctor --redact` |

---

## Quick-Start Workflow

### 1. Register Your Current Account
If you are already logged in to your primary Google account in AGY:
```powershell
agyx save personal
```
This reads your live `gemini:antigravity` credential and encrypts it as `personal` without modifying your live session.

### 2. Verify Current & Accounts
```powershell
agyx accounts
agyx current
```

### 3. Add a Second Account
```powershell
agyx login college
```
AGYX launches AGY's login flow. Complete the Google login in your browser for your second account. When finished and you exit AGY, AGYX saves the new account as `college` and restores your `personal` account.

### 4. Switch Accounts
```powershell
# Switch to college
agyx switch college

# Verify active account
agyx current

# Launch AGY with the active account
agyx run
```

### 5. Check System Health
```powershell
agyx doctor
```
Or with masked emails and shortened paths for bug reports:
```powershell
agyx doctor --redact
```

---

## Recovery Procedures

1. **Automatic Journal Restore**:
   If an operation (such as `agyx login`) is terminated unexpectedly (e.g. power loss or process kill), the crash-recovery journal ensures that running *any* `agyx` command will detect the interrupted state and restore your prior credential before doing anything else.
2. **Restore Original Backup**:
   Run `agyx restore-original` at any time to put back the credential snapshot taken before AGYX ever performed its first credential swap.
3. **Emergency AGY Re-Login**:
   If credentials are lost, simply run `agy auth login` directly to re-authenticate cleanly with Google.

---

## License

MIT License.
