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
   > **macOS and Linux backends are NOT implemented or verified yet.** Discovery on those platforms must be performed before running on macOS or Linux.
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

## Command Roles

AGYX maintains a strict separation between registering an already-authenticated account and adding a new one:

| Command | Role | Impact on Live Session |
|---|---|---|
| `agyx save <name>` | Registers the **currently logged-in** AGY account as a named profile. | **ZERO IMPACT**. The live credential is never modified, rewritten, or touched. |
| `agyx login <name>` | Runs AGY's authentication flow to log in to a **NEW** Google account. | Temporarily swaps credentials; restores the prior live account upon completion or interruption. |
| `agyx switch <name>` | Switches the live AGY session to the named profile. | Replaces `gemini:antigravity` with the stored profile blob. |
| `agyx current` | Shows who is active right now. | Reads live OS credential (never reads a cached flag). |
| `agyx restore-original` | Emergency recovery of pre-AGYX credential. | Restores pre-swap backup byte-for-byte. |

---

## Installation (Windows ARM64 / x64)

### Build from Source
```powershell
git clone https://github.com/yogeswar142/agyx.git
cd agyx
cargo build --release
```
The compiled self-contained binary is located at `target\release\agyx.exe`.

Add `target\release` to your `PATH`, or copy `agyx.exe` to a folder in your `PATH` (e.g. `C:\Users\<user>\AppData\Local\agy\bin`).

---

## Usage Workflow

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

### 5. Quota (Phase 1 Status)
```powershell
agyx quota
```
Reports `"unknown"` honestly. AGY 1.2.14 does not expose any public CLI command or flag for quota.

---

## License

MIT License.
