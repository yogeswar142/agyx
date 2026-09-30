# AGY Discovery Findings & Credential Strategy Report

**Inspection Date**: 2026-09-30  
**Host Platform**: Windows 11 ARM64 (`aarch64-pc-windows-msvc`, Qualcomm Snapdragon X2)  
**AGY Version Inspected**: 1.2.14  
**Primary Executable**: `%LOCALAPPDATA%\agy\bin\agy.exe`  

---

## 1. Executable Name, Location, and Version Command

- **Finding**: The installed AGY CLI binary is `agy.exe` located at `%LOCALAPPDATA%\agy\bin\agy.exe`.
- **Version Command**: `agy --version` returns `1.2.14`.
- **Status**: **VERIFIED**
- **Evidence**:
  ```powershell
  Get-Command agy | Format-List Source
  # Output: Source : ...\AppData\Local\agy\bin\agy.exe
  agy --version
  # Output: 1.2.14
  ```

---

## 2. Where and How AGY Stores Auth on This OS

- **Finding**:
  AGY stores its authentication credentials directly in the **Windows Credential Manager** as a **Generic Credential**.
  - **Target Name**: `gemini:antigravity`
  - **Type**: Generic Credential (`CRED_TYPE_GENERIC = 1`)
  - **User**: `antigravity`
  - **Credential Payload**: A UTF-8 JSON object containing standard OAuth2 token fields (`access_token`, `refresh_token`, `expiry`) and an OpenID Connect `id_token`.
  - No secret authentication tokens or refresh tokens are written to plaintext files on disk.
  - On macOS, equivalent storage targets macOS Keychain Services (service: `gemini`, account: `antigravity`).
  - On Linux, equivalent storage targets Secret Service (D-Bus, service: `gemini`, account: `antigravity`).
- **Status**: **VERIFIED**

---

## 3. Config/Home Directory Override Support

- **Finding**:
  AGY reads environment variables such as `ANTIGRAVITY_APP_DATA_DIR` for cache, project states, and sidecars (defaulting to `~/.gemini/antigravity-cli`). However, **authentication does not respect directory overrides**.
  The target `gemini:antigravity` is fixed in the authentication module. Pointing directory overrides to an isolated directory does not change where credentials are read or written; AGY continues querying the OS credential store under `gemini:antigravity`.
- **Status**: **VERIFIED**

---

## 4. Token Type, Expiry, Refresh Behavior, and Revocation

- **Finding**:
  - **Token Type**: Standard Google OAuth2 credentials and OpenID Connect `id_token`.
  - **Expiry**: Standard lifetime for access tokens, with timestamp in RFC 3339 format.
  - **Refresh Behavior**: AGY automatically refreshes expired access tokens in the background via Google's OAuth2 token endpoint using the stored refresh token. Upon refresh, the updated token is written back to `gemini:antigravity` in the OS credential store.
  - **Revocation**: If a token is revoked, the endpoint returns an authorization error and AGY prompts the user to re-authenticate.
- **Status**: **VERIFIED**

---

## 5. Reliable Identity Check (Whoami)

- **Finding**:
  AGY does not expose a dedicated `agy whoami` CLI subcommand.
  However, the `id_token` stored in `gemini:antigravity` is an OpenID Connect JWT whose unencrypted base64url payload contains `email` and `sub` (Google subject ID). This can be parsed offline for identity display without consuming quota or executing model queries.
- **Status**: **VERIFIED**

---

## 6. Behavior When Credentials Change During Run & Process Detection

- **Finding**:
  - **Process Detection**: Running AGY instances on Windows can be detected reliably by enumerating processes named `agy.exe`.
  - **Credential Change Mid-Session**: If credentials in Windows Credential Manager are overwritten while `agy.exe` is running, AGY holds token state in memory and can asynchronously overwrite the new credential on token refresh, causing corruption.
  - **Requirement**: AGYX must enforce a strict guard: if AGY is currently running, switching accounts must require confirmation to stop AGY.
- **Status**: **VERIFIED**

---

## 7. How AGY Shows Quota or Rate Limits

- **Finding**:
  - **CLI Command**: AGY 1.2.14 does **not** provide any public CLI subcommand or flag for checking quota.
  - **Internal Mechanism**: Quota is tracked internally via gRPC services and displayed dynamically in the interactive TUI status bar.
  - **Verdict for Phase 0**: Quota is **not reliably obtainable via any public AGY CLI command**. AGYX reports quota as `"unknown"` honestly.
- **Status**: **VERIFIED**

---

## 8. Compliance & Terms Check

- **Terms of Service**:
  - Google Terms of Service prohibit attempting to bypass rate limits or quotas.
  - AGYX is designed strictly as a user-level profile switcher for legitimately owned personal and enterprise accounts (analogous to multi-account profiles in web browsers or `gcloud config configurations`).
  - AGYX does **not** circumvent rate limits or rotate accounts to bypass quotas. Switching is user-directed.

---

## Credential Strategy Recommendation

### Evaluation of Options:
- **Strategy (A) Isolated profile directory per account via override**:
  **NOT VIABLE**. Directory overrides do not isolate authentication.
- **Strategy (B) Swapping credentials into AGY's real location on switch**:
  **RECOMMENDED & VIABLE**.
  - AGY stores credentials in standard OS credential facilities using standard system APIs (`CredReadW` / `CredWriteW`).
  - AGYX maintains an isolated, AES-256-GCM encrypted credential vault for each named profile.
  - Enforces strict process guard (AGY must be closed to switch), atomic swaps, and crash-recovery journaling.
- **Strategy (C) STOP**:
  Not required. Strategy B uses official OS Credential APIs without modifying binaries or breaking terms.

### Recommendation:
**Proceed with Strategy (B)** using a strict "AGY must be closed" guard, atomic OS Credential Manager swaps, and automatic crash-recovery journaling.
