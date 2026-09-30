# Security Policy

## Disclaimer & Terms of Use

> **UNOFFICIAL TOOL DISCLAIMER**  
> AGYX is an independent, unofficial community tool. It is **NOT** affiliated with, sponsored by, or endorsed by Google or the Antigravity team.  
> - AGYX is strictly intended for managing multiple legitimately authenticated Google accounts that you own and have authorization to use.
> - AGYX **does not** bypass, circumvent, or manipulate quotas, rate limits, or access controls.
> - AGYX wraps the installed official AGY binary without modifying or patching it.
> - Use at your own risk.

---

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

---

## Reporting a Vulnerability

If you discover a security vulnerability within AGYX, please report it responsibly:
- **Do NOT** open a public GitHub issue.
- Please email security findings or open a private GitHub Security Advisory at:
  `https://github.com/yogeswar142/agyx/security/advisories`

We appreciate your responsible disclosure and will investigate and address reported vulnerabilities promptly.

---

## Security Model Summary

- **Local Storage**: Account profiles are encrypted at rest using **AES-256-GCM**.
- **Master Key**: The vault key is held in your operating system's credential store (Windows Credential Manager).
- **Threat Boundary**: Protects against copied files, cold disk theft, and backups. Does **not** protect against malware running under the same OS user account.
- **Redaction**: Access tokens, refresh tokens, and JWT credentials are never printed or logged.
