# Secure Vault

A local, offline-first password manager and encrypted file vault for Windows. No cloud, no accounts, no telemetry — your data never leaves your machine.

Built with Rust (Axum backend, embedded frontend via `rust-embed`). Single ~3 MB executable, no installer required.

---

## Features

### Passwords & Credentials
- AES-256-GCM encryption with Argon2id key derivation
- Unlimited vaults — local or shared (network path)
- Categories with custom icons and colors
- Password strength scoring and health dashboard (weak, reused, expiring)
- Password history (last 5 per entry)
- TOTP / 2FA code generation built into entries
- Password generator — random or passphrase mode
- Drag-and-drop import (CSV, Bitwarden JSON, LastPass CSV)
- Export to CSV or JSON
- Vault merge (combine two vaults, skip duplicates)
- Breach check via Have I Been Pwned (k-anonymity — password never sent)

### Encrypted Files
- Files stored as encrypted entries inside the vault alongside passwords
- AES-256-GCM encrypted — same key, same file, same backup
- Organized by category (store files in "Home", "Work", etc. with your other entries)
- Upload via topbar button or drag-and-drop
- Download decrypts in memory — nothing plaintext on disk
- File type icons auto-detected from MIME type

### Security
- Two-factor authentication: TOTP (authenticator app), Email OTP, WebAuthn (security key)
- Backup codes for TOTP
- PIN quick-unlock (re-unlock after auto-lock without full password)
- Auto-lock on inactivity (configurable 5 min – never)
- Activity log per session
- Shared vault file locking (safe concurrent access on network shares)

### App
- Single `.exe` — no installer, no dependencies
- No CMD window (`windows_subsystem = "windows"`)
- Auto-quits ~10 seconds after closing the browser tab
- Duplicate instance detection — second launch opens existing session in browser
- Light / dark mode, custom accent color
- Keyboard shortcuts throughout

---

## Usage

1. Double-click `Vault.exe`
2. Your default browser opens to `http://127.0.0.1:7474`
3. Create a vault (first run) or unlock an existing one
4. Use **Quit** in the sidebar or close the tab (auto-quits in ~10s)

Vault files are stored wherever you choose. Default path is next to the exe. For a shared vault, point multiple machines at the same network path.

---

## Building from Source

**Prerequisites:** [Rust](https://rustup.rs/) (stable)

```bash
git clone https://github.com/ChrisMangin/secure-vault
cd secure-vault
cargo build --release
# Output: target/release/Vault.exe
```

---

## Data & Privacy

- All vault data is encrypted at rest using AES-256-GCM
- Key derived with Argon2id (t=3, m=65536, p=4) — same parameters as the original Python version, so existing vaults open without migration
- Server binds to `127.0.0.1` (loopback only) — not accessible from other machines
- No analytics, no update checks, no network calls except the optional breach check (k-anonymity, opt-in per entry)

---

## Vault File Format

```json
{
  "version": 2,
  "salt": "<base64 Argon2id salt>",
  "nonce": "<base64 AES-GCM nonce>",
  "ciphertext": "<base64 encrypted payload>"
}
```

The decrypted payload contains `entries`, `categories`, `settings`, and any uploaded file data — all in one file.

---

## License

MIT
