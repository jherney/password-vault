---
description: "One encrypted local vault I control, usable from terminal or GUI, still openable in KeePass-compatible apps"
type: Project
about: "pwvault"
---

# pwvault

## What This Is

A small, local password manager whose vault is a standard KeePass (`.kdbx`) file, with a command-line interface and a Tkinter GUI sharing the same vault. This round of work hardens the existing app, adds TOTP codes and automatic versioned backups, publishes it to PyPI with a desktop launcher, and polishes the GUI.

## Core Value

I can keep all my passwords in one encrypted local vault that I control, use it from the terminal or a GUI, and still open it in KeePass-compatible apps.

## Current State

| Attribute | Value |
|-----------|-------|
| Type | Application |
| Version | 1.2.0 |
| Status | Production (personal use) |
| Last Updated | 2026-10-30 |

## Requirements

### Core Features

- **Hardening:** continue QA-driven fixes (data-loss and key-file edge cases), broaden tests, security review of changes
- **TOTP/2FA codes:** store and generate TOTP in entries via KeePassXC's standard `otp` attribute (CLI and GUI)
- **Automatic versioned backups:** back up before every save, keep last N, restore from backup
- **Packaging/release:** publish to PyPI; `.desktop` launcher with icon for the GUI
- **GUI polish:** modernized Tkinter look, search, keyboard shortcuts

### Validated (Shipped)

- [x] KDBX 4 vault (AES-256, Argon2d), password and/or key file unlock — 1.2.0
- [x] Groups, entry history, recycle bin, expiry, attachments — 1.2.0
- [x] CSV import (browser, KeePass, Bitwarden, LastPass, 1Password); export CSV/HTML/XML/TXT — 1.2.0
- [x] Password generator, self-clearing clipboard, auto-lock — 1.2.0
- ✓ Automatic versioned backups: previous vault kept before every save (last 10), `pwvault backup list|restore`, old-key backups purged after re-key — Phase 1
- ✓ Failed or interrupted saves never corrupt the vault (fault-injection tested) — Phase 1

### Active (In Progress)

- ✓ TOTP/2FA codes via KeePassXC's `otp` attribute (CLI and GUI, RFC 6238 generator) — Phase 2

### Planned (Next)

- To be defined during /paul:plan

### Out of Scope

- Browser integration — deferred to a later milestone
- Folder sync with conflict merge — deferred; backups first
- Passkeys — complex, poor Python library support

## Constraints

### Technical Constraints

- Vaults must stay openable in KeePassXC; no proprietary fields (TOTP uses the standard `otp` attribute)
- No new runtime dependencies unless essential (TOTP via stdlib `hmac`/`base64`)
- Linux first; CI covers Python 3.10–3.14
- `lxml` >= 5.0 required (older versions resolve external XML entities)

### Business Constraints

- Personal project, no deadline

### Compliance Constraints

- No data-loss risk: backups before every save, writes stay atomic

## Key Decisions

| Decision | Rationale | Date | Status |
|----------|-----------|------|--------|
| Scope v1.3 to TOTP + backups among new features | Smallest high-value slice; browser/sync/passkeys deferred | 2026-10-30 | Active |
| Packaging targets: PyPI + `.desktop` launcher | Lowest-effort distribution; RPM/Flatpak later | 2026-10-30 | Active |
| Implement TOTP with stdlib | Avoid new dependencies in a security tool | 2026-10-30 | Active |
| Delete old-key backups after a verified re-key | A leaked old password mustn't open leftover backups | 2026-10-30 | Active |
| Every vault write goes through `Vault._write()` | One place for lock, conflict check, backup and atomic write | 2026-10-30 | Active |

## Success Metrics

| Metric | Target | Current | Status |
|--------|--------|---------|--------|
| CI test suite | All existing + new tests pass | 126 passing | On track |
| TOTP interoperability | Codes match KeePassXC for same entry | RFC vectors + phone check pass; real KeePassXC not run here | Met (partial evidence) |
| Save safety | Failed/interrupted save never corrupts vault; last N backups restorable | Met (Phase 1) | ✓ |
| Distribution | `pip install pwvault` from PyPI; GUI in desktop app menu | - | Not started |
| Security review | `/cso` finds no high-severity issues in changes | - | Not started |

## Tech Stack / Tools

| Layer | Technology | Notes |
|-------|------------|-------|
| Language | Python 3.10+ | Single-module CLI (`pwvault.py`) and GUI (`pwvault_gui.py`) |
| Vault format | KDBX 4 via `pykeepass` 4.2.0 | Pinned version |
| XML | `lxml` >= 5.0 | Security requirement |
| GUI | Tkinter | `python3-tk` on Fedora/Debian |
| Packaging | setuptools (`pyproject.toml`) | Entry points `pwvault`, `pwvault-gui` |
| CI | GitHub Actions (`.github/workflows/tests.yml`) | |
| Legacy migration | `cryptography` >= 42 (optional extra) | `.pwv` → `.kdbx` only |

## Links

| Resource | URL |
|----------|-----|
| Repository | https://github.com/jherney/password-vault |

---
*Created: 2026-10-30*
*Last updated: 2026-10-30 after Phase 2*
