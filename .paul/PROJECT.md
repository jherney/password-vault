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
| Version | 1.3.0 (1.4 in progress) |
| Status | Production (personal use) |
| Last Updated | 2026-11-05 |

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
- ✓ TOTP/2FA codes via KeePassXC's `otp` attribute (CLI and GUI, RFC 6238 generator) — Phase 2
- ✓ Database > Backups dialog (Ctrl+Shift+B): list backups newest first, restore after confirmation — Phase 3
- ✓ Light and dark palettes following the desktop setting, with a Theme button that applies live — Phase 3
- ✓ WCAG contrast checked for both palettes; consistent label spacing in dialogs — Phase 3
- ✓ PyPI release `pwvault-manager` 1.3.0 and desktop launcher — Phase 5
- ✓ Merge two copies of a vault, KeePassXC-compatible (UUID match, history, moves, recycle bin, permanent deletions): `pwvault merge` and GUI Database > Merge another copy… — Phase 6
- ✓ Permanent deletes recorded in DeletedObjects and moves stamp LocationChanged, so they carry over in merges here and in KeePassXC — Phase 6
- ✓ Offline check for breached, reused and weak passwords: local HIBP Pwned Passwords store (resumable download or import, ~16 GB, integrity-checked), `pwvault check`, `pwvault breach update|import|status`, GUI Database > Check passwords…; no network use during a check — Phase 8
- ✓ YubiKey HMAC-SHA1 challenge-response as part of the master key, KeePassXC-compatible (CLI `--yubikey`, GUI slot choice remembered per vault); proven against KeePassXC's own YubiKey test vault, not yet with a physical key — Phase 7

### Active (In Progress)

- v1.4 Daily-driver gaps: Phase 9 browser autofill is next

### Planned (Next)

- Phase 9: browser autofill (WebExtension + native messaging)

### Out of Scope

- Automatic folder sync or watching for conflict files — merge is manual (`pwvault merge` / GUI); browser integration moved into v1.4 Phase 9
- Passkeys — complex, poor Python library support

## Constraints

### Technical Constraints

- Vaults must stay openable in KeePassXC; no proprietary fields (TOTP uses the standard `otp` attribute)
- No new runtime dependencies unless essential (TOTP via stdlib `hmac`/`base64`)
- Linux first; CI covers Python 3.10–3.14
- `lxml` >= 6.1 required (older versions resolve external XML entities; GHSA-vfmq-68hx-4jfw fixed in 6.1.0)

### Business Constraints

- Personal project, no deadline

### Compliance Constraints

- No data-loss risk: backups before every save, writes stay atomic

## Key Decisions

| Decision | Rationale | Date | Status |
|----------|-----------|------|--------|
| Scope v1.3 to TOTP + backups among new features | Smallest high-value slice; browser/sync/passkeys deferred | 2026-10-30 | Active |
| v1.4 closes daily-driver gaps in Python on pykeepass (merge, YubiKey, breach check, browser autofill); no Rust rewrite or custom crypto | Keeps audited KDBX crypto and KeePassXC compatibility | 2026-11-05 | Active |
| Packaging targets: PyPI + `.desktop` launcher | Lowest-effort distribution; RPM/Flatpak later | 2026-10-30 | Active |
| Implement TOTP with stdlib | Avoid new dependencies in a security tool | 2026-10-30 | Active |
| Delete old-key backups after a verified re-key | A leaked old password mustn't open leftover backups | 2026-10-30 | Active |
| Merge applies permanent deletions (KeePassXC Synchronize rules), unlike KeePassXC's default KeepNewer merge | Two-device use must not bring deleted passwords back | 2026-11-05 | Active |
| License GPL-3.0-or-later from 1.4 (was MIT; 1.3.0 and earlier stay MIT) | Matches pykeepass (GPL-3.0) and lets KeePassXC's GPL test data live in the repo | 2026-11-05 | Active |
| Every vault write goes through `Vault._write()` | One place for lock, conflict check, backup and atomic write | 2026-10-30 | Active |
| Theme follows the desktop by default; in-app override saved outside the vault and applied live | Keeps vault format unchanged; the user asked for a control, then for it to apply immediately | 2026-10-30 | Active |
| Restore via `Vault.restore()` only, after confirmation | One verified path; GUI never copies backup files | 2026-10-30 | Active |
| Breach check is offline only: the whole HIBP list is downloaded once (every range, same for everyone) and checked locally; no k-anonymity lookups | No password, hash or prefix leaves the machine because of a check | 2026-11-05 | Active |
| Breach list is a cache (`$XDG_CACHE_HOME`), 68 bits per hash, no counts, integrity-checked (index SHA-256, per-range CRC32); damage is reported, never answered | ~16 GB instead of ~40; a corrupted cache can't hide breaches | 2026-11-05 | Active |

## Success Metrics

| Metric | Target | Current | Status |
|--------|--------|---------|--------|
| CI test suite | All existing + new tests pass | 267 passing (per-file runs, 2026-11-05) | On track |
| TOTP interoperability | Codes match KeePassXC for same entry | RFC vectors + phone check pass; real KeePassXC not run here | Met (partial evidence) |
| Save safety | Failed/interrupted save never corrupts vault; last N backups restorable | Met (Phase 1) | ✓ |
| Distribution | `pip install pwvault-manager` from PyPI; GUI in desktop app menu | `pwvault-manager` 1.3.0 published to PyPI 2026-11-05 | ✅ Met |
| Security review | `/cso` finds no high-severity issues in changes | Phases 6, 7 and 8: no supported findings (runs 1793899968881-553cb096ceb6e924, 1793911242861-c63a7360f2ca517d, 1793923911466-61bf8128ec79c1c7; Phase 8 run partial: no scanners) | ✅ Met for Phases 6–8 |

## Tech Stack / Tools

| Layer | Technology | Notes |
|-------|------------|-------|
| Language | Python 3.10+ | Single-module CLI (`pwvault.py`) and GUI (`pwvault_gui.py`) |
| Vault format | KDBX 4 via `pykeepass` 4.2.0 | Pinned version |
| XML | `lxml` >= 6.1 | Security requirement |
| GUI | Tkinter | `python3-tk` on Fedora/Debian |
| Packaging | setuptools (`pyproject.toml`) | Entry points `pwvault`, `pwvault-gui` |
| CI | GitHub Actions (`.github/workflows/tests.yml`) | |
| Legacy migration | `cryptography` >= 50.0.2 (optional extra) | `.pwv` → `.kdbx` only |
| YubiKey | `yubikey-manager` >= 5.5 (optional extra) | HMAC-SHA1 challenge-response; needs pcsc-lite-devel to build pyscard |

## Links

| Resource | URL |
|----------|-----|
| Repository | https://github.com/jherney/password-vault |

---
*Created: 2026-10-30*
*Last updated: 2026-11-05 after Phase 8*
