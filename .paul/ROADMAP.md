---
description: "pwvault — milestone and phase structure"
type: Roadmap
about: "pwvault"
---

# Roadmap: pwvault

## Overview

Take pwvault from 1.2.0 to a hardened, distributable release: fix remaining edge cases, add TOTP codes and automatic versioned backups, polish the GUI, and publish to PyPI with a desktop launcher.

## Current Milestone

**v1.3 Hardening, TOTP, Backups & Release** (v1.3.0)
Status: In progress
Phases: 4 of 5 complete (80%)

## Phases

| Phase | Name | Plans | Status | Completed |
|-------|------|-------|--------|-----------|
| 1 | Safe saves & backups | 1/1 | ✅ Complete | 2026-10-30 |
| 2 | TOTP codes | 1/1 | ✅ Complete | 2026-10-30 |
| 3 | GUI polish | 1/1 | ✅ Complete | 2026-10-30 |
| 4 | Security review & hardening | 2/3 (04-02 not needed) | ✅ Complete | 2026-10-30 |
| 5 | Packaging & release | 2/3 | In progress | - |

## Phase Details

### Phase 1: Safe saves & backups ✅

**Goal:** Every save keeps a versioned backup; backups are listable/restorable; failed saves never corrupt the vault
**Depends on:** Nothing (first phase)
**Research:** Unlikely (existing atomic-save code)

**Scope:**
- Backup-before-save in `Vault.save()`, keep last 10
- `pwvault backup list|restore`
- Purge old-key backups after re-key
- Fault-injection tests for interrupted saves

**Plans:**
- [x] 01-01: Backups on save, CLI restore, interrupted-save tests

### Phase 2: TOTP codes ✅

**Goal:** Store and generate TOTP codes compatible with KeePassXC's `otp` attribute, in CLI and GUI
**Depends on:** Phase 1 (saves are backed up)
**Research:** Likely (KeePassXC `otp` URI format and legacy TOTP fields)
**Research topics:** `otpauth://` URI parsing, KeePassXC `TOTP Seed`/`TOTP Settings` legacy fields, RFC 6238 test vectors

**Scope:**
- Stdlib TOTP (RFC 6238) generator
- CLI: set TOTP on an entry, copy the current code
- GUI: show the live code with a countdown, copy it

**Plans:**
- [x] 02-01: TOTP core (RFC 6238, KeePassXC formats), `pwvault totp` CLI, GUI live code

### Phase 3: GUI polish ✅

**Goal:** A cleaner, faster GUI: modernized look, search, keyboard shortcuts, backup restore screen
**Depends on:** Phases 1–2 (GUI surfaces backups and TOTP)
**Research:** Unlikely

**Scope:**
- Light/dark palette that follows the desktop setting (chosen at startup)
- Spacing and contrast tidy-up within both palettes
- Restore-from-backup dialog (GUI)
- Shortcut gaps (Ctrl+Shift+B for Backups)
- Search as you type and Ctrl+F already exist; not re-planned

**Plans:**
- [x] 03-01: Backups dialog, desktop light/dark palette with a live Theme button, spacing and shortcut tidy-up

### Phase 4: Security review & hardening

**Goal:** `/cso` review of all v1.3 changes with no high-severity findings; QA-driven edge-case fixes
**Depends on:** Phases 1–3
**Research:** Unlikely

**Scope:**
- Security audit (`/cso`) and fixes
- QA pass (`/qa`) on CLI and GUI with regression tests

**Plans:**
- [x] 04-01: Security audit (findings, threat model, data classification); re-key purge made crash-safe (F-01); key file ignored by git
- [-] 04-02: not needed (no open high or medium findings)
- [x] 04-03: QA pass on CLI and GUI; 4 defects fixed incl. trash restore to original group

### Phase 5: Packaging & release

**Plans:**
- [x] 05-01: Release readiness: hash-pinned lock file (F-15), version 1.3.0, changelog, drift test
- [x] 05-02: Desktop launcher: per-user .desktop entry and icon via `pwvault-gui --install-launcher`
- [ ] 05-03: PyPI release: trusted-publishing workflow written; name `pwvault-manager` (chosen); build and clean install verified. Waiting on: PyPI trusted publisher (manual), your approval to tag v1.3.0 (depends on 05-01)

**Decided:** distribution name `pwvault-manager` (`pwvault` and `passguard` are taken on PyPI).

**Goal:** `pip install pwvault` from PyPI; GUI in the desktop app menu; v1.3.0 tagged
**Depends on:** Phase 4
**Research:** Likely (PyPI trusted publishing from GitHub Actions)

**Scope:**
- PyPI publish workflow (trusted publishing)
- `.desktop` file + icon, install helper
- Version bump to 1.3.0, changelog, tag

---
*Roadmap created: 2026-10-30*
*Last updated: 2026-10-30 after Phase 5 plan*
