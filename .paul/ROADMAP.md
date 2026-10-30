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
Phases: 1 of 5 complete (20%)

## Phases

| Phase | Name | Plans | Status | Completed |
|-------|------|-------|--------|-----------|
| 1 | Safe saves & backups | 1/1 | ✅ Complete | 2026-10-30 |
| 2 | TOTP codes | TBD | Not started | - |
| 3 | GUI polish | TBD | Not started | - |
| 4 | Security review & hardening | TBD | Not started | - |
| 5 | Packaging & release | TBD | Not started | - |

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

### Phase 2: TOTP codes

**Goal:** Store and generate TOTP codes compatible with KeePassXC's `otp` attribute, in CLI and GUI
**Depends on:** Phase 1 (saves are backed up)
**Research:** Likely (KeePassXC `otp` URI format and legacy TOTP fields)
**Research topics:** `otpauth://` URI parsing, KeePassXC `TOTP Seed`/`TOTP Settings` legacy fields, RFC 6238 test vectors

**Scope:**
- Stdlib TOTP (RFC 6238) generator
- CLI: set TOTP on an entry, copy the current code
- GUI: show the live code with a countdown, copy it

### Phase 3: GUI polish

**Goal:** A cleaner, faster GUI: modernized look, search, keyboard shortcuts, backup restore screen
**Depends on:** Phases 1–2 (GUI surfaces backups and TOTP)
**Research:** Unlikely

**Scope:**
- Visual refresh (ttk theme, spacing, dark-mode aware)
- Search/filter as you type; keyboard shortcuts
- Restore-from-backup dialog

### Phase 4: Security review & hardening

**Goal:** `/cso` review of all v1.3 changes with no high-severity findings; QA-driven edge-case fixes
**Depends on:** Phases 1–3
**Research:** Unlikely

**Scope:**
- Security audit (`/cso`) and fixes
- QA pass (`/qa`) on CLI and GUI with regression tests

### Phase 5: Packaging & release

**Goal:** `pip install pwvault` from PyPI; GUI in the desktop app menu; v1.3.0 tagged
**Depends on:** Phase 4
**Research:** Likely (PyPI trusted publishing from GitHub Actions)

**Scope:**
- PyPI publish workflow (trusted publishing)
- `.desktop` file + icon, install helper
- Version bump to 1.3.0, changelog, tag

---
*Roadmap created: 2026-10-30*
*Last updated: 2026-10-30 after Phase 1*
