---
description: "pwvault — current position and accumulated context"
type: ProjectState
about: "pwvault"
---

# Project State

## Project Reference

See: .paul/PROJECT.md (updated 2026-10-30)

**Core value:** I can keep all my passwords in one encrypted local vault that I control, use it from the terminal or a GUI, and still open it in KeePass-compatible apps.
**Current focus:** v1.3 — Phase 4 Security review & hardening (plan 04-01 complete; 04-02 and 04-03 remain)

## Current Position

Milestone: v1.3 Hardening, TOTP, Backups & Release
Phase: 4 of 5 (Security review & hardening) — In progress
Plan: 04-01 complete (SUMMARY written)
Status: Ready for next decision: whether a fix plan (04-02) is needed, then QA (04-03)
Last activity: 2026-10-30 — Unified 04-01: F-01 fixed; findings, threat model and data classification written; full suite 151 OK

Progress:
- Milestone: [██████░░░░] 60%
- Phase 1: [██████████] 100% ✓
- Phase 2: [██████████] 100% ✓
- Phase 3: [██████████] 100% ✓
- Phase 4: [███░░░░░░░] 33% (plan 04-01 of 3 complete)

## Loop Position

Current loop state:
```
PLAN ──▶ APPLY ──▶ UNIFY
  ✓        ✓        ✓     [Plan 04-01 complete - ready for next PLAN]
```

## Accumulated Context

### Decisions

| Decision | Phase | Impact |
|----------|-------|--------|
| Restore goes through `Vault.restore()`; the GUI never copies backup files | Phase 3 | Wrong-key backups refused, no change made |
| Theme follows the desktop by default; in-app choice saved in `~/.config/pwvault/settings.ini`, not the vault | Phase 3 | Only new file the GUI writes outside the vault and its backups |
| Theme applies live: palette re-applied to open windows and dialogs | Phase 3 | Palette values must be unique within each palette (tested) |
| Dark accent `#6c8cff` → `#4263eb` (white label 3.07:1 → 4.98:1) | Phase 3 | Dark look slightly deeper than the original |
| Setting or clearing `otp` drops legacy TOTP Seed/Settings | Phase 2 | Only one TOTP secret per entry |
| Reading a code never saves the vault | Phase 2 | No backup created by `totp` copy |
| 2026-10-30: 04-01 checkpoint: fix F-01 (durable re-key purge), close F-07, complete the audit gaps; no critical/high findings, so no 04-02 fix plan for F-02–F-12 | Phase 4 | F-01 fixed in pwvault.py; F-11 and F-12 deferred to Phase 5 |
| All vault writes go through `Vault._write()` (lock, conflict check, backup, atomic write, prune) | Phase 1 | New save paths get backups for free |

### Deferred Issues

- Phase 2: TOTP in CSV import/export (LastPass `totp`, 1Password `OTPAuth`, Bitwarden `login_totp`)
- Phase 2: KeePass 2 native `TimeOtp-*` fields not read
- Phase 2: real KeePassXC not run on this machine; interop covered by RFC vectors, sample entries, and phone check
- Phase 3: Backups restore locks the vault rather than reloading in place (approved as-is)
- Phase 3: a stray untracked `pwvault.keyx` (32 bytes) appeared in the repo root during a test run at 21:51; source not identified (not reproduced in a later full run); `*.keyx` is now git-ignored
- Phase 4 (04-01): F-15 no lock file for dependencies; deferred to Phase 5 before any publish workflow. CI pins (F-11) and dependency minimums (F-12, F-14) fixed after the second CSO run

### Blockers/Concerns

- Phase 1: ~~backups not opened in real KeePassXC~~ resolved 2026-10-30: a backup opens in keepassxc-cli 2.8.0 with correct TOTP.
- Phase 1: after a re-key, only the purge keeps old-key backups from lingering; revisit in Phase 4's security review.
- Phase 4 (04-01): the stray `pwvault.keyx` writer is still unidentified; the ignore rule keeps it out of git.

### Git State

Last commit: 0e16557 (Phase 3 plan, GUI and tests), then the Phase 3 close-out commit
Branch: qa-fixes-2026-10-28 (pushed to origin up to 0e16557)
Feature branches merged: none
Uncommitted: `.gstack/` and `pwvault.keyx` (both intentionally not committed)

## Session Continuity

Last session: 2026-10-30
Stopped at: Plan 04-01 complete
Next action: /paul:plan for the next Phase 4 plan (QA pass, 04-03); no fix plan is needed unless new findings come up
Resume file: .paul/phases/04-security-review/04-01-SUMMARY.md

---
*STATE.md — Updated after every significant action*
