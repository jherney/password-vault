---
description: "pwvault — current position and accumulated context"
type: ProjectState
about: "pwvault"
---

# Project State

## Project Reference

See: .paul/PROJECT.md (updated 2026-10-30)

**Core value:** I can keep all my passwords in one encrypted local vault that I control, use it from the terminal or a GUI, and still open it in KeePass-compatible apps.
**Current focus:** v1.3 — Phase 4 Security review & hardening (not yet planned)

## Current Position

Milestone: v1.3 Hardening, TOTP, Backups & Release
Phase: 3 of 5 (GUI polish) — Complete
Plan: 03-01 complete (SUMMARY written)
Status: Ready for next PLAN (Phase 4)
Last activity: 2026-10-30 — Phase 3 unified; checkpoint approved by user; transitioned to Phase 4

Progress:
- Milestone: [██████░░░░] 60%
- Phase 1: [██████████] 100% ✓
- Phase 2: [██████████] 100% ✓
- Phase 3: [██████████] 100% ✓

## Loop Position

Current loop state:
```
PLAN ──▶ APPLY ──▶ UNIFY
  ✓        ✓        ✓     [Loop complete - ready for next PLAN]
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
| All vault writes go through `Vault._write()` (lock, conflict check, backup, atomic write, prune) | Phase 1 | New save paths get backups for free |

### Deferred Issues

- Phase 2: TOTP in CSV import/export (LastPass `totp`, 1Password `OTPAuth`, Bitwarden `login_totp`)
- Phase 2: KeePass 2 native `TimeOtp-*` fields not read
- Phase 2: real KeePassXC not run on this machine; interop covered by RFC vectors, sample entries, and phone check
- Phase 3: Backups restore locks the vault rather than reloading in place (approved as-is)
- Phase 3: a stray untracked `pwvault.keyx` (32 bytes) appeared in the repo root during a test run at 21:51; source not identified, not committed

### Blockers/Concerns

- Phase 1: ~~backups not opened in real KeePassXC~~ resolved 2026-10-30: a backup opens in keepassxc-cli 2.8.0 with correct TOTP.
- Phase 1: after a re-key, only the purge keeps old-key backups from lingering; revisit in Phase 4's security review.
- Phase 3: the GUI test run leaves `pwvault.keyx` in the repo root (see Deferred Issues); Phase 4 should find the writer and stop it.

### Git State

Last commit: 0e16557 (Phase 3 plan, GUI and tests), then the Phase 3 close-out commit
Branch: qa-fixes-2026-10-28 (pushed to origin up to 0e16557)
Feature branches merged: none
Uncommitted: `.gstack/` and `pwvault.keyx` (both intentionally not committed)

## Session Continuity

Last session: 2026-10-30
Stopped at: Phase 3 complete, transitioned to Phase 4
Next action: /paul:plan for Phase 4 (Security review & hardening)
Resume file: .paul/ROADMAP.md

---
*STATE.md — Updated after every significant action*
