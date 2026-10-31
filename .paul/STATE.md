---
description: "pwvault — current position and accumulated context"
type: ProjectState
about: "pwvault"
---

# Project State

## Project Reference

See: .paul/PROJECT.md (updated 2026-10-30)

**Core value:** I can keep all my passwords in one encrypted local vault that I control, use it from the terminal or a GUI, and still open it in KeePass-compatible apps.
**Current focus:** v1.3 — Phase 3 GUI polish (plan 03-01 awaiting approval)

## Current Position

Milestone: v1.3 Hardening, TOTP, Backups & Release
Phase: 3 of 5 (GUI polish) — Planning
Plan: 03-01 created, awaiting approval
Status: PLAN created, ready for APPLY
Last activity: 2026-10-30 — Created .paul/phases/03-gui-polish/03-01-PLAN.md (standard track, 3 tasks + human-verify)

Progress:
- Milestone: [████░░░░░░] 40%
- Phase 1: [██████████] 100% ✓
- Phase 2: [██████████] 100% ✓
- Phase 3: [░░░░░░░░░░] 0% (plan 03-01 created)

## Loop Position

Current loop state:
```
PLAN ──▶ APPLY ──▶ UNIFY
  ✓        ○        ○     [Plan 03-01 created, awaiting approval]
```

## Accumulated Context

### Decisions

| Decision | Phase | Impact |
|----------|-------|--------|
| v1.3 features limited to TOTP + automatic backups | Init | Browser integration, sync, passkeys out of scope |
| Packaging: PyPI + `.desktop` launcher | Init | RPM/Flatpak deferred |
| TOTP via stdlib, KeePassXC `otp` attribute | Init | No new runtime dependency; interop with KeePassXC |
| Delete old-key backups after a verified re-key | Phase 1 | Leaked old password can't open leftover backups |
| All vault writes go through `Vault._write()` (lock, conflict check, backup, atomic write, prune) | Phase 1 | New save paths get backups for free |
| A failed backup fails the save; a failed prune never does | Phase 1 | Backup dir can briefly hold more than 10 |
| Setting or clearing `otp` drops legacy TOTP Seed/Settings | Phase 2 | Only one TOTP secret per entry |
| Reading a code never saves the vault | Phase 2 | No backup created by `totp` copy |

### Deferred Issues

- Phase 2: TOTP in CSV import/export (LastPass `totp`, 1Password `OTPAuth`, Bitwarden `login_totp`)
- Phase 2: KeePass 2 native `TimeOtp-*` fields not read
- Phase 2: real KeePassXC not run on this machine; interop covered by RFC vectors, sample entries, and phone check

### Blockers/Concerns

- Phase 1: ~~backups not opened in real KeePassXC~~ resolved 2026-10-30: a backup opens in keepassxc-cli 2.8.0 with correct TOTP.
- Phase 1: after a re-key, only the purge keeps old-key backups from lingering; revisit in Phase 4's security review.

### Git State

Last commit: 948d090 (Phase 2)
Branch: qa-fixes-2026-10-28
Feature branches merged: none
Uncommitted: none

## Session Continuity

Last session: 2026-10-30
Stopped at: Plan 03-01 created
Next action: Review and approve plan, then run /paul:apply .paul/phases/03-gui-polish/03-01-PLAN.md
Resume file: .paul/phases/03-gui-polish/03-01-PLAN.md

---
*STATE.md — Updated after every significant action*
