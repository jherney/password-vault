---
description: "pwvault — current position and accumulated context"
type: ProjectState
about: "pwvault"
---

# Project State

## Project Reference

See: .paul/PROJECT.md (updated 2026-10-30)

**Core value:** I can keep all my passwords in one encrypted local vault that I control, use it from the terminal or a GUI, and still open it in KeePass-compatible apps.
**Current focus:** v1.3 — Phase 2 TOTP codes

## Current Position

Milestone: v1.3 Hardening, TOTP, Backups & Release
Phase: 2 of 5 (TOTP codes)
Plan: Not started
Status: Ready to plan
Last activity: 2026-10-30 — Phase 1 complete (01-01 unified), transitioned to Phase 2

Progress:
- Milestone: [██░░░░░░░░] 20%
- Phase 1: [██████████] 100% ✓
- Phase 2: [░░░░░░░░░░] 0%

## Loop Position

Current loop state:
```
PLAN ──▶ APPLY ──▶ UNIFY
  ○        ○        ○     [Phase 1 loop closed - ready to PLAN Phase 2]
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

### Deferred Issues

None yet.

### Blockers/Concerns

- Phase 1: backups weren't opened in real KeePassXC (not installed); verified with pykeepass. Check once KeePassXC is available.
- Phase 1: after a re-key, only the purge keeps old-key backups from lingering; revisit in Phase 4's security review.

## Session Continuity

Last session: 2026-10-30
Stopped at: Phase 1 complete, ready to plan Phase 2
Next action: /paul:plan for Phase 2 (TOTP codes)
Resume file: .paul/ROADMAP.md

---
*STATE.md — Updated after every significant action*
