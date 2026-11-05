---
description: "pwvault — current position and accumulated context"
type: ProjectState
about: "pwvault"
---

# Project State

## Project Reference

See: .paul/PROJECT.md (updated 2026-10-30)

**Core value:** I can keep all my passwords in one encrypted local vault that I control, use it from the terminal or a GUI, and still open it in KeePass-compatible apps.
**Current focus:** v1.4 Daily-driver gaps — Phase 6 Vault merge

## Current Position

Milestone: v1.4 Daily-driver gaps
Phase: 6 of 6–9 (Vault merge) — In progress
Plan: 06-01 complete; 06-02 (GUI) next
Status: Ready for next PLAN
Last activity: 2026-11-05 — Unified 06-01: merge engine, `pwvault merge`, KeePassXC interop; full suite 183 OK

Progress:
- v1.3 Hardening, TOTP, Backups & Release: [██████████] 100% ✓ (released 2026-11-05)
- v1.4 Daily-driver gaps: [█░░░░░░░░░] 12%
- Phase 6: [█████░░░░░] 50% (06-01 ✓, 06-02 GUI next)

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
| 2026-10-30: 04-01 checkpoint: fix F-01 (durable re-key purge), close F-07, complete the audit gaps; no critical/high findings, so no 04-02 fix plan for F-02–F-12 | Phase 4 | F-01 fixed in pwvault.py; F-11 and F-12 deferred to Phase 5 |
| All vault writes go through `Vault._write()` (lock, conflict check, backup, atomic write, prune) | Phase 1 | New save paths get backups for free |
| 2026-11-05: `pwvault merge` applies permanent deletions (KeePassXC Synchronize rules), unlike KeePassXC's default KeepNewer merge | Phase 6 | Interop test expects the same result as keepassxc-cli except for permanently deleted entries |
| 2026-11-05: Every move stamps LocationChanged and every permanent delete writes DeletedObjects (pykeepass does neither) | Phase 6 | Moves and deletions made in pwvault carry over in merges here and in KeePassXC; deletions made with 1.3 or earlier were not recorded |

### Deferred Issues

- Phase 2: TOTP in CSV import/export (LastPass `totp`, 1Password `OTPAuth`, Bitwarden `login_totp`)
- Phase 2: KeePass 2 native `TimeOtp-*` fields not read
- Phase 2: real KeePassXC not run on this machine; interop covered by RFC vectors, sample entries, and phone check
- Phase 3: Backups restore locks the vault rather than reloading in place (approved as-is)
- Phase 3: a stray untracked `pwvault.keyx` (32 bytes) appeared in the repo root during a test run at 21:51; source not identified (not reproduced in a later full run); `*.keyx` is now git-ignored
- Phase 6 (06-01): deletions made with pwvault ≤ 1.3 not recorded (reappear on first merge); Meta HistoryMaxItems/HistoryMaxSize not read; database CustomData not merged (revisit in Phase 9); KDBX3↔4 time re-encoding untested
- Phase 4 (04-01): F-15 no lock file for dependencies; deferred to Phase 5 before any publish workflow. CI pins (F-11) and dependency minimums (F-12, F-14) fixed after the second CSO run

### Blockers/Concerns

- Phase 1: ~~backups not opened in real KeePassXC~~ resolved 2026-10-30: a backup opens in keepassxc-cli 2.8.0 with correct TOTP.
- Phase 6: `/cso` done 2026-11-05 (run 1793899968881-553cb096ceb6e924, partial, no supported findings; cryptography floor raised to 50.0.2 from its OSV triage). Manual GUI open of a merged vault still due before Phase 6 closes
- Phase 1: after a re-key, only the purge keeps old-key backups from lingering; revisit in Phase 4's security review.
- Resolved 04-03 (CLI-03 trash restore fixed in a follow-up): the stray `pwvault.keyx` was a test key file the user created by hand; the ignore rule stays.

### Git State

Last commit: ce9009e (requirements.lock committed; v1.3.0 tag)
Branch: vault-merge (from main at ce9009e), 06-01 and the cryptography floor committed, not pushed
Uncommitted: `.gstack/` and `pwvault.keyx` (both intentionally not committed)

## Session Continuity

Last session: 2026-11-05
Stopped at: 06-01 loop closed
Next action: /paul:plan for 06-02 (GUI Database > Merge… dialog)
Resume file: .paul/phases/06-vault-merge/06-01-SUMMARY.md

---
*STATE.md — Updated after every significant action*
