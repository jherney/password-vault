---
description: "pwvault — current position and accumulated context"
type: ProjectState
about: "pwvault"
---

# Project State

## Project Reference

See: .paul/PROJECT.md (updated 2026-11-05)

**Core value:** I can keep all my passwords in one encrypted local vault that I control, use it from the terminal or a GUI, and still open it in KeePass-compatible apps.
**Current focus:** v1.4 Daily-driver gaps — Phase 8 Offline breach check

## Current Position

Milestone: v1.4 Daily-driver gaps
Phase: 8 of 6–9 (Offline breach check)
Plan: Not started
Status: Ready to plan
Last activity: 2026-11-05 — Phase 7 complete (07-01, 07-02; /cso no supported findings), transitioned to Phase 8

Progress:
- v1.3 Hardening, TOTP, Backups & Release: [██████████] 100% ✓ (released 2026-11-05)
- v1.4 Daily-driver gaps: [█████░░░░░] 50% (Phases 6–7 ✓)
- Phase 8: [░░░░░░░░░░] 0%

## Loop Position

Current loop state:
```
PLAN ──▶ APPLY ──▶ UNIFY
  ○        ○        ○     [Ready for first PLAN of Phase 8]
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
| 2026-11-05: Phase 7 work goes through PR #6 (branch yubikey-gui) so CodeRabbit reviews it; its one finding fixed in 0579ff2 | Phase 7 | PR workflow available for later phases |
| 2026-11-05: No YubiKey available (user, at 07-01 APPLY); the real-hardware checkpoint (AC-5) is deferred. KeePassXC compatibility is covered offline by KeePassXC's own YubiKey test vault and known answer; driver calls checked against yubikey-manager 5.9.2 source | Phase 7 | Driver never run against a device; first real-key use is the open item |
| 2026-11-05: GUI merge changes the vault in memory; Save writes once, Discard/Escape/close reload from disk (no password prompt); lock drops it | Phase 6 | Pattern for later in-memory-then-confirm dialogs |
| 2026-11-05: Every move stamps LocationChanged and every permanent delete writes DeletedObjects (pykeepass does neither) | Phase 6 | Moves and deletions made in pwvault carry over in merges here and in KeePassXC; deletions made with 1.3 or earlier were not recorded |

### Deferred Issues

- Phase 2: TOTP in CSV import/export (LastPass `totp`, 1Password `OTPAuth`, Bitwarden `login_totp`)
- Phase 2: KeePass 2 native `TimeOtp-*` fields not read
- Phase 2: real KeePassXC not run on this machine; interop covered by RFC vectors, sample entries, and phone check
- Phase 3: Backups restore locks the vault rather than reloading in place (approved as-is)
- Phase 3: a stray untracked `pwvault.keyx` (32 bytes) appeared in the repo root during a test run at 21:51; source not identified (not reproduced in a later full run); `*.keyx` is now git-ignored
- Phase 7 (07-01): AC-5 real-YubiKey check with keepassxc-cli -y; `[yubikey]` extra needs pcsc-lite-devel to build pyscard
- Phase 6 (06-01): deletions made with pwvault ≤ 1.3 not recorded (reappear on first merge); Meta HistoryMaxItems/HistoryMaxSize not read; database CustomData not merged (revisit in Phase 9); KDBX3↔4 time re-encoding untested
- Phase 4 (04-01): F-15 no lock file for dependencies; deferred to Phase 5 before any publish workflow. CI pins (F-11) and dependency minimums (F-12, F-14) fixed after the second CSO run

### Blockers/Concerns

- Phase 7: YubiKey driver untested on hardware (no key available); AC-5 of 07-01 open until a key is used once with keepassxc-cli
- Phase 1: ~~backups not opened in real KeePassXC~~ resolved 2026-10-30: a backup opens in keepassxc-cli 2.8.0 with correct TOTP.
- Phase 1: after a re-key, only the purge keeps old-key backups from lingering; revisit in Phase 4's security review.
- Resolved 04-03 (CLI-03 trash restore fixed in a follow-up): the stray `pwvault.keyx` was a test key file the user created by hand; the ignore rule stays.

### Git State

Last commit: 0a11adb (07-01 YubiKey CLI), pushed
Branch: yubikey-gui (Phase 7 complete, PR #6 open to main); main at 0a11adb
Uncommitted: `.gstack/` and `pwvault.keyx` (both intentionally not committed)

## Session Continuity

Last session: 2026-11-05
Stopped at: Phase 7 complete, ready to plan Phase 8 (PR #6 to merge)
Next action: merge PR #6, then /paul:plan for Phase 8 (Offline breach check)
Resume file: .paul/ROADMAP.md

---
*STATE.md — Updated after every significant action*
