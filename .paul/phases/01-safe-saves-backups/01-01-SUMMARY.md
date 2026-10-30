---
phase: 01-safe-saves-backups
plan: 01
subsystem: storage
tags: [kdbx, pykeepass, backups, atomic-write, flock, fault-injection]

requires: []
provides:
  - Backup of the previous vault file before every save (<vault>.backups/, newest 10 kept)
  - "`pwvault backup list` and `pwvault backup restore N`"
  - Purge of old-key backups after a verified re-key (CLI and GUI notice)
  - Fault-injection tests proving an interrupted save leaves the vault intact
affects: [02-totp, 03-gui-polish, 04-security-review]

tech-stack:
  added: []
  patterns:
    - "All vault writes go through Vault._write(): lock, conflict check, backup, atomic write, prune"
    - "load_kdbx() is the one place a KDBX blob is checked and opened, with the VaultError mapping"

key-files:
  created: [tests/test_backups.py]
  modified: [pwvault.py, pwvault_gui.py, README.md]

key-decisions:
  - "Backups are written under the save lock from the bytes the conflict check just read"
  - "A failed backup fails the save; a failed prune never does"
  - "Re-key purges every backup only after the new file is shown to open with the new key"
  - "Restore checks the backup against the unlocked vault's key before anything changes"

patterns-established:
  - "Fault-injection tests patch os.fsync / os.replace / write_private and assert bytes unchanged, no temp leftovers, retry succeeds"

duration: not tracked
started: 2026-10-30T19:52:37-03:00
completed: 2026-10-30T20:08:00-03:00
description: "Every save now keeps the previous vault in <vault>.backups/ (last 10), restorable with `pwvault backup restore N`; old-key backups are purged after a re-key"
type: Summary
about: "pwvault"
---

# Phase 1 Plan 01: Safe saves & backups Summary

**Every save now keeps the previous vault file in `<vault>.backups/` (newest 10), `pwvault backup list|restore` brings an old version back, a re-key purges backups made with the retired key, and 18 new tests (4 of them fault-injection) prove a failed save leaves the vault as it was.**

## Performance

| Metric | Value |
|--------|-------|
| Duration | Not tracked (APPLY began 2026-10-30T19:52-03:00) |
| Completed | 2026-10-30T20:08:00-03:00 |
| Tasks | 3 of 3 completed |
| Files modified | 4 (1 created, 3 modified) |
| Tests | 54 → 72, all passing under xvfb (211 s) |

## Acceptance Criteria Results

| Criterion | Status | Notes |
|-----------|--------|-------|
| AC-1: Backup before every save | Pass | Byte-for-byte copy, 0600 file / 0700 dir, beside the real file for symlinked vaults; first save makes none (`BackupOnSaveTests`) |
| AC-2: Only the newest 10 kept | Pass | 12 saves leave exactly 10, newest first; a stray `notes.txt` survives |
| AC-3: Failed backup blocks the save | Pass | ENOSPC on the backup → OSError, vault bytes unchanged, no temp files, retry works |
| AC-4: Interrupted saves never corrupt | Pass | `kp.save` error, fsync error, `os.replace` error, Ctrl-C: vault unchanged, reopens, no leftovers, retry has no false conflict |
| AC-5: List and restore from the CLI | Pass | Numbered newest first with time and size; restore backs up the current file first (so it can be undone); wrong password or a foreign-key backup is refused and nothing changes; bad N exits before any password prompt |
| AC-6: Re-key purges old-key backups | Pass | Purge after the new file re-derives its key; count printed by `passwd` and shown in the GUI status bar; a failed re-key save deletes nothing |

## Accomplishments

- No save path can replace the vault without first keeping the file it replaces: the backup lives inside the same lock and conflict check every save already used.
- A stolen-then-changed master password no longer unlocks leftover backups: they're deleted once the re-keyed vault is proven to open.
- Save safety is now tested at every failure point, not just assumed from `write_private()`.

## Files Created/Modified

| File | Change | Purpose |
|------|--------|---------|
| `pwvault.py` | Modified (+130/−14) | `BACKUP_KEEP`, `BACKUP_STAMP`, `backup_dir()`, `list_backups()`, `remove_backups()`, `load_kdbx()`; `Vault.save()` split into `save()` + `_write()`; `Vault.restore()`; `rekeyed` / `purged_backups`; `cmd_backup`; `passwd` notice; `backup` subparser; docstring bullet |
| `pwvault_gui.py` | Modified (+3/−1) | Change-password status bar mentions the purged backups |
| `tests/test_backups.py` | Created (265 lines, 18 tests) | `BackupOnSaveTests` (7), `InterruptedSaveTests` (4), `BackupCliTests` (7) |
| `README.md` | Modified (+15) | Features bullet, CLI table row, "Backups" section |

## Decisions Made

| Decision | Rationale | Impact |
|----------|-----------|--------|
| Back up from `current` under the lock | It's exactly the file being replaced; no second read, no race with the GUI | Phase 3's restore dialog can call `Vault.restore()` as is |
| Prune failures are swallowed per file | A leftover backup is harmless; failing a save that already succeeded isn't | Backup dir may briefly exceed 10 if a file can't be deleted |
| Plain `unlink` for purge | Backups are encrypted; overwriting is meaningless on btrfs/SSD | Documented in `remove_backups()` |
| The purge count includes the pre-re-key copy | That copy was made with the old key too, so it must go | `passwd` after 3 saves reports 3; the save-level test sees 4 |

## Deviations from Plan

### Summary

| Type | Count | Impact |
|------|-------|--------|
| Design adjustments | 4 | Same behavior, cleaner shape |
| Scope additions | 1 | Small usability gain |
| Verification gaps | 1 | KeePassXC check done with pykeepass instead |
| Deferred | 0 | — |

**Total impact:** No scope creep; every acceptance criterion met.

### Design adjustments

**1. `restore_backup()` became the method `Vault.restore(backup)`.**
It checks the backup against the unlocked vault's own credentials, which are the ones the user just typed at `unlock()`, so the outcome matches the plan. The shared helper is named `_write()` (plan suggested `_locked_write()`).

**2. `list_backups()` returns `(utc_time, path)` pairs instead of paths.**
The CLI needs the timestamp, and parsing the name in one place keeps the rule for skipping stray files in one spot.

**3. Backup list times show seconds instead of using `fmt_time()`.**
`fmt_time()` shows minutes only, so several saves in one minute would show identical times. The list uses local `%Y-%m-%d %H:%M:%S`.

**4. New `load_kdbx()` shared by `Vault.open()` and `Vault.restore()`.**
Side effect: in `open()`, a missing key file is now reported before the KDF/XML-parser checks run. That only changes which error a user sees when both problems exist at once. Existing tests pass unmodified.

### Scope additions

- `backup restore` validates N, and rejects a missing N, *before* asking for the password, so a typo doesn't cost an Argon2 unlock.

### Verification gaps

- KeePassXC isn't installed on this machine, so "a backup opens in KeePassXC" was checked by opening backups with `pykeepass` (in `test_save_keeps_previous_file_byte_for_byte` and `test_rekey_purges_old_key_backups`). Backups are byte copies of files KeePassXC already opens, so the risk is low.

### Deferred Items

None.

## Issues Encountered

| Issue | Resolution |
|-------|------------|
| `leftovers()` helper was needed by two test classes | Moved to module level |
| No defects in `pwvault.py` surfaced by fault injection | None needed: `write_private()` already cleans up on every failure path, including `KeyboardInterrupt` |

## Next Phase Readiness

**Ready:**
- Every later phase's saves (TOTP edits, GUI changes) are backed up automatically.
- `Vault.restore()` and `list_backups()` are ready for Phase 3's restore dialog.

**Concerns:**
- Backups use whatever key was in effect when they were made. After a re-key only the purge protects them, so Phase 4's security review should look at the purge path again.
- Open a backup in real KeePassXC once, when it's available.

**Blockers:**
- None

---
*Built with PAUL Framework v1.4 · https://chrisai.cv/skool · https://youtube.com/@chris-ai-systems*
*Phase: 01-safe-saves-backups, Plan: 01*
*Completed: 2026-10-30*
