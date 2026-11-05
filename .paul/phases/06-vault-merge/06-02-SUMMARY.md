---
phase: 06-vault-merge
plan: 02
subsystem: ui
tags: [tkinter, merge, gui]

requires:
  - phase: 06-vault-merge
    provides: merge_vaults()/MergeReport (06-01)
provides:
  - Database > Merge another copy… dialog (preview, Save, Discard)
  - open_other_copy()/check_other_copy() shared by CLI and GUI
  - App.reload_from_disk() (drop in-memory changes without re-entering the password)
affects: [09 browser autofill (GUI dialog patterns), any future in-memory-then-confirm GUI action]

tech-stack:
  added: []
  patterns:
    - "In-memory change, then Save or reload_from_disk(): Escape and WM_DELETE_WINDOW route to the discard path; lock() destroying the dialog drops the change with the vault"

key-files:
  created: [tests/test_gui_merge.py]
  modified: [pwvault.py, pwvault_gui.py, tests/test_merge.py, README.md, CHANGELOG.md]

key-decisions:
  - "Discard reloads from disk with the key in memory rather than locking"
  - "Destroy is not overridden: lock() destroys dialogs after clearing the vault, so discard logic lives in close()"

patterns-established:
  - "Opening another KDBX for read goes through open_other_copy()"

duration: ~1h
started: 2026-11-05T16:00:00-04:00
completed: 2026-11-05T17:40:00-04:00
description: "GUI Database > Merge another copy…: lists every change from the other copy, then saves once with a backup or reloads from disk; CLI and GUI share open_other_copy()"
type: Summary
about: "pwvault"
---

# Phase 6 Plan 02: GUI merge dialog Summary

**Database > Merge another copy… lists every change the other copy brings (added, updated, moved, deleted), then Save writes it once with a backup and Discard/Escape/close reloads the vault from disk without asking for the password. The CLI and the GUI open the other copy through one function.**

## Performance

| Metric | Value |
|--------|-------|
| Duration | ~1h |
| Tasks | 2 auto + 1 checkpoint (approved) |
| Files modified | 5 (+1 created) |
| Tests | 195 OK (183 + 3 open_other_copy + 9 GUI) |

## Acceptance Criteria Results

| Criterion | Status | Notes |
|-----------|--------|-------|
| AC-1: Merge from the GUI | Pass | Rows, totals, one save with backup, entries refreshed, status line, other file unchanged; user-verified |
| AC-2: Discard leaves the vault as it was | Pass | Discard, Escape and window close: file bytes and entries equal; no password prompt (user-verified) |
| AC-3: Other credentials and errors | Pass | Own password + key file; wrong password, vault itself, symlink, missing file, non-KDBX shown inline; "Already up to date." |
| AC-4: Safe around locking | Pass | Lock with the list open: dialog closed, vault None, file unchanged |
| AC-5: One path for CLI and GUI | Pass | `cmd_merge` uses `check_other_copy` (before any prompt) and `open_other_copy`; 06-01 CLI tests unchanged and passing |

## Files Created/Modified

| File | Change | Purpose |
|------|--------|---------|
| `pwvault.py` | Modified | `check_other_copy()`, `open_other_copy()`; `cmd_merge` uses them |
| `pwvault_gui.py` | Modified (+150) | `MergeDialog`, `App.reload_from_disk()`, `App.open_merge()`, menu item |
| `tests/test_gui_merge.py` | Created (156 lines) | 9 GUI tests |
| `tests/test_merge.py` | Modified | `OpenOtherCopyTests` (3) |
| `README.md`, `CHANGELOG.md` | Modified | GUI merge paragraph; Unreleased entry |

## Decisions Made

| Decision | Rationale | Impact |
|----------|-----------|--------|
| Discard = reload from disk with the in-memory key | No password prompt; the merge engine has no undo | One extra Argon2 run on discard (busy cursor) |
| Discard logic in `close()`, not `destroy()` | `lock()` destroys dialogs after setting `vault = None` | Lock drops an unsaved merge for free |

## Deviations from Plan

| Type | Count | Impact |
|------|-------|--------|
| Small additions | 2 | No scope change |

- `check_other_copy()` split out of `open_other_copy()` so the CLI still fails on a missing/same file before asking for a password (the plan named only `open_other_copy`)
- Enter on the "Already up to date." screen closes the dialog (it re-ran Merge)
- Test expectation corrected: a vault without a recycle bin shows "Recycle Bin/" as an added group (06-01 behavior, now visible in the GUI)

## Issues Encountered

| Issue | Resolution |
|-------|------------|
| One assertion compared the vault file with itself | Replaced with a byte comparison against the pre-merge file |

## Next Phase Readiness

**Ready:** Phase 6 complete; dialog pattern (in-memory change, Save or reload) reusable for Phase 8's report dialog.

**Concerns:** None new. Deferred items from 06-01 still stand (pre-1.4 deletions unrecorded, HistoryMax*, CustomData, KDBX3↔4).

**Blockers:** None

---
*Phase: 06-vault-merge, Plan: 02*
*Completed: 2026-11-05*
