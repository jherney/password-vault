---
phase: 06-vault-merge
plan: 01
subsystem: storage
tags: [kdbx, merge, sync, keepassxc, pykeepass, lxml]

requires:
  - phase: 01-safe-saves-backups
    provides: Vault._write() (lock, conflict check, backup) used for the single merge save
provides:
  - merge_vaults() / MergeReport: KeePassXC-style merge of two vault copies by UUID
  - `pwvault merge OTHER [--dry-run] [--same-credentials] [--other-keyfile PATH]`
  - DeletedObjects recorded on every permanent delete
  - LocationChanged stamped on every move
affects: [06-02 GUI merge dialog, 09 browser autofill (sync story)]

tech-stack:
  added: []
  patterns:
    - "Merge works on the lxml tree directly (pykeepass has no merge, DeletedObjects or LocationChanged support)"
    - "Elements copied from the other file go through _Merger.adopt(): time re-encoding across KDBX versions, attachment refs remapped into this vault's pool"

key-files:
  created: [tests/test_merge.py]
  modified: [pwvault.py, README.md, CHANGELOG.md]

key-decisions:
  - "Permanent deletions apply (KeePassXC Synchronize rules), unlike KeePassXC's default KeepNewer merge (user decision)"
  - "A vault without a recycle bin adopts the other copy's bin (KeePassXC leaves it a plain group)"
  - "Moves stamp LocationChanged; permanent deletes write DeletedObjects"

patterns-established:
  - "Every move in Vault goes through _moved(); every permanent delete through _record_deleted()"

duration: ~2.5h
started: 2026-11-05T12:40:00-04:00
completed: 2026-11-05T15:10:00-04:00
description: "pwvault merge: KeePassXC-compatible two-copy merge by UUID with history, moves, recycle bin and permanent deletions; matches keepassxc-cli except where pwvault deliberately applies deletions"
type: Summary
about: "pwvault"
---

# Phase 6 Plan 01: Vault merge (engine + CLI) Summary

**`pwvault merge OTHER.kdbx` merges another copy of the vault by UUID the way KeePassXC does: the newer version wins with the other kept in history, moves and the recycle bin carry over, and permanent deletions apply. The result matches `keepassxc-cli merge` entry for entry, except for the deliberate differences below.**

## Performance

| Metric | Value |
|--------|-------|
| Duration | ~2.5h |
| Tasks | 3 of 3 completed |
| Files modified | 4 code/docs (+ .paul state) |
| Tests | 183 OK (164 before + 19 new in tests/test_merge.py) |

## Acceptance Criteria Results

| Criterion | Status | Notes |
|-----------|--------|-------|
| AC-1: Edits on both sides survive | Pass | X/Y/Z case; Z history holds both versions; history capped at HISTORY_MAX; other file byte-identical |
| AC-2: New entries and groups in the right place | Pass | Nested new groups keep UUIDs; attachments on current and history versions; custom icon copied |
| AC-3: Moves and deletions carry over | Pass | Move, trash, permanent delete; entry edited after the other side's delete is kept; group with new content kept; DeletedObjects recorded |
| AC-4: Safe save and clear report | Pass | One save with backup; `--dry-run` leaves file identical; own password/key file; wrong password; same-file and symlink refusal; missing file |
| AC-5: Same result as KeePassXC | Pass (with documented differences) | Equal entries except permanently deleted ones (KeePassXC keeps them) and a recycle bin adopted by a vault that had none. KeePassXC opens pwvault's result; KeePassXC-made edits and deletions merge in |

## Accomplishments

- Merge engine (`_Merger`) ported from KeePassXC 2.8 `Merger.cpp` rules, read from source before writing: entry/group UUID matching, history union keyed by modification time, LocationChanged-based moves, earliest DeletionTime per UUID, group deleted only when empty and not changed after deletion
- Two gaps pykeepass leaves fixed at the `Vault` layer, so moves and deletions made in pwvault (CLI and GUI) now take part in merges here and in KeePassXC
- Interop proven both ways against keepassxc-cli 2.8.0 on this machine

## Files Created/Modified

| File | Change | Purpose |
|------|--------|---------|
| `pwvault.py` | Modified (+396) | `_record_deleted`, `_moved`, `MergeReport`, `merge_vaults`, `_Merger`, `cmd_merge`, `merge` subparser |
| `tests/test_merge.py` | Created (426 lines) | Engine, structure, deletion, CLI and KeePassXC interop tests |
| `README.md` | Modified | "Using the vault on two devices" section, command table, feature list |
| `CHANGELOG.md` | Modified | Unreleased: Added merge; Changed deletions/moves recording |

## Decisions Made

| Decision | Rationale | Impact |
|----------|-----------|--------|
| Apply permanent deletions (user, at APPLY) | Two-device use should not resurrect deleted passwords; matches KeePassXC's optional Synchronize mode | Differs from keepassxc-cli default; README explains it |
| Adopt the other copy's recycle bin when this vault has none | KeePassXC's behavior (plain group) makes trashed entries look live; its code marks it TODO | Only affects vaults that never had a bin |
| Equal modification times: keep this side, merge histories | Same as KeePassXC (treated as the same version) | Rare true conflicts keep the local version |

## Deviations from Plan

### Summary

| Type | Count | Impact |
|------|-------|--------|
| Auto-fixed | 1 | Essential: without it moves never merged |
| Spec change (user decision) | 1 | AC-5 now allows the deletion difference |
| Simplification | 2 | No behavior change |

**Total impact:** One essential fix found by reading pykeepass; no scope creep.

### Auto-fixed Issues

**1. Moves did not record LocationChanged**
- **Found during:** Task 1, while checking which side's location wins
- **Issue:** pykeepass `move_entry`/`move_group`/`trash_*` never update `Times/LocationChanged`, so a move made in pwvault looked older than the other copy's unchanged location and was lost in any merge (here or in KeePassXC)
- **Fix:** `Vault._moved()` stamps it; called from `update_entry` (group change), `delete_entry` (trash), `restore_entry`, `delete_group` (trash)
- **Files:** pwvault.py
- **Verification:** `test_moves_stamp_location_changed`, `test_moves_trash_and_permanent_deletes_carry_over`, interop test

### Spec change

- AC-3 ("deletions carry over") and AC-5 ("same result as KeePassXC") conflicted: keepassxc-cli's default merge mode (KeepNewer) skips deletions — verified with keepassxc-cli 2.8.0. User chose "apply them". The interop test asserts the difference explicitly.

### Simplifications

- No `Vault.load_other()` helper: `cmd_merge` opens the other copy read-only with the existing `load_kdbx()`
- No mapping of a differently-UUID'd recycle bin; copies of one vault share the bin UUID, and the "no bin here" case is handled by adoption

### Deferred Items

- Entries permanently deleted with pwvault ≤ 1.3 were never recorded in DeletedObjects; they reappear on the first merge with a copy that still has them (documented in README)
- KeePassXC's history-size cap (Meta HistoryMaxSize) and Meta HistoryMaxItems are not read; pwvault uses HISTORY_MAX=10 as everywhere else
- Database-level CustomData is not merged (pwvault doesn't use it; KeePassXC-Browser keys live there — revisit in Phase 9)
- KDBX 3 ↔ 4 time re-encoding in `adopt()` is untested (pwvault and KeePassXC both write KDBX 4)

## Issues Encountered

| Issue | Resolution |
|-------|------------|
| pykeepass `.attachments` returns nothing for history versions | Test reads `Binary/Value@Ref` from the XML; merge itself was correct |
| First full-suite log lost its summary to `tail` | Re-ran with output to a file |

## Next Phase Readiness

**Ready:**
- `merge_vaults()` returns a `MergeReport` the GUI can show as-is (06-02)
- Dry run is just "don't save": the engine only touches the in-memory vault

**Concerns:**
- Not yet checked by hand: a merged vault opened in pwvault-gui
- `/cso` review of this diff still due before Phase 6 closes (ROADMAP constraint)

**Blockers:** None

---
*Phase: 06-vault-merge, Plan: 01*
*Completed: 2026-11-05*
