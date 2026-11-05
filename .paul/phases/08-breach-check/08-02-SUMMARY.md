---
phase: 08-breach-check
plan: 02
subsystem: ui/breach-check
tags: [tkinter, treeview, breach-check, gui]

requires:
  - phase: 08-breach-check (08-01)
    provides: check_vault(), Finding, checked_entries(), BreachStore and its missing/damaged VaultError
provides:
  - CheckDialog (Database > Check passwords…) listing breached, reused and weak entries
  - App.open_check(); double-click / Show entry / Return jumps to the entry via show_group()
  - make_check_vault() shared test fixture (tests/test_breach.py)
affects: [08-03 phase /cso]

tech-stack:
  added: []
  patterns:
    - "Report dialogs call the engine (check_vault) and only format; no check logic in the GUI"
    - "Jump-to-entry from a modal dialog: destroy the dialog, then App.show_group(group, select=entry)"

key-files:
  created: [tests/test_gui_breach.py]
  modified: [pwvault_gui.py, tests/test_breach.py, README.md, CHANGELOG.md]

key-decisions:
  - "Show entry closes the report and selects the entry in the main window (user choice at PLAN)"
  - "Issues joined with '; ' so a reused row can list names with commas"

patterns-established:
  - "GUI tests import module-level fixtures and BreachBase from test_breach, never a test class"

duration: ~15min
completed: 2026-11-05T19:22:32-04:00
description: "GUI Database > Check passwords… report of breached, reused and weak entries; double-click jumps to the entry"
type: Summary
about: "pwvault"
---

# Phase 8 Plan 02: GUI password check report Summary

**Database > Check passwords… shows breached, reused and weak entries from `check_vault()`; double-click, Show entry or Return closes it and selects the entry in the main window.**

## Performance

| Metric | Value |
|--------|-------|
| Duration | ~15 min (plan 19:07, unify 19:22) |
| Completed | 2026-11-05 |
| Tasks | 3 of 3 (2 auto, 1 checkpoint approved) |
| Files modified | 5 |

## Acceptance Criteria Results

| Criterion | Status | Notes |
|-----------|--------|-------|
| AC-1: Report lists flagged entries | Pass | `test_lists_flagged_entries_without_showing_passwords`: exact rows (title, username, group path, issues), summary "4 of 5 entries flagged (1 breached, 2 reused, 1 weak).", no password in any label, button or cell |
| AC-2: Without a breach list | Pass | `test_without_a_breach_list`, `test_damaged_breach_list`; every report opened with `socket.socket` patched to raise |
| AC-3: Jump to an entry | Pass | `test_double_click_jumps_to_the_entry` (real clicks on a subgroup row), `test_show_entry_button_and_return`: dialog gone, group shown, search cleared, entry selected |
| AC-4: Clean vault, lock, no vault | Pass | `test_clean_vault`, `test_lock_closes_the_report`, `test_open_check` |
| AC-5: Looks right in both themes | Pass | Approved by the user from screenshots (light/dark, with and without a list, after a jump) |

## Accomplishments

- Every flagged entry is one double-click from the report, in any group.
- The report works without the 16 GB list (reused and weak still shown) and explains how to get it.
- The GUI adds no check logic: it formats `check_vault()` results.

## Task Commits

Uncommitted on branch `breach-gui` at UNIFY time.

| Task | Commit | Type | Description |
|------|--------|------|-------------|
| Task 1: CheckDialog and menu item | (pending) | feat | Dialog, `open_check()`, README, CHANGELOG |
| Task 2: GUI tests | (pending) | test | tests/test_gui_breach.py, shared fixture |

## Files Created/Modified

| File | Change | Purpose |
|------|--------|---------|
| `pwvault_gui.py` | Modified (+79) | `CheckDialog`, Database menu item, `App.open_check()` |
| `tests/test_gui_breach.py` | Created (8 tests) | Report, no list, damaged list, jumps, clean vault, lock, open_check |
| `tests/test_breach.py` | Modified | `CheckTests.make_vault` moved to module-level `make_check_vault(tmp)` |
| `README.md` | Modified | GUI paragraph in "Checking for breached passwords" |
| `CHANGELOG.md` | Modified | GUI line under Unreleased |

## Verification Results

```
test_breach.py:       21 passed, 10 subtests passed
test_gui_breach.py:    8 passed,  2 subtests passed
test_gui_merge.py:     9 passed
test_gui_polish.py:   23 passed, 16 subtests passed
test_gui_yubikey.py:  12 passed
test_totp.py:         54 passed, 57 subtests passed
test_cli_qa.py:        4 passed
```
(xvfb-run, one file at a time.) grep: CheckDialog never reads `entry.password`. `graphify update .` run.

## Decisions Made

| Decision | Rationale | Impact |
|----------|-----------|--------|
| Show entry closes the report (no edit-on-top, no live re-check) | User choice at PLAN | Reopen the report to re-check |
| `/cso` split into 08-03 | User chose the complex track | Phase 8 is 3 plans |

## Deviations from Plan

### Summary

| Type | Count | Impact |
|------|-------|--------|
| Wording/format | 2 | Cosmetic |
| Duplication accepted | 1 | Small |

1. **Issues separator:** "; " between issues (plan example used ", ") so "reused with Mail, Forum" stays readable.
2. **No-list note:** the store's error already says to run `pwvault breach update`, so the hint says only that it runs in a terminal and downloads ~55 GB once (plan wording repeated the command).
3. **Summary counts:** `CheckDialog.summary()` repeats the few lines of counting in `cmd_check()`; sharing them would change pwvault.py, which the plan's boundaries protect.

### Review fix (CodeRabbit, PR #9)

- The report never took keyboard focus, so Return/Escape could go to the main window if the window manager left focus there. It now calls `focus_force()` on the list (or the dialog when empty). The Return test no longer forces focus itself; it presses Return wherever the focus is, and failed before the fix.

### Deferred Items

- The no-list note shows the shared VaultError text with literal backticks (`` `pwvault breach update` ``) and wraps mid-command; approved as-is at the checkpoint.

## Issues Encountered

| Issue | Resolution |
|-------|------------|
| Tk refuses `event_generate("<Double-1>")` | Test sends two real presses on the row's bbox |
| Generated `<Return>` ignored without focus | Test focuses the tree first |
| run-password-vault driver needs openbox (not installed here) | Screenshots taken with a scratch script under xvfb-run + ImageMagick `import` |
| `breach import` of a two-hash test list refused (20 GB free check, 3.1 GB in /tmp) | Expected; the screenshot script set `PWNED_MIN_FREE = 0` like the tests |

## Next Phase Readiness

**Ready:**
- Phase 8 code complete (CLI 08-01, GUI 08-02) for the 08-03 `/cso` pass

**Concerns:**
- `import_breach_list` applies the 20 GB free-space floor even to small files; harmless for the real list, worth a look in 08-03
- Tk Variable finalizer warning when GUI tests and download tests share one pytest process (objects collected on a worker thread); tests pass

**Blockers:**
- None

---
*Built with PAUL Framework v1.4 · https://chrisai.cv/skool · https://youtube.com/@chris-ai-systems*
*Phase: 08-breach-check, Plan: 02*
*Completed: 2026-11-05*
