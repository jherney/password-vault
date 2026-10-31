---
phase: 04-security-review
plan: 03
type: Summary
about: "pwvault"
description: "QA pass on CLI and GUI: 3 defects fixed with regression tests, 1 deferred (trash restore group)"
---

# Phase 4 Plan 03: QA pass Summary

**Ran 29 CLI and 10 GUI paths on scratch vaults. Fixed 4 defects, each with a regression test. Full suite: 156 tests OK.**

## Changes

| Defect | Fix | Test |
|---|---|---|
| CLI-01: `export` overwrote an existing file (medium) | refuse existing path (`pwvault.py` `export`) | `tests/test_cli_qa.py` `test_export_never_overwrites_an_existing_file` |
| CLI-02: `add` saved an untitled entry (low) | refuse blank title and URL (`cmd_add`) | `test_add_refuses_an_entry_with_no_title_or_url` |
| GUI-01: quit left idle-lock and clipboard timers pending (low) | `quit()` cancels both (`pwvault_gui.py`) | `tests/test_gui_qa.py` `test_quit_cancels_pending_lock_and_clipboard_timers` |

Existing test adjusted: `test_csv_export_is_spreadsheet_safe_and_reimports_exactly` re-exported to the same path, which the CLI-01 guard now refuses. It now writes the raw export to its own file. The guard was not weakened.

## Follow-up: CLI-03 (was deferred)

`trash restore` now returns an entry to its original group. Trashing records the group in the standard `PreviousParentGroup` element (the same one KeePassXC writes). Restore uses it when the group still exists outside the bin, and otherwise falls back to Root. Checked with keepassxc-cli 2.8.0: the trashed entry opens and reads correctly.

Details, including accepted items, in `04-03-QA.md`.

## Verification

- Focused: `test_pwvault.ImportExportTests`, `test_cli_qa`, `test_gui_qa`: 12 tests OK.
- Full suite: `xvfb-run -a python3 -m unittest discover -s tests`: Ran 156 tests, OK, exit 0 (151 before + 5 new regression tests).
