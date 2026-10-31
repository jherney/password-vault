---
phase: 03-gui-polish
plan: 01
subsystem: ui
tags: [tkinter, backups, theme, wcag, keyboard-shortcuts]
requires:
  - phase: 01-safe-saves-backups
    provides: list_backups() and Vault.restore() used by the Backups dialog
  - phase: 02-totp-codes
    provides: TOTP row, Ctrl+T and countdown kept working in both palettes
provides:
  - Database > Backups dialog (Ctrl+Shift+B) that lists backups newest first and restores one after confirmation
  - Light and dark palettes; default follows KDE window colour or GNOME color-scheme
  - Theme button in the top bar (System / Light / Dark), saved in ~/.config/pwvault/settings.ini, applied live
  - WCAG contrast tests for both palettes; README shortcut table and theme/backup notes
affects: [phase-4-security-review, phase-5-packaging]
tech-stack:
  added: []
  patterns:
    - "Palette chosen at startup and switchable live: use_palette() sets the module colours, switch_palette() re-applies styles and recolours open widgets by value"
    - "Colour values must be unique within a palette, because the live switch maps each old value to its counterpart"
key-files:
  created:
    - tests/test_gui_polish.py
    - .paul/phases/03-gui-polish/03-01-PLAN.md
    - .paul/phases/03-gui-polish/03-01-SUMMARY.md
  modified:
    - pwvault_gui.py
    - README.md
    - .gitignore
    - .paul/STATE.md
    - .paul/ROADMAP.md
    - .paul/paul.toml
    - .paul/ledger.toml
key-decisions:
  - "Restore goes through Vault.restore(); the GUI never copies backup files itself"
  - "Theme follows the desktop by default; an in-app choice overrides it and is stored outside the vault"
  - "Dark accent darkened from #6c8cff to #4263eb so white button text reaches 4.98:1 (was 3.07:1) — user's choice"
  - "Light panel colour #ffffff changed to #fdfdfe so each palette's values are unique for the live switch"
  - "Theme choice applies live rather than on next start (added after the checkpoint, at the user's request)"
patterns-established:
  - "New colour-bearing widgets read palette names at creation time, so they pick up the current palette after a switch"
duration: ~2 sessions (approximate)
started: 2026-10-30
completed: 2026-10-30
description: "GUI polish: Backups restore dialog, desktop-following light/dark palettes, a live Theme button, contrast tests, and shortcut docs"
type: Summary
about: "pwvault"
---

# Phase 3 Plan 01: GUI polish Summary

**Backups restore dialog, light and dark themes with a live Theme button, WCAG contrast tests for both palettes, and consistent label spacing in the dialogs. The human checkpoint was approved by the user on their KDE desktop.**

## Performance

| Metric | Value |
|--------|-------|
| Duration | ~2 sessions (approximate) |
| Started | 2026-10-30 |
| Completed | 2026-10-30 (approximate) |
| Tasks | 3 auto + 1 human-verify checkpoint (approved by the user) |
| Files modified | 8 (plus 3 created) |

## Acceptance Criteria Results

| Criterion | Status | Notes |
|-----------|--------|-------|
| AC-1: Restore a vault from a backup in the GUI | Pass (tests) | Newest first, confirmation before restore, wrong-key backup refused with no change, empty state disables Restore, Ctrl+Shift+B and menu entry (`test_lists_backups_newest_first`, `test_restore_replaces_the_vault_after_confirmation`, `test_cancelled_confirmation_changes_nothing`, `test_refused_backup_shows_error_and_changes_nothing`, `test_no_backups_says_so_and_disables_restore`, `test_ctrl_shift_b_opens_backups_when_unlocked`, `test_database_menu_has_backups_entry`). After a restore the vault locks and the user unlocks to see restored entries, rather than reloading in place. |
| AC-2: Palette follows the desktop theme | Pass | KDE luminance, GNOME fallback, dark fallback on unreadable input (`ThemeTests`). Live switch added later (see Deviations). Approved by the user on their KDE desktop in both themes. |
| AC-3: Both palettes readable; shortcuts complete | Pass | Contrast ≥ 4.5:1 for every text pair in both palettes (`test_both_palettes_meet_4_5_to_1`). README shortcut table lists Ctrl+Shift+B. Entry and Change-master dialogs use one label gutter (`padx=(0, 10)`). Approved by the user: shortcuts Ctrl+T, Ctrl+C and Ctrl+F work in both themes. |

Test results:
- `python3 -m unittest discover -s tests -p test_gui_polish.py`: 23 tests, OK (latest run, after the spacing change)
- `python3 -m unittest discover -s tests -p test_pwvault.py`: 50 tests, OK (latest run, after the spacing change)
- Full suite `xvfb-run -a python3 -m unittest discover -s tests -v`: 141 tests, OK. This run predates the Theme button and live switch; the two GUI files were rerun after those changes.
- Visual check: Xvfb screenshots of the main window and Backups dialog in light and dark, plus a live switch with the dialog open (dialog recoloured). Desktop check on a real KDE session not done.

## Accomplishments

- Database > Backups (Ctrl+Shift+B) lists the vault's backups and restores one after confirmation, going through `Vault.restore()`.
- The GUI follows KDE or GNOME light/dark by default. A Theme button in the top bar overrides it and applies immediately to open windows and dialogs.
- WCAG contrast tests cover both palettes, and the dark accent-button label now reaches 4.98:1.

## Files Created/Modified

| File | Change | Purpose |
|------|--------|---------|
| `pwvault_gui.py` | Modified | BackupsDialog, theme detection, settings read/write, use_palette/switch_palette, Theme button |
| `tests/test_gui_polish.py` | Created | Backups, theme detection, saved choice, live recolour, palette uniqueness, contrast |
| `README.md` | Modified | Shortcut row, theme and backup notes |
| `.gitignore` | Modified | `graphify-out/` |
| `.paul/phases/03-gui-polish/03-01-PLAN.md` | Created | Plan (committed in 0e16557) |
| `.paul/STATE.md`, `ROADMAP.md`, `paul.toml`, `ledger.toml` | Modified | Planning state (committed in 0e16557); not yet updated for this summary |

## Decisions Made

| Decision | Rationale | Impact |
|----------|-----------|--------|
| Restore via `Vault.restore()` only | One code path for verification and the pre-restore backup | Wrong-key backups are refused, nothing changes |
| Dark accent `#6c8cff` → `#4263eb` (hover `#3652c8`) | Contrast 3.07:1 → 4.98:1 for the accent-button label; user chose this option | Dark look is slightly deeper than the original constants |
| Light panel `#ffffff` → `#fdfdfe` | The live switch maps each colour value to its counterpart; two roles sharing `#ffffff` would be mapped wrongly | Visually identical; enforced by `test_each_palette_has_distinct_colours` |
| In-app Theme button stored in `~/.config/pwvault/settings.ini` | Keeps the choice out of the vault file; user asked for an override | No change to vault format |

## Deviations from Plan

- **Live theme switch and Theme button added (not in plan).** The plan excluded live switching. The user asked for a control after the checkpoint, and then for it to apply immediately. It went in as its own change within this plan.
- **Dark palette values changed.** The plan kept the dark palette exactly as the original constants. The accent and its hover colour changed (see Decisions).
- **Spacing done after the checkpoint.** Labels in the entry dialog and the Change master key dialog had uneven gutters (only Title and Username had one, so "Attachments" touched its field). All now share one gutter. Button gaps were already 8 px across dialogs, and the detail panel already had consistent row spacing, so neither changed.
- **Restore locks the vault.** The plan said the GUI should reload entries. It locks instead, so the user unlocks to see the restored file.
- **Known-gap test removed.** The contrast test no longer pins the old 3.07:1 exception, because the accent change fixed it.

## Issues Encountered

- Light-palette panel and label colours shared `#ffffff`, which would have broken the live recolour. Fixed by the panel change above.
- The GUI test module imports and the test discovery need `-p <file>` from the `tests` directory; running the module names directly failed.

## Next Phase Readiness

**Ready:**
- Phase 4 (security review) can review the restore path (`Vault.restore`) and the settings file, which is the only new file the app writes.

**Concerns:**
- The Backups restore locks the vault rather than reloading it in place. The user approved the flow as it is.
- The new settings file is the only file the GUI writes outside the vault and its backups.

**Blockers:**
- None.

---
*Built with PAUL Framework v1.4 · https://chrisai.cv/skool · https://youtube.com/@chris-ai-systems*
*Phase: 03-gui-polish, Plan: 01*
*Completed: 2026-10-30*
