---
phase: 05-packaging-release
plan: 02
type: Summary
about: "pwvault"
description: "Per-user desktop launcher: pwvault-gui --install-launcher / --uninstall-launcher write or remove a .desktop entry and icon; 7 new tests; full suite 164 OK"
---

# Phase 5 Plan 02: Desktop launcher Summary

**`pwvault-gui --install-launcher` adds pwvault to the app menu for the current user, and `--uninstall-launcher` removes exactly its two files. No root, no packaging changes.**

## Acceptance criteria

| Criterion | Result |
|---|---|
| AC-1: install writes valid desktop entry and icon | Pass: test checks Type, Name, Icon, Categories (Utility, Security), Exec; `desktop-file-validate` passes (one advisory hint, below); SVG well-formed |
| AC-2: install repeatable, other files untouched | Pass: second install gives identical bytes; a sibling `.desktop` file is unchanged |
| AC-3: uninstall removes only pwvault's files; absent is OK | Pass: exit 0 and "Nothing to remove." when absent |
| AC-4: Exec works from the desktop's PATH | Pass: absolute path when `pwvault-gui` is on PATH; bare name otherwise; paths with spaces are quoted |

## Notes

- `desktop-file-validate` hints that `Security` is best paired with `Settings` or `System`. Kept `Security` because the plan requires it.
- In this checkout `pwvault-gui` isn't on PATH, so the installed Exec is the bare name. After a pip install it becomes the absolute path.
- Flags are read from `sys.argv` rather than argparse, as the GUI takes only one optional vault path.

## Files

- `pwvault_gui.py`: `ICON_SVG`, `DESKTOP_ENTRY`, `launcher_paths`, `install_launcher`, `uninstall_launcher`, flag handling in `main`
- `tests/test_desktop_launcher.py` (new, 7 tests)
