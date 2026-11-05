---
phase: 07-yubikey-unlock
plan: 02
subsystem: ui
tags: [tkinter, yubikey, settings, gui]

requires:
  - phase: 07-yubikey-unlock
    provides: Vault/load_kdbx/open_other_copy yubikey=, challenge_response driver (07-01)
provides:
  - YubiKeyField on the unlock/create screens, Change master key and Merge another copy
  - pwvault.yubikey_touch_prompt hook; GUI touch_prompt() context manager
  - Remembered slot per vault (settings.ini, hashed path -> slot number); read-modify-write settings
  - sentence() for GUI error messages (no more str.capitalize lowercasing)
affects: [08 breach check GUI dialog, 09 browser autofill (unlock state)]

tech-stack:
  added: []
  patterns:
    - "Blocking hardware waits stay on the Tk thread; the prompt is drawn from the driver's keepalive callback"
    - "Any label a touch prompt can grey must set Error.TLabel explicitly when it shows an error"

key-files:
  created: [tests/test_gui_yubikey.py]
  modified: [pwvault.py, pwvault_gui.py, README.md, CHANGELOG.md]

key-decisions:
  - "Remembered slot keyed by a SHA-256 prefix of the resolved vault path (INI keys can't hold every path; the file needn't list vaults)"
  - "Change master key with an absent new YubiKey uses the existing failed-save path (error + reload from disk); nothing is written"
  - "Work went through a PR (#6, branch yubikey-gui) for a CodeRabbit review"

duration: ~1.5h
completed: 2026-11-05
description: "YubiKey support in the GUI: slot choice on unlock/create (remembered per vault), in Change master key and Merge, a visible touch prompt; plus GUI error messages that keep their capitals"
type: Summary
about: "pwvault"
---

# Phase 7 Plan 02: YubiKey in the GUI Summary

**The GUI can now create, unlock, re-key and merge YubiKey vaults: a slot choice on the unlock/create screens (remembered per vault), in Change master key and in Merge another copy, with "Touch your YubiKey…" drawn while the key waits. Reviewed by CodeRabbit on PR #6; its one finding is fixed.**

## Performance

| Metric | Value |
|--------|-------|
| Tasks | 2 auto + checkpoint (approved) |
| Tests | 229 on the last full run (+11 GUI YubiKey); +1 regression test after the CodeRabbit fix |
| Commits | `00056a6` (feature), `0579ff2` (CodeRabbit fix), on `yubikey-gui` / PR #6 |

## Acceptance Criteria Results

| Criterion | Status | Notes |
|-----------|--------|-------|
| AC-1: Unlock and create with a YubiKey | Pass | Unlock with slot works, "No YubiKey" gives the wrong-password message; create with a slot (short password allowed) |
| AC-2: Remembered slot, no secrets | Pass | Preselected after lock and restart; other vault unaffected; settings.ini holds a path hash + slot only; theme and slots keep each other |
| AC-3: Change master key and Merge | Pass | Add/change/remove via the dialog, remembered slot follows; Merge with the other copy's own slot |
| AC-4: Touch prompt and errors | Pass | Prompt visible during the call; driver errors inline, password cleared, file unchanged; absent new key on re-key writes nothing |
| AC-5: Look and feel | Pass | User approved the GUI checkpoint (2026-11-05) |

## Files Created/Modified

| File | Change | Purpose |
|------|--------|---------|
| `pwvault.py` | Modified | `yubikey_touch_prompt()` hook called from the driver's keepalive |
| `pwvault_gui.py` | Modified | `read_settings/write_setting`, `remembered_yubikey/remember_yubikey`, `touch_prompt()`, `YubiKeyField`, `sentence()`; unlock screen, ChangeMasterDialog, MergeDialog wiring |
| `tests/test_gui_yubikey.py` | Created | 12 tests (settings, hook, unlock/create, remembered slot, re-key, merge, touch prompt, errors, error style) |
| `README.md`, `CHANGELOG.md` | Modified | GUI YubiKey paragraph; Unreleased entries |

## Deviations from Plan

| Type | Count | Impact |
|------|-------|--------|
| Auto-fixed (found while testing) | 1 | GUI-wide message formatting |
| Review fix (CodeRabbit) | 1 | 4 lines + regression test |
| Simplification | 1 | Re-key failure path |

- **`str.capitalize()` bug (pre-existing):** every GUI error lowercased all but the first letter (paths, "YubiKey"). Replaced in 11 places by `sentence()`.
- **CodeRabbit PR #6, "Restore the error style after a failed merge." (Minor):** valid; `touch_prompt()` leaves the label muted. Fixed at the flagged line and three sibling lines (merge "choose a file", Change master key mismatch and weak-key checks); regression test fails without the fix.
- **Remembered-slot key** is a hash of the path, not the path (plan said "vault path → slot").
- **Re-key with an absent YubiKey** reuses `app.save()`'s failure path (error dialog, lock, reload) instead of a new inline error path; nothing is written either way.

### Deferred Items

- Not exercised with a physical YubiKey (07-01 AC-5 still open)
- No serial selection in the GUI (CLI `--yubikey SLOT:SERIAL` only)

## Next Phase Readiness

**Ready:** Phase 7 complete. `/cso --diff --base 4414816` (run 1793911242861-c63a7360f2ca517d): partial (binary fixture unread, no hardware), no supported findings; gitleaks and OSV 0 candidates. Its one hardening note (a crafted header with missing Argon2 fields or a salt over 63 bytes crashed instead of erroring) was fixed at phase close with a test.
**Concerns:** Real-hardware behavior of the driver and of the Tk-thread touch wait is untested.
**Blockers:** None

---
*Phase: 07-yubikey-unlock, Plan: 02*
*Completed: 2026-11-05*
