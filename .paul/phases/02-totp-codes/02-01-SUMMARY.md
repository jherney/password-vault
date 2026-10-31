---
phase: 02-totp-codes
plan: 01
subsystem: security
tags: [totp, rfc6238, keepassxc, otp, tkinter, argparse]
requires:
  - phase: 01-safe-saves-backups
    provides: all vault writes go through Vault._write() (backup first)
provides:
  - stdlib RFC 6238 TOTP generator (SHA-1/256/512, 6-10 digits, Steam)
  - KeePassXC-compatible TOTP storage in the protected `otp` attribute, with legacy read support
  - `pwvault totp` CLI (copy, --show, --set, --clear) and a TOTP line in `get`
  - GUI live code with countdown, Copy button, Ctrl+T, and a TOTP field in the entry dialog
affects: [phase-3-gui-polish, phase-4-security-review]
tech-stack:
  added: []
  patterns:
    - "TOTP secret lives only in the protected `otp` field; legacy TOTP Seed/Settings are read but dropped when a new secret is set"
    - "Callers normalize input (normalize_totp) before update_entry/add_entry; restore_history writes stored values back byte for byte"
key-files:
  created:
    - tests/test_totp.py
    - .paul/phases/02-totp-codes/02-01-SUMMARY.md
  modified:
    - pwvault.py
    - pwvault_gui.py
    - README.md
key-decisions:
  - "TOTP via stdlib only (hmac, hashlib, base64, struct): no new runtime dependency"
  - "Store secrets as KeePassXC writes them (otpauth:// URI in `otp`); never rewrite a valid URI"
  - "HOTP (counter-based) codes are refused with a clear error, not supported"
  - "Reading a code (`totp` without --set/--clear) does not save the vault, so it creates no backup"
patterns-established:
  - "Single secret per entry: setting or clearing `otp` removes legacy TOTP Seed/Settings in the same history version"
duration: ~1 session
started: 2026-10-30T20:12:51-03:00
completed: 2026-10-30T20:20:00-03:00
description: "TOTP codes via KeePassXC's `otp` attribute in the CLI and GUI, RFC 6238 generator checked against the RFC vectors"
type: Summary
about: "pwvault"
---

# Phase 2 Plan 01: TOTP codes Summary

**TOTP secrets stored in KeePassXC's `otp` attribute; the CLI and GUI show and copy live codes, checked against the RFC 6238 vectors and 54 TOTP tests.**

## Performance

| Metric | Value |
|--------|-------|
| Duration | ~1 session (approximate) |
| Started | 2026-10-30T20:12:51-03:00 |
| Completed | 2026-10-30T20:20:00-03:00 (approximate) |
| Tasks | 3 auto + 1 human-verify checkpoint, all completed |
| Files modified | 5 (plus 1 created test file) |

## Acceptance Criteria Results

| Criterion | Status | Notes |
|-----------|--------|-------|
| AC-1: Codes match RFC 6238 | Pass | All 18 Appendix B vectors (SHA-1/256/512), 6-digit variants, seconds-left, Steam vector (`test_rfc_6238_vectors`, `test_seconds_left`, `test_steam_code`) |
| AC-2: KeePassXC formats read the same way | Pass | otpauth URI, KeeOtp `key=…`, legacy TOTP Seed/Settings incl. `30;S`; `otp` wins over legacy; bad input raises VaultError (`test_otpauth_uri_variants`, `test_keeotp_format`, `test_legacy_fields`, `test_otp_wins_over_legacy`, `test_errors_name_the_problem`) |
| AC-3: Setting and clearing a secret | Pass | Bare base32 becomes the KeePassXC URI; legacy fields dropped; history round trip; clear removes the element; invalid refused (`test_bare_secret_becomes_keepassxc_uri`, `test_clear_removes_the_field`, `test_changes_are_history_versions`, `test_invalid_refused`) |
| AC-4: CLI | Pass | `totp` copy/--show/--set/--clear, no-TOTP error, `get` line only when set; `totp --help` shows the new flags (`test_copies_the_code`, `test_show_prints_grouped_code_never_the_secret`, `test_set_invalid_secret_changes_nothing`, `test_clear_confirm_and_cancel`, `test_get_mentions_totp_only_when_set`) |
| AC-5: GUI | Pass | Live code and countdown, Ctrl+T, Copy, timer stops on reselect/lock, unreadable note, dialog set/clear/refuse, legacy storage kept unless TOTP changes (`test_live_code_and_countdown`, `test_timer_stops_on_reselect_and_lock`, `test_ctrl_t_and_copy_button_copy_the_current_code`, `test_dialog_keeps_legacy_storage_unless_totp_changes`) |

Test results:
- `python3 -m unittest discover -s tests -p "test_totp.py"`: 54 tests, OK
- `xvfb-run -a python3 -m unittest discover -s tests -v`: 126 tests, OK (exit 0)
- Human checkpoint (phone authenticator and GUI against the same secret): approved by the user

## Accomplishments

- Entries hold TOTP secrets in the standard `otp` field, so KeePassXC-created 2FA entries now produce codes in pwvault.
- The stdlib generator matches the RFC 6238 vectors, including Steam codes.
- The CLI copies codes without saving the vault; the GUI shows a live countdown and Ctrl+T copies the current code.

## Files Created/Modified

| File | Change | Purpose |
|------|--------|---------|
| `pwvault.py` | Modified | TOTP parse/generate, `otp` storage with history, `totp` subcommand, `get` line |
| `pwvault_gui.py` | Modified | TOTP field in entry dialog, live code and countdown, Ctrl+T |
| `tests/test_totp.py` | Created | RFC vectors, format parsing, vault and CLI and GUI behavior |
| `README.md` | Modified | TOTP section, CLI rows, feature bullet |

## Decisions Made

| Decision | Rationale | Impact |
|----------|-----------|--------|
| Stdlib-only TOTP | Avoid new deps in a security tool | No change to dependency list |
| Store as KeePassXC writes it (`otp` URI) | Vault must open in KeePassXC without proprietary fields | Valid URIs are never rewritten |
| Refuse HOTP | Counter-based codes need the counter saved on each read | Clear error message; out of scope |
| Reads don't save | A read should not create a backup | `totp` copy path leaves the file untouched |

## Deviations from Plan

None recorded during APPLY. The plan's approach was followed; the test count (54 TOTP tests) and the full suite (126) are the executed results.

## Issues Encountered

None.

## Next Phase Readiness

**Ready:**
- Phase 3 (GUI polish) can build on the detail panel and entry dialog that now include TOTP rows.

**Concerns:**
- KeePassXC interop was not checked against a real KeePassXC install on this machine. Coverage rests on RFC vectors, sample entries in KeePassXC formats, and the phone check.
- TOTP is not in CSV import/export yet (LastPass `totp`, 1Password `OTPAuth`, Bitwarden `login_totp`). Deferred.
- KeePass 2's native `TimeOtp-*` fields are not read. Deferred.

**Blockers:**
- None.

---
*Built with PAUL Framework v1.4 · https://chrisai.cv/skool · https://youtube.com/@chris-ai-systems*
*Phase: 02-totp-codes, Plan: 01*
*Completed: 2026-10-30*
