---
phase: 08-breach-check
plan: 01
subsystem: security/breach-check
tags: [hibp, pwned-passwords, sha1, offline, bisect, cli]

requires:
  - phase: 01-backups
    provides: BACKUP_STAMP (store directory names)
provides:
  - Compact offline store of HIBP Pwned Passwords (68 bits per hash, no counts) with resumable download and file import
  - BreachStore.contains() reading two index entries and one range slice
  - check_vault(vault, store) -> list[Finding] (breached, reused, weak), for the 08-02 GUI
  - CLI `pwvault check`, `pwvault breach update|import|status`
affects: [08-02 GUI report dialog]

tech-stack:
  added: []
  patterns:
    - "Large rebuildable data lives in $XDG_CACHE_HOME, never next to the vault"
    - "A finished build becomes live by one atomic symlink swap (current -> store-<stamp>); readers resolve the link once"
    - "Resume point = length of the fsynced index; anything past the last recorded offset is cut back"

key-files:
  created: [tests/test_breach.py]
  modified: [pwvault.py, README.md, CHANGELOG.md]

key-decisions:
  - "Store in ~/.cache/pwvault/pwned (XDG_CACHE_HOME), not ~/.local/share: it is large and can always be downloaded again"
  - "Store directories + `current` symlink instead of renaming partial files over live ones"
  - "Ranges are fetched gzip-compressed (about half the transfer)"

patterns-established:
  - "Network code takes the fetcher as a parameter; tests pass a fake one and patch socket.socket to prove a check is offline"

duration: not recorded (APPLY ran in an earlier session)
completed: 2026-11-05T18:31:06-04:00
description: "Offline HIBP breach store (~16 GB, resumable download or import) and `pwvault check` flagging breached, reused and weak passwords"
type: Summary
about: "pwvault"
---

# Phase 8 Plan 01: Breach store and `pwvault check` Summary

**Offline HIBP breach store (~16 GB, resumable download or import) and `pwvault check` flagging breached, reused and weak passwords with no network use during the check.**

## Performance

| Metric | Value |
|--------|-------|
| Duration | Not recorded (APPLY ran in an earlier session) |
| Completed | 2026-11-05T18:31:06-04:00 (commit 9fb30f8) |
| Tasks | 2 of 2 auto tasks completed; checkpoint (AC-5) deferred |
| Files modified | 4 (plus .paul notes) |

## Acceptance Criteria Results

| Criterion | Status | Notes |
|-----------|--------|-------|
| AC-1: Store build and lookup | Pass | `test_import_then_lookup`, `test_download_matches_import_byte_for_byte`, `test_lookup_reads_one_range_only` (two reads: 16 index bytes, then that range's records). Location is the cache dir, not the data dir (deviation 1); `test_store_defaults_to_the_cache_dir` |
| AC-2: Interrupted or bad downloads never leave a broken store | Pass | `test_old_store_answers_until_a_rebuild_finishes`, `test_interrupted_download_resumes_after_the_last_finished_batch`, `test_a_crash_mid_batch_is_cut_back_on_resume`, `test_bad_ranges_are_retried`, `test_ranges_that_stay_bad_fail_the_update` (error names the range) |
| AC-3: `pwvault check` reports breached, reused, weak | Pass | `test_check_vault_findings`, `test_cli_check_with_store_and_no_network` (output has no password) |
| AC-4: No network during the check, clear message without a store | Pass | Both CLI check tests run with `socket.socket` patched to raise; `test_cli_check_without_store` reports reused/weak and the `breach update` hint |
| AC-5: Real download (human-verify) | **Deferred** | User chose to defer at UNIFY (2026-11-05). No store exists on this machine; the real HIBP API has not been used yet |

## Accomplishments

- A check never touches the network: the whole list (all 1,048,576 ranges, the same for everyone) is downloaded once and looked up locally.
- Downloads survive Ctrl+C, crashes and bad responses: batches of 4096 ranges are fsynced before being recorded, a resume cuts back any half-written batch, and the old store stays live until the new one is swapped in.
- `check_vault()` is UI-independent and returns `Finding` objects that 08-02 can show in the GUI.

## Task Commits

All work is in one commit on branch `breach-check`, open as PR #8 into main.

| Task | Commit | Type | Description |
|------|--------|------|-------------|
| Task 1: Breach store | `9fb30f8` | feat | Store format, build/resume, download, import, lookup |
| Task 2: CLI commands | `9fb30f8` | feat | `check`, `breach update/import/status`, README, CHANGELOG |

## Files Created/Modified

| File | Change | Purpose |
|------|--------|---------|
| `pwvault.py` | Modified (+~400 lines, nothing removed) | Breach store section, `check_vault`, `cmd_check`, `cmd_breach`, argparse entries |
| `tests/test_breach.py` | Created (20 tests) | Store, download, resume, check and CLI tests, all offline |
| `README.md` | Modified | "Checking for breached passwords" section and command table rows |
| `CHANGELOG.md` | Modified | Unreleased entry |

## Decisions Made

| Decision | Rationale | Impact |
|----------|-----------|--------|
| Cache dir (`$XDG_CACHE_HOME/pwvault/pwned`) instead of data dir | 16 GB that can always be re-downloaded is cache, not user data; backup tools skip it | README/CHANGELOG say `~/.cache/pwvault/pwned/` |
| `store-<stamp>/` directories, `current` symlink, `partial/` build dir | One atomic `os.replace` of a symlink switches stores; a reader resolves it once and can't mix files from two stores | Old stores removed after the swap |
| gzip transfer | HIBP serves ranges gzip-compressed at about half the size | Damaged gzip is a retried error (`test_damaged_gzip_is_an_error`) |

## Deviations from Plan

### Summary

| Type | Count | Impact |
|------|-------|--------|
| Design changes | 4 | Better durability and correct size figures; no scope creep |
| Scope additions | 1 | gzip transfer, small |
| Deferred | 1 | AC-5 real download |

**Total impact:** Same commands and behavior as planned; storage location, layout and size figures differ from the plan text.

1. **Store location:** plan said `$XDG_DATA_HOME/pwvault/pwned/` (default `~/.local/share`); built in `$XDG_CACHE_HOME/pwvault/pwned/` (default `~/.cache`).
2. **Build layout:** plan described `hashes.bin.partial` / `index.partial` / `progress` renamed over live files; built as `partial/` (resume point is the fsynced `index.bin` length, no progress file), renamed to `store-<stamp>/` and made live through the `current` symlink.
3. **Size:** plan estimated 6–12 GB and a 16 GB free-space minimum; HIBP has ~2.6 billion hashes, so the store is ~16 GB (~55 GB downloaded) and the minimum is 20 GB.
4. **Range validation:** plan required suffixes strictly increasing within a range; built to sort each range and reject duplicates or empty ranges instead (`test_ranges_in_any_order_are_stored_sorted`). Import files must still be in strict hash order.
5. **Addition:** gzip `Accept-Encoding` for range downloads.

### Cleanup after APPLY (this session)

`/clean-code` pass before commit: lookup uses `bisect` instead of a hand-written search; `_BreachBuild._make_current()`, `_print_finding()` and `_print_breach_status()` split out; one `BreachStore.DAMAGED` message. It also fixed a file-descriptor leak when `BreachStore()` failed to open the index after opening the hashes file. Full suite passed afterwards (252 tests, 15 files, run per file).

### Deferred Items

- AC-5: real `pwvault breach update` against the HIBP API (with one Ctrl+C and resume), `breach status`, and `check` on the real vault.

## Issues Encountered

| Issue | Resolution |
|-------|------------|
| Full suite exceeds a 15-minute single run | Run per file; slowest are test_totp (~3.5 min), test_pwvault and test_merge (~2+ min each) |

## Boundaries

`strength()`, `Vault._write()`, YubiKey, merge and backup code untouched (diff of pwvault.py against main removes no lines). `check` and `breach` never write the vault. No new dependencies.

## Next Phase Readiness

**Ready:**
- `check_vault()` and `Finding` for the 08-02 GUI report dialog
- `BreachStore` raises a `VaultError` with the `breach update` hint when there is no list, which the GUI can show as-is

**Concerns:**
- The downloader has never run against the real API (AC-5); rate limits or response details may differ from the fakes
- `check_vault` calls `strength()` and a store lookup per entry; fine for normal vaults, not measured on very large ones

**Blockers:**
- None for 08-02

---
*Built with PAUL Framework v1.4 · https://chrisai.cv/skool · https://youtube.com/@chris-ai-systems*
*Phase: 08-breach-check, Plan: 01*
*Completed: 2026-11-05*
