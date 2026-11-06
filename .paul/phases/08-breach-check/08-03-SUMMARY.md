---
phase: 08-breach-check
plan: 03
subsystem: security/breach-check
tags: [integrity, sha256, crc32, cso, hardening]

requires:
  - phase: 08-breach-check (08-01, 08-02)
    provides: breach store, check_vault(), CheckDialog
provides:
  - Breach store format 2 (index.bin SHA-256 in meta.json, crc.bin CRC32 per range) with checks on open and lookup
  - cmd_check reports a store found damaged mid-check like a missing one
  - breach import free-space floor sized from the input file
  - GUI no-list note without backticks, command unbreakable
  - fetch_range reply and decompressed size capped at 4 MB
  - Phase 8 /cso pass (no supported findings)
affects: [Phase 9 browser autofill (/cso gaps to revisit)]

tech-stack:
  added: []
  patterns:
    - "Cache stores carry integrity data and fail closed: a mismatch raises VaultError, callers fall back to the no-list path"
    - "Network replies are read with a size cap, including after decompression"

key-files:
  created: []
  modified: [pwvault.py, pwvault_gui.py, tests/test_breach.py, tests/test_gui_breach.py, README.md, CHANGELOG.md]

key-decisions:
  - "Index SHA-256 on open + CRC32 per range on lookup; no whole-file hash of hashes.bin"
  - "Format 1 stores reported as outdated, not migrated (none exist)"
  - "Phase 8 /cso accepted at the checkpoint"

patterns-established:
  - "Mutation spot-check: remove each new check and confirm a test fails"

duration: ~45min
completed: 2026-11-05T20:21:39-04:00
description: "Breach list detects damage (index SHA-256, per-range CRC32); leftovers fixed; Phase 8 /cso: no supported findings, download size capped"
type: Summary
about: "pwvault"
---

# Phase 8 Plan 03: Breach-store integrity, leftovers and phase /cso Summary

**A damaged breach list is now reported instead of silently missing breaches; the GUI note and import free-space leftovers are fixed; the Phase 8 `/cso` pass found no supported findings and led to a 4 MB cap on downloaded ranges.**

## Performance

| Metric | Value |
|--------|-------|
| Duration | ~45 min (plan 19:40, unify ~20:20) |
| Completed | 2026-11-05 |
| Tasks | 3 auto + 1 checkpoint (accept) |
| Files modified | 6 |

## Acceptance Criteria Results

| Criterion | Status | Notes |
|-----------|--------|-------|
| AC-1: Corruption is reported, not silently missed | Pass | `test_corruption_is_reported_not_answered` (offset emptying a range, index hash, short crc.bin → open fails; flipped record byte, altered CRC → that range's lookup fails, others still answer); `test_cli_check_with_a_damaged_store`; GUI `test_breach_list_damaged_during_lookup` |
| AC-2: Build, resume and format | Pass | `store_files()` now compares crc.bin too, so download-vs-import and resume tests cover it; crash test leaves stray CRCs that resume trims; `test_format_1_store_is_outdated` |
| AC-3: Leftovers | Pass | GUI note has no backtick and contains `pwvault breach update` (Tk confirmed not to wrap at U+00A0); `test_import_needs_only_room_for_its_file` (3 GB free import OK, update refused, 1 MB free import refused) |
| AC-4: Phase /cso pass | Pass | Run 1793923911466-61bf8128ec79c1c7, report saved; no supported findings; one hardening note fixed; accepted at checkpoint |

## Accomplishments

- `check` can no longer give a confident wrong answer from a corrupted cache file.
- The import path works on machines without 20 GB free.
- Phase 8 closes with its security review done.

## Task Commits

On branch `breach-integrity`.

| Task | Commit | Type | Description |
|------|--------|------|-------------|
| Plan | `c00acc8` | docs | 08-03 plan, PR #9 merge and integrity input in STATE |
| Tasks 1–2 | `0798633` | feat | Store format 2, cmd_check fallback, import free space, GUI note |
| Task 3 fix | `60de7a4` | fix | 4 MB cap on downloaded ranges |

## Files Created/Modified

| File | Change | Purpose |
|------|--------|---------|
| `pwvault.py` | Modified | crc.bin, index SHA-256, `BreachStore._check`, CRC check in `contains`, `_sync`, `_file_sha256`, `_check_free_space(needed)`, `cmd_check` fallback, `PWNED_MAX_RANGE` cap in `fetch_range` (gzip module no longer imported) |
| `pwvault_gui.py` | Modified | `CheckDialog.as_note`, `UPDATE_COMMAND` |
| `tests/test_breach.py` | Modified | Corruption, format 1, CLI damaged, import free space, oversized reply tests; read-count and crash tests updated |
| `tests/test_gui_breach.py` | Modified | Note text, damaged-during-lookup report |
| `README.md`, `CHANGELOG.md` | Modified | Damage detection, import free space |

## Verification Results

```
test_breach.py:      26 passed, 17 subtests passed
test_gui_breach.py:   9 passed,  2 subtests passed
test_pwvault.py:     50 passed, 14 subtests passed
test_cli_qa.py:       4 passed
test_gui_merge.py:    9 passed
test_gui_polish.py:  23 passed, 16 subtests passed
test_backups.py:     20 passed
test_merge.py:       22 passed
```
Mutation spot-check: removing the per-range CRC check (3 failures), the crc.bin resume trim (1) or the index-hash check (2) each fails tests. Truncated gzip reply → "arrived damaged" (manual check). `graphify update .` run.

## /cso (run 1793923911466-61bf8128ec79c1c7)

- Scope: `--diff --base 67a13d7` (all of Phase 8), daily mode, ~2 min.
- Result: **partial; no supported findings in the assessed scope.**
- Assessed: application model, attack surface, HIBP integration, STRIDE, data classification; OWASP 2025 A01/A04/A05/A08/A10 for this diff. Dependencies, CI/CD, infrastructure, LLM, skills: not applicable (none in the diff).
- Hardening note fixed: `fetch_range` read and gunzipped replies without a limit (16 in parallel); only HIBP/its CDN or a CA-trusted MITM could exploit it, for memory exhaustion of the user's own download. Capped at 4 MB.
- Gaps: no scanners run (gitleaks, OSV, semgrep); sequential challenge (no independent agent); KeePassXC test fixture unread; untracked `.gstack/` QA output not reviewed.

## Decisions Made

| Decision | Rationale | Impact |
|----------|-----------|--------|
| Index SHA-256 + per-range CRC32 | Catches CodeRabbit's case on open and record damage on read, at ~20 ms per open and 4 B per lookup | Lookup reads index, range, CRC |
| Format 1 → "outdated", no migration | No real store exists yet | First real store is format 2 |
| Accept /cso and close Phase 8 | No supported findings; hardening applied | Scanner gap carried forward |

## Deviations from Plan

| Type | Count | Impact |
|------|-------|--------|
| Scope additions | 1 | Download size cap from /cso (small) |
| Implementation detail | 2 | See below |

1. **Download size cap** (not planned): added from the /cso challenge, with a test.
2. **cmd_check restructured** like CheckDialog (one try around opening the store and checking) so a damaged-during-lookup store falls back instead of a traceback; the plan said only that check_vault would propagate the error.
3. **Read order:** a lookup reads index (16 B), range, then CRC (4 B); the plan listed index, CRC, range.

### Deferred Items

- Run `/cso` with scanners (`gstack-cso doctor`) before a release.

## Issues Encountered

| Issue | Resolution |
|-------|------------|
| `hashlib.file_digest` is 3.11+ (CI covers 3.10) | Chunked SHA-256 helper |
| Default argument `needed=PWNED_MIN_FREE` bound at definition, ignoring the tests' patch | `needed=None`, read at call time |
| First corruption test flipped the wrong range's byte | Test targets the range's own records via its index offset |

## Next Phase Readiness

**Ready:**
- Phase 8 complete: offline breach, reuse and weakness check in CLI and GUI, integrity-checked store

**Concerns:**
- First real `breach update` against HIBP still not run (08-01 AC-5)
- /cso scanner coverage not run for Phase 8

**Blockers:**
- None

---
*Built with PAUL Framework v1.4 · https://chrisai.cv/skool · https://youtube.com/@chris-ai-systems*
*Phase: 08-breach-check, Plan: 03*
*Completed: 2026-11-05*
