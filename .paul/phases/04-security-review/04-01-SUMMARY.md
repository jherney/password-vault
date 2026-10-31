---
phase: 04-security-review
plan: 01
subsystem: security
tags: [security-audit, stride, data-classification, backups, rekey, cso]
requires:
  - phase: 01-safe-saves-backups
    provides: backups before every save; re-key purge of old-key backups
  - phase: 02-totp-codes
    provides: TOTP storage and parsing reviewed
  - phase: 03-gui-polish
    provides: Backups dialog, theme settings file, live palette switch reviewed
provides:
  - 04-01-FINDINGS.md: 12 findings with severity, location, status; every audit-scope item named
  - 04-01-THREAT-MODEL.md: STRIDE per component and trust boundary
  - 04-01-DATA-CLASSIFICATION.md: data inventory, flows, retention
  - Durable re-key purge: a crash during a master-key change no longer leaves old-key backups
affects: [phase-4-plans-02-and-03, phase-5-packaging]
tech-stack:
  added: []
  patterns:
    - "Crash-recoverable multi-step operations record a marker (digest of the file being written) before the step, and the next open finishes or discards it"
key-files:
  created:
    - .paul/phases/04-security-review/04-01-FINDINGS.md
    - .paul/phases/04-security-review/04-01-THREAT-MODEL.md
    - .paul/phases/04-security-review/04-01-DATA-CLASSIFICATION.md
    - .paul/phases/04-security-review/04-01-PLAN.md
  modified:
    - pwvault.py
    - tests/test_backups.py
    - .gitignore
    - .paul/STATE.md
    - .paul/ROADMAP.md
    - .paul/paul.toml
    - .paul/ledger.toml
key-decisions:
  - "Re-key purge is finished on the next open if the crash came after the new file was written (marker holds the new file's SHA-256)"
  - "No critical, high or medium findings; the remaining low findings are accepted or deferred to Phase 5 with reasons"
  - "*.keyx is git-ignored so a key file saved into the repo can't be committed"
patterns-established:
  - "Findings file is the single record of audit status: every scope item named, with a status even when clean"
duration: ~1 session (approximate)
started: 2026-10-30
completed: 2026-10-30
description: "Security audit of the v1.3 changes: one fix (durable re-key purge), key-file leak closed, threat model and data classification written, no critical or high findings"
type: Summary
about: "pwvault"
---

# Phase 4 Plan 01: Security audit Summary

**Audit of the v1.3 changes found no critical, high or medium issues. The one low finding that mattered (a crash could leave old-key backups after a master-key change) is fixed and tested. The threat model and data classification are written.**

## Performance

| Metric | Value |
|--------|-------|
| Duration | ~1 session (approximate) |
| Started | 2026-10-30 |
| Completed | 2026-10-30 (approximate) |
| Tasks | 3 (2 auto, 1 decision checkpoint, resolved by the user) |
| Files modified | 7 (plus 4 created) |

## Acceptance Criteria Results

| Criterion | Status | Notes |
|-----------|--------|-------|
| AC-1: Every v1.3 change audited and recorded | Pass | `04-01-FINDINGS.md` names every scope item with a status. The `/cso` run was partial (static, 600 s budget); gaps were closed by manual review. |
| AC-2: No high or critical finding without a decision | Pass | 0 critical, 0 high. F-01 fixed; the rest accepted with reasons or deferred to Phase 5. |
| AC-3: Test runs do not write key files into the repo | Pass | Full suite 151 OK after the fix; no `pwvault.keyx` appeared in the repo root. The leak could not be reproduced, so no test was changed. |

Test results:
- `python3 -m unittest discover -s tests -p test_backups.py`: 20 tests, OK (after the fix)
- `xvfb-run -a python3 -m unittest discover -s tests -v`: 151 tests, OK (exit 0)

## Accomplishments

- F-01 fixed: `Vault.save` records a marker with the SHA-256 of the new file before writing; `Vault.open` finishes the purge if the file matches, or drops the marker if the write never landed.
- Two regression tests: a crash after the write is finished on the next open; a crash before the write keeps the backups.
- Threat model (STRIDE over each component and trust boundary) and data classification (inventory, flows, retention) written.
- Every item in the audit scope reviewed by the end of the plan.

## Files Created/Modified

| File | Change | Purpose |
|------|--------|---------|
| `pwvault.py` | Modified | Re-key marker: `_write_rekey_marker`, `_finish_interrupted_rekey`, called from `save` and `open` |
| `tests/test_backups.py` | Modified | Two crash tests for the re-key purge |
| `.gitignore` | Modified | `*.keyx` |
| `.paul/phases/04-security-review/04-01-FINDINGS.md` | Created | Findings, severity, status, audit-scope table, coverage gaps |
| `.paul/phases/04-security-review/04-01-THREAT-MODEL.md` | Created | STRIDE per component |
| `.paul/phases/04-security-review/04-01-DATA-CLASSIFICATION.md` | Created | Data inventory, flows, retention |
| `.paul/phases/04-security-review/04-01-PLAN.md` | Created | Plan (approved) |

## Decisions Made

| Decision | Rationale | Impact |
|----------|-----------|--------|
| Marker holds the digest of the new file | Lets the next open tell "write landed" from "write never happened" without trusting the timing | Old-key backups are purged even after a crash; a crash before the write keeps them |
| F-01 fixed inside this plan | The user chose this at the checkpoint, though the plan said audit only | Plan 04-02 now covers only what the user asks for later |
| F-07 closed as false positive | Masked lines show RFC test-vector timestamps and a clipboard helper key, not personal data | No change to test data |
| F-11, F-12 deferred to Phase 5 | No publish workflow yet; pinning matters once publishing is added | Recorded in the findings and threat model |

## Deviations from Plan

- **Plan said audit only; F-01 was fixed.** The user directed the fix at the checkpoint ("fix F-01, close F-07, audit the gaps").
- **Task 2 changed no test.** The stray key file did not reproduce in a clean full run, so no test writing it could be identified.
- **Findings not submitted to the helper.** The `/cso` helper's `submit` step was not run, because the run's budget ran out first. The findings were written from the helper's read-only output and manual review.
- **Follow-up review was manual.** The gap items (`cmd_backup`, `KeyFileField.new`, the TOTP field, the CI workflow, the dependency files, `normalize_totp`) were read directly, not through a second `/cso` run.

## Issues Encountered

- The key file could not be reproduced, so its origin is still unknown. The `*.keyx` ignore rule stops it being committed.
- The `/cso` budget (600 s) was too short to cover all phases in one run. Phases 10 and 11 were written as separate documents instead.

## Next Phase Readiness

**Ready:**
- Plan 04-02 and 04-03 remain for Phase 4. The user has not yet asked for any further fixes, so 04-02 is not planned.

**Concerns:**
- Phase 5 publishing needs CI pinning (F-11) and hash-pinned dependencies (F-12).
- The stray key file's origin is unknown.

**Blockers:**
- None.

---
*Built with PAUL Framework v1.4 · https://chrisai.cv/skool · https://youtube.com/@chris-ai-systems*
*Phase: 04-security-review, Plan: 01*
*Completed: 2026-10-30*
