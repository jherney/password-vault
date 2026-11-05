---
phase: 05-packaging-release
plan: 01
type: Summary
about: "pwvault"
description: "Hash-pinned requirements.lock used by CI, version 1.3.0, CHANGELOG.md, and a drift test; full suite 164 OK"
---

# Phase 5 Plan 01: Release readiness Summary

**Lock file pins every dependency with hashes and CI installs from it; version is 1.3.0 with a changelog, and a test keeps them in step.**

## Acceptance criteria

| Criterion | Result |
|---|---|
| AC-1: lock installs only hashed, pinned packages | Pass on Python 3.11, 3.12, 3.14 (fresh venvs, `--require-hashes`). 3.10 and 3.13 resolve with the same pins (checked with uv); their installs run in CI |
| AC-2: CI installs from the lock | Pass: `tests.yml` uses `pip install --require-hashes -r requirements.lock` |
| AC-3: version 1.3.0 everywhere | Pass: `pwvault --version` prints `pwvault 1.3.0`; top changelog entry 1.3.0 |
| AC-4: version and changelog cannot drift | Pass: test fails on a 1.2.9 heading (checked), passes once restored |

## Deviation from plan

- The lock was generated with **uv** (`uv pip compile --universal --python-version 3.10`), not pip-tools. pip-compile, run on 3.14, pinned `importlib-metadata` 10.1.0, which has no 3.10 build, so the 3.10 CI job would have failed. The uv universal lock puts version markers on the pins (9.0.1 below 3.11, 10.1.0 from 3.11).
- Local checks could not install on 3.10 or 3.13 (no interpreter available offline). Those jobs are the first real test of the lock on those versions.

## Files

- `requirements.lock` (new), `.github/workflows/tests.yml`, `README.md` (Dependencies section with the regenerate command)
- `pwvault.py` (`__version__`), `CHANGELOG.md` (new), `tests/test_release.py` (new)
