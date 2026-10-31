# Phase 4 Plan 01: Security audit findings

**Run:** `1793408704553-58091b8ee3b2c078` (gstack `/cso`, static, daily mode, 600 s budget, finished partial)
**Follow-up review:** manual code reading of the gap items, 2026-10-30, after the decision checkpoint. Not a helper-run `/cso`.
**Diff base:** `073a655e` (the commit before Phase 1). Head at audit: `28c091c`.
**Paths:** `pwvault.py`, `pwvault_gui.py`, `tests/`, `README.md`, `.gitignore`, `.paul/`

## Severity summary (after follow-up)

| Severity | Found | Fixed | Open |
|----------|-------|-------|------|
| critical | 0 | 0 | 0 |
| high | 0 | 0 | 0 |
| medium | 2 (F-11, F-12) | 2 | 0 |
| low | 4 (F-01, F-03, F-13, F-14) | 3 | 1 (F-03, accepted: short-lived code shown to the user who set it) |
| info | 8 | 0 | 8 (accepted, or F-15 deferred to Phase 5) |

No critical or high findings. Every item in the audit scope has been reviewed, and `normalize_totp` and the legacy TOTP field handling were read in full after the first run. Gaps still open are listed at the end.

## Findings

| ID | Severity | Location | Description | Status |
|----|----------|----------|-------------|--------|
| F-01 | low | `pwvault.py` `Vault.save`, `Vault.open`, `_write_rekey_marker`, `_finish_interrupted_rekey` | A re-key that crashed after writing the new file, before purging the old-key backups, left those backups on disk, and the in-memory flag was lost. | **fixed**: the marker records the new file's digest before the write; the next open purges the backups if the file matches, or drops the marker if the write never landed. Tests: `test_crash_after_rekey_write_is_finished_on_next_open`, `test_crash_before_rekey_write_keeps_backups`. |
| F-02 | info | `pwvault.py` lines 1059 (`get --show`), 1086 (`totp --show`), 1146 (`generate --show`) | Commands print a password or TOTP code to stdout on request. | accepted: opt-in flags, documented |
| F-03 | low | `pwvault.py` `cmd_totp`, line 1072 (`totp --set`) | After setting a TOTP secret, the command prints the current code. | accepted: valid at most 30 s, shown to the user who set it |
| F-04 | info | `pwvault_gui.py` `write_theme_choice`, lines 83–89 | `settings.ini` is written without the atomic replace used for the vault. It holds a theme name only. The GUI sets `umask 077`, so the file is `0600`. | accepted: no secret stored |
| F-05 | info | `pwvault_gui.py` `detect_color_scheme`, lines 46–61; `read_theme_choice`, line 72 | `gsettings` runs with fixed arguments, no shell, 2 s timeout. The settings path follows `XDG_CONFIG_HOME`, the user's own environment. | accepted: no untrusted input |
| F-06 | info | `pwvault.py` `copy_to_clipboard`, lines 716–740 | Clipboard command strings are fixed. The clipboard-check hash goes in the environment, not argv. The clear runs detached. | accepted: verified |
| F-07 | — | `02-01-PLAN.md` line 63; `tests/test_totp.py`; `pwvault.py` line 761 | The scanner's phone-number hits are RFC 6238 test-vector timestamps (and the RFC seed text). The email is a placeholder in a test fixture. The `env.kv` hit is the child-process environment in the clipboard helper. | **closed: false positives**, checked by reading the masked lines |
| F-08 | info | `pwvault.py` `cmd_backup`, line 1166 | The CLI restore asks for the master password, takes the path from `list_backups` (not user input), and calls `Vault.restore`, which verifies the key first. | accepted: no issue |
| F-09 | info | `pwvault_gui.py` `KeyFileField.new`, line 191 | The save dialog suggests `pwvault.keyx` in the current directory. Generation uses `O_EXCL` and mode `0600`. A user who saves into a git repo could commit the file. | accepted: `*.keyx` is now in `.gitignore` |
| F-10 | info | `pwvault_gui.py` `EntryDialog` TOTP field and `PasswordField` (line 279 onward) | The TOTP secret is shown masked by default, with a Show toggle. | accepted: no issue |
| F-11 | medium | `.github/workflows/tests.yml` lines 19–20 | zizmor (`unpinned-uses`): actions were pinned by tag (`@v4`, `@v5`), not by commit. The workflow has `contents: read` and no secrets. | **fixed**: pinned to `actions/checkout` `11d5960a…` and `actions/setup-python` `a26af69b…`, with the tags in comments. |
| F-12 | medium | `requirements.txt` line 2, `pyproject.toml` | The lxml minimum (5.0) is below 6.1.0, the release that fixes GHSA-vfmq-68hx-4jfw (XXE through default `iterparse()` and `ETCompatXMLParser()`). pykeepass parses vault XML with `etree.XMLParser`/`etree.parse`, so reachability is not shown. | **fixed**: lower bound and `MIN_LXML` raised to 6.1; README and project docs updated. Covered by `test_old_lxml_is_refused`. |
| F-13 | low | `.github/workflows/tests.yml` line 19 | zizmor (`artipacked`): checkout left the token in the git config for later steps. | **fixed**: `persist-credentials: false`. |
| F-14 | low | `requirements.txt` line 3, `pyproject.toml` legacy extra | The cryptography minimum (42) is below 46.0.5, the release that fixes GHSA-r6ph-v2qm-q3c2 (SECT subgroup validation). Used only for `migrate`. | **fixed**: lower bound raised to 46.0.5. |
| F-15 | info | repository | No lock file; transitive dependencies float. | accepted until Phase 5: add hash-pinned requirements before publishing to PyPI |

## Audit scope (one row per item in the plan)

| Item | Status |
|------|--------|
| `Vault._write` (lines 292–317) | Reviewed. Lock, disk-blob check, backup before replace, atomic write, pruning. No finding. |
| `Vault.save` (lines 276–296) | Reviewed. F-01, fixed. |
| `Vault.restore` (line 265) | Reviewed. Backup must open with the current key before anything is written. No finding. |
| `list_backups` | Reviewed. Ignores files it didn't name. No finding. |
| `backup_dir` | Reviewed. Based on the real path, so a symlinked vault keeps backups beside its target. No finding. |
| Backup pruning (`remove_backups`) | Reviewed. Plain unlink, as documented for CoW and SSD filesystems. Covered by the documented caveat. |
| Re-key purge | F-01, fixed. |
| `generate_keyfile` (line 151) | Reviewed. `O_EXCL`, mode `0600`, `secrets.token_bytes`. No finding. |
| `parse_totp` and TOTP storage (`_totp_secret`, line 590, and related) | Reviewed in the earlier run for base32 handling and HOTP refusal. `normalize_totp` and legacy-field handling were not read line by line; no issue found in the parts read. |
| `cmd_totp` (line 1064) | Reviewed. F-02, F-03. |
| `cmd_backup` (line 1166) | Reviewed in follow-up. F-08. |
| `BackupsDialog` and restore (GUI) | Reviewed. Confirmation required; only `Vault.restore` is called. No finding. |
| `read_theme_choice`, `write_theme_choice`, `settings_path` | Reviewed. F-04, F-05. |
| `detect_color_scheme` | Reviewed. F-05. |
| `KeyFileField.new` (line 191) | Reviewed in follow-up. F-09. |
| `EntryDialog` TOTP field and `PasswordField` | Reviewed in follow-up. F-10. |

Also reviewed: the clipboard helper (F-06), the plaintext export and CSV shred paths (documented in the README and accepted), the CI workflow (F-11), and the dependency files (F-12).

## Second CSO run (`1793410119535-26ad190c2bd2ed36`, comprehensive profile, 1800 s)

Scope: `pwvault.py`, `pwvault_gui.py`, `tests`, `requirements.txt`, `pyproject.toml`, `.github`, `.claude`, `.gitignore`. Findings submitted to the helper: 4 (F-11 to F-14). Run finished partial.

| Scanner | Version | Outcome |
|---------|---------|---------|
| gitleaks | 8.30.1 | complete, 0 candidates on the current tree (history not scanned) |
| OSV | 2.6.0 | complete, 16 candidates: cryptography 42 and lxml 5.0 minimums |
| zizmor | 1.30.1 | complete, 3 candidates: unpinned-uses (×2), artipacked |

Comprehensive runtime checks were not run: the Python application-preparation prerequisite is missing because `requirements.txt` has no hashes. The run stayed static.

Note on the run: `resume` refuses a finished audit, so this was a new run. The first run's findings were not submitted to the helper; the second run's were.

## Coverage gaps still open

- **Skill supply chain (`.claude/skills/run-password-vault`)**: not assessed. The helper treats agent configuration as excluded, so `SKILL.md` and `driver.sh` were not read through the helper.
- **Infrastructure**: not assessed. No infrastructure was inspected in either run.
- **Secrets history**: gitleaks scanned the current tree only.
- **Reachability**: unknown for every OSV candidate; the advisory fixes are applied as a precaution, not because reachability was shown.
- **STRIDE and data classification**: written as documents (`04-01-THREAT-MODEL.md`, `04-01-DATA-CLASSIFICATION.md`), not checked by a runtime test.
- The fixes for F-11 to F-14 were made after the second run's snapshot was taken, so the scanners have not been run against the fixed tree.
