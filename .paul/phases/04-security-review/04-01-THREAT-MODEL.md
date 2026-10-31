# pwvault threat model (STRIDE), v1.3 changes

**Plan:** 04-01 · **Date:** 2026-10-30 · **Covers:** Phase 1 (backups, safe saves), Phase 2 (TOTP), Phase 3 (Backups dialog, theme settings) as of commit `28c091c`.
**Method:** STRIDE per component and trust transition, linked to the assets and invariants below. Findings reference `04-01-FINDINGS.md`.

## Assets and invariants

| Asset | Invariant |
|-------|-----------|
| Master password and key file | Never written to disk by pwvault. A key file is created only with mode `0600` and `O_EXCL`. |
| Vault file (`.kdbx`) | Encrypted with AES-256 and Argon2d. Replaced atomically. Never replaced while another program has changed it since unlock. |
| Backups (`vault.kdbx.backups/`) | Each backup is encrypted with the key in use when it was made. Only a backup that opens with the current key can be restored. After a master-key change, no backup opens with the old key. |
| Entry secrets (passwords, TOTP secrets, attachments, notes) | Visible only after unlock. Leave the vault only by an explicit action (show, copy, export). |
| TOTP codes | Valid for at most 30 s. Reading a code never saves the vault. |
| Settings file (`~/.config/pwvault/settings.ini`) | Holds no secret. Read only for the theme choice. |

## Trust boundaries

1. User ↔ pwvault (keyboard, terminal, screen).
2. pwvault ↔ file system (vault, backups, lock file, key file, settings, exports, CSV imports).
3. pwvault ↔ clipboard and other desktop programs (clipboard managers, `wl-copy`, `xclip`, `gsettings`, `kdeglobals`).
4. pwvault ↔ other programs that can write the vault file (sync folders, other pwvault instances, other editors).
5. Source code ↔ CI and dependency supply chain (GitHub Actions, PyPI packages).

The threat model assumes malware running as the same user is out of scope, as the README states. It cannot be stopped by an application.

## STRIDE by component

### Vault write and backup (`Vault._write`, `Vault.save`, `write_private`, `remove_backups`)

| Threat | Analysis | Mitigation | Residual / finding |
|--------|----------|------------|--------------------|
| **S**poofing: another program replaces the vault | Writes check the file still matches the bytes read at unlock. | `_write` compares with `disk_blob` under a `flock`. | Accepted. Another program with the right key can still write a valid vault. |
| **T**ampering: partial write corrupts the vault | A crash could leave a torn file. | Temp file, `fsync`, then `os.replace`. Fault-injection tests cover interrupted saves. | None. |
| **T**ampering: backups replaced by an attacker | An attacker with write access to the backup folder can replace or add files. | Restore verifies the backup opens with the current key before writing. Other names are ignored. | Accepted: a backup of a different key is refused. |
| **R**epudiation | No audit log of changes. | KDBX keeps entry history; backups keep whole versions. | Info. No security event log. Accepted for a personal tool. |
| **I**nformation disclosure: old-key backups after a master-key change | A leaked old password could open leftover backups. | Re-key purges old-key backups. | **F-01**: a crash between the write and the purge left them. **Fixed**, with a marker that the next open finishes. |
| **D**enial of service: fails save when backup fails | A full disk blocks the save. | By design: a failed backup blocks the save, so the vault is never replaced without a backup. | Accepted. |
| **E**levation of privilege | pwvault runs as the user; files are created `0600` (`umask 077`); no setuid. | `write_private`, `os.umask(0o077)`. | None. |

### Key file (`generate_keyfile`, `KeyFileField.new`)

| Threat | Analysis | Mitigation | Residual / finding |
|--------|----------|------------|--------------------|
| **I**nformation disclosure: key file in a shared folder | The save dialog suggests `pwvault.keyx` in the current folder. | `*.keyx` is git-ignored. | **F-09**: accepted. |
| **T**ampering: an existing file is overwritten | A symlink or existing file could be overwritten. | `O_EXCL` creates the file in one step. | None. |
| Weak randomness | Key material could be predictable. | `secrets.token_bytes`. | None. |

### TOTP (`parse_totp`, `_totp_secret`, `normalize_totp`, `entry_totp`, `cmd_totp`)

| Threat | Analysis | Mitigation | Residual / finding |
|--------|----------|------------|--------------------|
| **I**nformation disclosure: codes printed | `totp --set` prints the code; `totp --show` prints it. | Codes are valid for at most 30 s. Explicit flags. | **F-03**, **F-02**: accepted. |
| **I**nformation disclosure: secret shown in the GUI | The TOTP field is masked by default. | `PasswordField` with a Show toggle. | **F-10**: accepted. |
| **T**ampering: malformed TOTP settings in a vault | Period, digits, algorithm and base32 all come from the vault. | Period must be positive; digits bounded; algorithm whitelisted; errors raised as `VaultError`. | None. Checked in review. |
| **D**enial of service: hostile period | A zero period would divide by zero. | Rejected in `_make_totp`. | None. |

### Clipboard (`copy_to_clipboard`)

| Threat | Analysis | Mitigation | Residual / finding |
|--------|----------|------------|--------------------|
| **I**nformation disclosure: password stays on the clipboard | Other programs can read the clipboard. | Cleared after 20 s, only if it still holds the copied value. `wl-copy --sensitive` asks clipboard managers not to keep it. | **F-06**: accepted. X11 has no such hint. |
| **T**ampering: command injection through the clear step | Commands are built from fixed strings. | The copied value's hash goes in the environment, not the command line. | **F-06**: accepted. |

### Settings and desktop integration (`read_theme_choice`, `write_theme_choice`, `detect_color_scheme`)

| Threat | Analysis | Mitigation | Residual / finding |
|--------|----------|------------|--------------------|
| **T**ampering: settings file edited to a bad value | Any value is read as system unless it's light or dark. | Unknown values fall back to system. | None. |
| **I**nformation disclosure | The settings file holds only a theme name. | None needed. | None. |
| **T**ampering: `gsettings` or `kdeglobals` read | `gsettings` runs with fixed arguments, no shell, 2 s timeout. | Only the colour choice depends on it. | **F-05**: accepted. |

### Exports and imports (`export`, `import_csv`, `shred`)

| Threat | Analysis | Mitigation | Residual / finding |
|--------|----------|------------|--------------------|
| **I**nformation disclosure: plaintext export | Exports are not encrypted. | Warning printed; documented. | Accepted by design. |
| **T**ampering: CSV formula injection when opened in a spreadsheet | Values starting with `= + - @`. | Prefixed with `'` on export. | None. |
| **I**nformation disclosure: shredded CSV recoverable | SSDs and copy-on-write filesystems keep old blocks. | Symlinks refused; overwrite is best-effort; documented. | Accepted. |

### CLI and GUI output (`get --show`, `generate --show`, error messages)

| Threat | Analysis | Mitigation | Residual / finding |
|--------|----------|------------|--------------------|
| **I**nformation disclosure to the terminal | Explicit `--show` prints a secret. | Opt-in flag. | **F-02**: accepted. |
| **I**nformation disclosure in error text | Error messages name paths, not secrets. | Errors describe the problem, not the value. | None found. |

### Dependencies and CI (`requirements.txt`, `pyproject.toml`, `.github/workflows/tests.yml`)

| Threat | Analysis | Mitigation | Residual / finding |
|--------|----------|------------|--------------------|
| **T**ampering: malicious dependency update | No lock file; transitive versions float. `lxml` and `cryptography` minimums were below advisory fixes. | `pykeepass` pinned; `lxml` ≥ 6.1; `cryptography` ≥ 46.0.5. | **F-12**, **F-14**: fixed. **F-15** (no lock file): deferred to Phase 5. |
| **T**ampering: compromised CI action | Actions were pinned by tag, not SHA. | Pinned to commit SHAs; read-only token; no secrets; no credentials persisted. | **F-11**, **F-13**: fixed. |
| **E**levation of privilege in CI | `contents: read`; no publish step. | Least privilege. | None yet. Re-assess when Phase 5 adds publishing. |

## Out of scope

- Malware running as the same user (reads memory, the clipboard, or keystrokes).
- Physical access to an unlocked session.
- Weak master passwords on a copied vault file. The app enforces a minimum length, and a key file is an option.

## Open items carried to Phase 4 plans 02 and 03

- Phase 5: add hash-pinned dependencies before any publish workflow (F-15). CI pinning (F-11) is already done.
- The lock-file and backup-folder permissions were checked by reading code, not by a runtime test.
