# Changelog

All notable changes to pwvault. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- `pwvault merge OTHER.kdbx` merges another copy of the vault into this one, KeePassXC-style: entries and groups matched by UUID, the newer version wins and the other is kept in history, moves, the recycle bin and permanent deletions carry over. `--dry-run` shows the changes without saving; `--same-credentials` and `--other-keyfile` open the other copy.
- YubiKey HMAC-SHA1 challenge-response as part of the master key, KeePassXC-compatible: `--yubikey SLOT[:SERIAL]` on every command, `passwd --new-yubikey/--no-yubikey`, `merge --other-yubikey`. Needs the optional `[yubikey]` extra (yubikey-manager).
- GUI: Database > Merge another copy… shows every change from the other copy, then saves the merge (with a backup) or discards it.

### Changed
- License changed from MIT to GPL-3.0-or-later, the license of pykeepass, which pwvault is built on. Releases up to 1.3.0 remain available under MIT.
- Permanently deleting an entry or group (from the recycle bin, or by emptying it) is recorded in the vault's standard deletion list, as KeePassXC does, so the deletion survives a merge.
- Moving an entry or group (including to and from the recycle bin) now updates its location-changed time, so a merge here or in KeePassXC knows which copy moved it last.

### Security
- The `cryptography` minimum (optional `[legacy]` extra, used only by `pwvault migrate`) is raised from 46.0.5 to 50.0.2, the locked version. OSV lists six advisories against 46.0.5 (CVE-2026-34073, CVE-2026-39892, CVE-2026-69247, CVE-2026-69248, CVE-2026-69249, GHSA-537c-gmf6-5ccf); none affects the AES-GCM and Scrypt calls pwvault makes, but the old floor allowed installing an affected version.

## [1.3.0]

### Added
- Automatic versioned backups: the previous vault is kept before every save (last 10). `pwvault backup list` and `pwvault backup restore N` list and restore them; old-key backups are removed after a master-key change.
- TOTP/2FA codes stored in the standard KeePassXC `otp` attribute: `pwvault totp NAME --set`, `--show`, `--clear`. The GUI shows a live code with a countdown.
- Database > Backups dialog (Ctrl+Shift+B) to list and restore backups.
- Light and dark palettes that follow the desktop setting, with a Theme button that applies immediately.
- A hash-pinned `requirements.lock`; CI installs from it.

### Changed
- Failed or interrupted saves never corrupt the vault.
- Trash restore returns an entry to the group it was deleted from, not to the root.

### Fixed
- `export` refuses to overwrite an existing file.
- `add` refuses an entry with no title or URL, as the GUI already did.
- Closing the GUI cancels the pending auto-lock and clipboard timers.
- A crash during a master-key change can no longer leave old-key backups behind.

### Security
- Security review of the v1.3 changes: no critical or high findings. Minimum versions raised for lxml (6.1, fixes GHSA-vfmq-68hx-4jfw) and cryptography (46.0.5, fixes GHSA-r6ph-v2qm-q3c2). CI actions pinned to commit SHAs.

## [1.2.0]

Earlier release. See the git history for details.
