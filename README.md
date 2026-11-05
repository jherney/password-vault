# pwvault

A small, local password manager. Your vault is a standard KeePass (`.kdbx`) file, so it also opens in KeePassXC and KeePass-compatible phone apps. pwvault has a command-line interface and a Tkinter GUI, and both use the same vault file.

> **Security note:** pwvault is a personal project. Use it at your own risk, and keep a backup of your vault and key file. A forgotten master password can't be recovered.

## Features

- Encrypted KDBX 4 vault (AES-256, Argon2d key derivation)
- Unlock with a master password, a key file, or both
- Nested groups, entry history, a recycle bin, expiry dates and file attachments
- Import from browser, KeePass, Bitwarden, LastPass and 1Password CSV exports
- Export to CSV, HTML, XML or TXT
- Password generator with a strength estimate
- Clipboard copy that clears itself after 20 seconds
- Auto-lock after 5 minutes idle (see [Auto-lock](#auto-lock))
- Automatic backup of the previous vault on every save, last 10 kept (see [Backups](#backups))
- TOTP (2FA) codes, stored KeePassXC-compatibly (see [TOTP codes](#totp-2fa-codes))
- Optional YubiKey challenge-response as part of the master key, compatible with KeePassXC (see [YubiKey](#yubikey))
- Merge two copies of a vault edited on different devices (see [Using the vault on two devices](#using-the-vault-on-two-devices))
- Offline check for breached, reused and weak passwords (see [Checking for breached passwords](#checking-for-breached-passwords))

## Requirements

- Linux or another POSIX system, Python 3.10 or newer
- [`pykeepass`](https://pypi.org/project/pykeepass/) and `lxml` 6.1 or newer (see `requirements.txt`)
- For the legacy `.pwv` migration only: `cryptography`
- Optional clipboard tool: `wl-clipboard` (Wayland) or `xclip` / `xsel` (X11)
- The GUI needs Tkinter (`python3-tk` on Fedora/Debian)

Install into a virtual environment (or with `pipx`), which also puts `pwvault` and `pwvault-gui` on your `PATH`:

```bash
pip install .            # add the [legacy] extra to migrate an old .pwv vault: pip install '.[legacy]'
```

Or run the scripts in place after `pip install -r requirements.txt`. The examples below use `python3 pwvault.py`; with the package installed, `pwvault` works the same.

## Quick start

```bash
python3 pwvault.py init                      # create a vault (asks for a master password)
python3 pwvault.py add --group Work/Email    # add an entry (generate with -g)
python3 pwvault.py list                      # list entries; passwords are hidden
python3 pwvault.py get github                # copy a password to the clipboard
```

The default vault is `~/.local/share/pwvault/vault.kdbx`. Override it with `--vault PATH` or the `PWVAULT_PATH` environment variable.

## Command-line reference

| Command | What it does |
|---|---|
| `init [--new-keyfile PATH]` | Create a vault, optionally with a new key file |
| `migrate [OLD]` | Convert an old-format `.pwv` vault to KeePass format; the old file is left untouched |
| `import CSV [--shred]` | Import a CSV export; `--shred` deletes the CSV afterwards |
| `merge OTHER [--dry-run] [--same-credentials] [--other-keyfile PATH]` | Merge another copy of the vault into this one (see [Using the vault on two devices](#using-the-vault-on-two-devices)) |
| `export {csv,html,xml,txt} OUT [--raw]` | Export every entry. **The output is not encrypted.** `--raw` writes CSV values exactly (see below) |
| `list [QUERY] [--group PATH]` | List entries, hiding passwords |
| `get QUERY [--show]` | Copy a password to the clipboard, or print it with `--show` |
| `totp QUERY [--show]` | Copy the entry's current 2FA code, or print it with `--show` |
| `totp QUERY --set` / `--clear` | Set (asked for, hidden) or remove the entry's TOTP secret |
| `add [-g] [-l LEN] [--group PATH]` | Add an entry; `-g` generates the password |
| `remove QUERY` | Move an entry to the recycle bin |
| `trash {list,restore,empty} [QUERY]` | Work with the recycle bin |
| `generate [-l LEN] [--no-symbols] [--no-lookalikes] [--show]` | Generate a password without saving it |
| `check` | List entries whose passwords are breached, reused or weak, without using the network (see [Checking for breached passwords](#checking-for-breached-passwords)) |
| `breach {update,import,status} [FILE]` | Download, import or show the offline breach list `check` uses |
| `passwd [--new-keyfile PATH] [--no-keyfile] [--new-yubikey SLOT \| --no-yubikey]` | Change the master password, key file and/or YubiKey |
| `backup {list,restore} [N]` | List the automatic backups, or restore backup `N` (see [Backups](#backups)) |
| `keyfile PATH` | Create a random key file |

Global options: `--vault PATH`, `--keyfile PATH`, `--yubikey SLOT[:SERIAL]` and `--version`.

## GUI

```bash
python3 pwvault_gui.py [PATH_TO_VAULT]
```

The GUI offers search across all groups, add/edit with a password generator, entry history with restore, attachments, the recycle bin, CSV import, export, and changing the master key. Keyboard shortcuts:

| Shortcut | Action |
|---|---|
| Ctrl+C | Copy the password of the selected entry |
| Ctrl+B | Copy the username |
| Ctrl+T | Copy the current one-time (TOTP) code |
| Ctrl+N | New entry |
| Ctrl+F | Focus search |
| Ctrl+L | Lock the vault |
| Ctrl+Shift+B | Open Backups (restore an earlier version of the vault) |
| Delete | Move the selected entry to the recycle bin |

The GUI's colours are light or dark. By default it follows the desktop setting (KDE's window colour, or GNOME's color-scheme) and uses dark if that can't be read. To override it, click the Theme button in the top bar, which cycles System, Light and Dark. The choice applies straight away, including to open dialogs, and is saved in `~/.config/pwvault/settings.ini`, not in the vault.

Database > Merge another copy… merges another copy of the vault into the open one, the same way `pwvault merge` does (see [Using the vault on two devices](#using-the-vault-on-two-devices)). Choose the file; leave "Same password and key file as this vault" ticked, or enter the other copy's own. The dialog lists every change (added, updated, moved, deleted) before anything is written: Save stores the merged vault once, keeping the current file as a backup, and Discard (or Escape) puts the open vault back the way it is on disk.

Database > Backups lists the last versions of the vault, newest first. Restoring one asks first, keeps the current file as a backup, and locks the vault so you unlock to see the restored entries.

### Auto-lock

After 5 minutes without input, the vault locks. An open edit dialog holds the vault unlocked, so the lock waits for it to close. That wait is capped: after 10 more minutes the vault locks anyway and the dialog's unsaved edits are discarded. Locking with Ctrl+L or the Lock button always closes open dialogs.

## Backups

Before every save, from the CLI or the GUI, pwvault copies the vault file it is about to replace into a `.backups` folder next to it (for the default vault, `~/.local/share/pwvault/vault.kdbx.backups/`). The last 10 are kept. If the backup can't be written, the save is cancelled and the vault is left as it was.

```bash
python3 pwvault.py backup list        # numbered, newest first
python3 pwvault.py backup restore 2   # asks for the master password
```

A backup is a complete `.kdbx` file, encrypted with the master key that was in use when it was made, so it also opens in KeePassXC. `restore` checks that the backup opens with the vault's current key before it changes anything, and backs up the current vault first, so a restore can itself be undone.

Changing the master key (`passwd` or the GUI) deletes the existing backups once the re-keyed vault is saved, because they would still open with the old password. The files are deleted, not overwritten: on SSDs and copy-on-write filesystems overwriting wouldn't remove old copies anyway.

## Using the vault on two devices

You can keep the vault file in a synced folder (Syncthing, Nextcloud and the like) and use it on more than one device. If both copies are changed before they sync, the sync tool keeps both files, for example `vault.sync-conflict-20261105-101500-ABCDEFG.kdbx` next to `vault.kdbx`. Merge the other one in:

```bash
python3 pwvault.py merge ~/Sync/vault.sync-conflict-20261105-101500-ABCDEFG.kdbx --dry-run           # see what would change
python3 pwvault.py merge ~/Sync/vault.sync-conflict-20261105-101500-ABCDEFG.kdbx --same-credentials  # do it
```

`merge` asks for the other copy's master password unless you pass `--same-credentials`; `--other-keyfile PATH` gives its key file. It works the way KeePassXC's merge does, so a copy changed in KeePassXC merges too:

- Entries and groups are matched by their internal ID, not by title, so renamed entries still match.
- When both copies changed an entry, the most recently changed version wins and the other one is kept in the entry's history. No version is lost.
- New entries and groups, moves and the recycle bin carry over.
- An entry permanently deleted in one copy (emptied from the recycle bin) is deleted in the other too, unless that copy changed it after the deletion. KeePassXC's own merge leaves such entries in place by default; pwvault applies the deletion.

The other file is only read. The merged vault is saved once, with the usual backup of the version before the merge, so `pwvault backup restore 1` undoes it. Delete the conflict file yourself once you've checked the result.

Deletions only carry over if they were recorded: pwvault records them from 1.4.0 on, and KeePassXC always has. Entries permanently deleted with pwvault 1.3 or earlier come back the first time you merge with a copy that still has them.

## TOTP (2FA) codes

An entry can hold the secret behind a site's two-factor codes. Paste either the secret the site shows (spaces and lower case are fine) or an `otpauth://totp/…` link:

```bash
python3 pwvault.py totp github --set    # asks for the secret, hidden
python3 pwvault.py totp github          # copies the current code (clears like a password)
python3 pwvault.py totp github --show   # prints it instead
python3 pwvault.py totp github --clear
```

In the GUI, set it in the entry's TOTP field. The detail panel then shows the current code with a countdown, and Ctrl+T copies it.

The secret is stored the way KeePassXC stores it: as an `otpauth://` link in the entry's protected `otp` field, so codes match in KeePassXC and other apps that read it. pwvault also reads the older formats KeePassXC accepts (KeeOtp's `key=…` in `otp`, and the `TOTP Seed` / `TOTP Settings` fields), including SHA-256/512, 6–10 digits, custom periods and Steam Guard codes. Setting or clearing a secret replaces the older fields. Counter-based (HOTP) codes aren't supported.

## YubiKey

A YubiKey's HMAC-SHA1 challenge-response slot can be part of the master key, together with the password and/or key file. pwvault does it the same way KeePassXC does, so the same vault opens in both apps with the same key. It needs the optional `yubikey-manager` package:

```bash
pip install 'pwvault-manager[yubikey]'          # or: sudo dnf install yubikey-manager
ykman otp chalresp --generate 2                  # only if slot 2 isn't set up yet; this overwrites slot 2
python3 pwvault.py --yubikey 2 init              # new vault that needs password + YubiKey
python3 pwvault.py --yubikey 2 list              # every command takes --yubikey
python3 pwvault.py passwd --new-yubikey 2        # add a YubiKey to an existing vault
python3 pwvault.py --yubikey 2 passwd --no-yubikey   # or remove it
```

`yubikey-manager` depends on `pyscard`, which pip builds from source on Linux: install `pcsc-lite-devel` (Fedora) or `libpcsclite-dev` (Debian/Ubuntu) first, or use the distribution's `yubikey-manager` package instead.

`--yubikey 2:SERIAL` picks one of several plugged-in keys (`ykman list` shows the serial). If the slot needs a touch, pwvault says so and waits 15 seconds. A YubiKey vault must be KDBX 4 with Argon2, which is what pwvault and KeePassXC create.

**Keep a spare.** The secret in the YubiKey slot is part of the key and pwvault never stores it. If the key is lost or broken, the vault can't be opened. Program a second YubiKey with the same secret (`ykman otp chalresp 2 <secret>`), or keep the secret somewhere safe offline.

In the GUI, choose the slot under **YubiKey** on the unlock screen (it is remembered for that vault; settings.ini keeps only a hash of the vault's path and the slot number), in Database > Change master key… to add, change or remove it, and in Database > Merge another copy… for the other copy. While the key waits for a touch, the window shows "Touch your YubiKey…".

## Checking for breached passwords

`pwvault check` lists the entries whose password is in a known data breach, is used by more than one entry, or is weak (under 50 bits by the generator's estimate). It never prints a password, skips the recycle bin and entries with no password, and works entirely offline.

Breached passwords are looked up in a local copy of Have I Been Pwned's [Pwned Passwords](https://haveibeenpwned.com/Passwords) list, which you download once:

```bash
python3 pwvault.py breach update    # ~1 million requests, ~55 GB downloaded, a few hours; needs 20 GB free
python3 pwvault.py breach status    # how many hashes, and when the list was downloaded
python3 pwvault.py check
```

- **Nothing about your passwords is sent.** `breach update` downloads every one of the list's 1,048,576 ranges, the same for everyone, and `check` makes no network connections at all.
- **Size.** The list is stored compactly in `~/.cache/pwvault/pwned/` (or `$XDG_CACHE_HOME/pwvault/pwned/`), outside the vault's folder: about 16 GB for the ~2.6 billion hashes, keeping the first 68 bits of each SHA-1 hash. A false "breached" result is about 1 in 100 billion per password. How often a password was seen is not kept.
- **Interrupted downloads resume.** Press Ctrl+C or lose the connection and run `breach update` again; it continues from the last finished batch. A damaged or unexpected response is retried and never stored. While an update runs, `check` keeps using the previous complete list.
- **Already have the list?** `breach import FILE` builds the store from a `HASH:COUNT` text file sorted by hash, such as the output of HIBP's [PwnedPasswordsDownloader](https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader).

Without a downloaded list, `check` still reports reused and weak passwords and says how to get the list.

## Security model

- The vault is written atomically with file mode `0600`. If the vault path is a symlink (for example into a synced folder), the file it points to is updated and the link is kept.
- Saves hold a file lock and refuse to overwrite changes another program made since you unlocked the vault. Nothing is lost silently; unlock again and redo the change.
- Key-derivation parameters are checked before any expensive work runs, so a hostile vault file can't force huge memory or time costs. Argon2 is limited to 1 GiB, 256 lanes and 32 GiB × passes in total; AES-KDF to 60 million rounds. That is about a minute of work at most, and far above KeePassXC's defaults.
- Vaults are only opened with `lxml` 6.1 or newer. Older `lxml` expands external XML entities, which a crafted vault could use to copy a local file into itself on the next save.
- Attachment data is removed from the file once no entry or history version uses it.
- Exports and CSV imports are plaintext. Delete them when you're done. `import --shred` overwrites the file before deleting it (it refuses symlinks, so it can't overwrite some other file), but on SSDs and copy-on-write filesystems (such as Fedora's default btrfs) old copies can survive. Full-disk encryption is what protects that data.
- CSV exports are safe to open in a spreadsheet app: a value starting with `=`, `+`, `-` or `@` gets a leading `'`, so a hostile entry can't run as a formula (for example, one that sends every password to a website). pwvault's own import removes the prefix again. To move to another password manager, use `export csv --raw` (or *CSV (raw)* in the GUI), which keeps values exact and shouldn't be opened in a spreadsheet.
- New key files are created in one step that fails if anything already exists at that path, so an existing key file (or a symlink) is never overwritten.
- Attachment names come from the vault file, so when you save one the GUI suggests only its plain file name, never a path.
- On Wayland, copied passwords are marked as sensitive so clipboard managers skip them (wl-clipboard 2.2+). X11 has no such hint, so a clipboard manager there may keep a copy.
- What pwvault can't protect against: malware running as your user (it can read the clipboard, log keystrokes or read process memory), and a weak master password on a vault file someone has copied.

## Tests

```bash
python3 -m unittest discover -s tests
```

The GUI tests need a display. Without one they're skipped; on a headless machine, run them with `xvfb-run -a python3 -m unittest discover -s tests`. The full suite takes about a minute, because each vault creation runs Argon2. GitHub Actions runs the whole suite, GUI tests included, on Python 3.10 to 3.13 for every push and pull request.

## Install from PyPI

```bash
pip install pwvault-manager        # the command is still `pwvault` and `pwvault-gui`
pwvault-gui --install-launcher     # optional: add pwvault to the desktop app menu
```

## Dependencies

`requirements.txt` lists what pwvault needs. `requirements.lock` pins every package, with hashes, for all supported Python versions. CI installs from it with `pip install --require-hashes -r requirements.lock`. To update it after editing `requirements.txt`, run:

```bash
uv pip compile requirements.txt --universal --python-version 3.10 --generate-hashes --output-file requirements.lock
```

## Project layout

| File | Purpose |
|---|---|
| `pwvault.py` | Vault storage, entries, import/export, migration, and the CLI |
| `pwvault_gui.py` | Tkinter front end; uses the same `pwvault` module |
| `tests/test_pwvault.py` | Unit and regression tests |
| `requirements.txt` | Python dependencies |
| `pyproject.toml` | Packaging; installs the `pwvault` and `pwvault-gui` commands |
| `.github/workflows/tests.yml` | CI |

## License

GNU General Public License v3.0 or later (GPL-3.0-or-later). See [LICENSE](LICENSE).

Releases up to and including 1.3.0 were published under the MIT License and stay available under it.
