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

## Requirements

- Python 3
- [`pykeepass`](https://pypi.org/project/pykeepass/) (see `requirements.txt`)
- For the legacy `.pwv` migration only: `cryptography`
- Optional clipboard tool: `wl-clipboard` (Wayland) or `xclip` / `xsel` (X11)
- The GUI needs Tkinter (`python3-tk` on Fedora/Debian)

```bash
pip install -r requirements.txt
```

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
| `export {csv,html,xml,txt} OUT` | Export every entry. **The output is not encrypted.** |
| `list [QUERY] [--group PATH]` | List entries, hiding passwords |
| `get QUERY [--show]` | Copy a password to the clipboard, or print it with `--show` |
| `add [-g] [-l LEN] [--group PATH]` | Add an entry; `-g` generates the password |
| `remove QUERY` | Move an entry to the recycle bin |
| `trash {list,restore,empty} [QUERY]` | Work with the recycle bin |
| `generate [-l LEN] [--no-symbols] [--no-lookalikes] [--show]` | Generate a password without saving it |
| `passwd [--new-keyfile PATH] [--no-keyfile]` | Change the master password and/or key file |
| `keyfile PATH` | Create a random key file |

Global options: `--vault PATH` and `--keyfile PATH`.

## GUI

```bash
python3 pwvault_gui.py [PATH_TO_VAULT]
```

The GUI offers search across all groups, add/edit with a password generator, entry history with restore, attachments, the recycle bin, CSV import, export, and changing the master key. Keyboard shortcuts:

| Shortcut | Action |
|---|---|
| Ctrl+C | Copy the password of the selected entry |
| Ctrl+B | Copy the username |
| Ctrl+N | New entry |
| Ctrl+F | Focus search |
| Ctrl+L | Lock the vault |
| Delete | Move the selected entry to the recycle bin |

### Auto-lock

After 5 minutes without input, the vault locks. An open edit dialog holds the vault unlocked, so the lock waits for it to close. That wait is capped: after 10 more minutes the vault locks anyway and the dialog's unsaved edits are discarded. Locking with Ctrl+L or the Lock button always closes open dialogs.

## Security model

- The vault is written atomically with file mode `0600`.
- Saves hold a file lock and refuse to overwrite changes another program made since you unlocked the vault. Nothing is lost silently; unlock again and redo the change.
- Key-derivation parameters are checked before any expensive work runs, so a hostile vault file can't force huge memory or time costs.
- Attachment data is removed from the file once no entry or history version uses it.
- Exports and CSV imports are plaintext. Delete them when you're done. `import --shred` overwrites the file before deleting it, but on SSDs and copy-on-write filesystems (such as Fedora's default btrfs) old copies can survive. Full-disk encryption is what protects that data.

## Tests

```bash
python3 -m unittest discover -s tests
```

The GUI tests need a display. Without one they're skipped; on a headless machine, run them with `xvfb-run -a python3 -m unittest discover -s tests`. The full suite takes about a minute, because each vault creation runs Argon2.

## Project layout

| File | Purpose |
|---|---|
| `pwvault.py` | Vault storage, entries, import/export, migration, and the CLI |
| `pwvault_gui.py` | Tkinter front end; uses the same `pwvault` module |
| `tests/test_pwvault.py` | Unit and regression tests |
| `requirements.txt` | Python dependencies |

## License

No license has been chosen yet.
