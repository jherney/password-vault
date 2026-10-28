#!/usr/bin/env python3
"""pwvault — a small, local password manager that stores its vault as a KeePass (.kdbx) file.

The vault opens in KeePass, KeePassXC and KeePass-compatible phone apps, and pwvault can
open databases those apps create.

Security model:
  * KDBX 4: AES-256 encryption, Argon2d key derivation (64 MiB, KeePassXC's defaults)
  * Unlock with a master password, a key file, or both
  * Atomic writes, file mode 0600; a save refuses to overwrite changes made by another session
  * Attachment data is pruned from the file when no entry or history version uses it

Features: nested groups, entry history, recycle bin, expiry dates, file attachments,
import from browser / KeePass / Bitwarden / LastPass / 1Password CSV exports,
export to CSV, HTML, XML and TXT, and a configurable password generator.
"""

import argparse
import csv
import fcntl
import getpass
import hashlib
import html
import io
import json
import math
import os
import secrets
import shutil
import stat
import string
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from lxml import etree
from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError, PayloadChecksumError
from pykeepass.pykeepass import BLANK_DATABASE_LOCATION, BLANK_DATABASE_PASSWORD

__version__ = "1.2.0"

DATA_DIR = Path.home() / ".local/share/pwvault"
DEFAULT_VAULT = Path(os.environ.get("PWVAULT_PATH", DATA_DIR / "vault.kdbx"))
LEGACY_VAULT = DATA_DIR / "vault.pwv"  # pre-KeePass pwvault format, see migrate_legacy()
CLIPBOARD_CLEAR_SECONDS = 20
MIN_MASTER_LEN = 12
MIN_GENERATED_LEN = 8
# Refuse files whose key derivation would take absurd memory or time to unlock. pykeepass runs
# AES-KDF as a Python loop (~0.7M rounds/s) and Argon2 with one thread per lane, so these keep a
# hostile file to about a minute of work. KeePassXC's defaults (64 MiB, ~1 s) are far below them.
MAX_KDF_MEMORY = 1 << 30  # Argon2 memory, bytes
MAX_KDF_ITERATIONS = 10_000  # Argon2 passes
MAX_KDF_WORK = 32 << 30  # Argon2 memory x passes, e.g. 64 MiB x 512 or 1 GiB x 32
MAX_KDF_PARALLELISM = 256  # Argon2 lanes
MAX_KDF_ROUNDS = 60_000_000  # AES-KDF rounds
# lxml < 5 resolves external entities by default, so a crafted vault could pull a local file
# into its XML (and into the next save). pykeepass doesn't pin lxml, so check here.
MIN_LXML = (5, 0)
KDBX_SIGNATURE = bytes.fromhex("03d9a29a67fb4bb5")
KEYFILE_LEN = 32  # KeePass and KeePassXC use a 32-byte key file as the raw key
HISTORY_MAX = 10  # versions kept per entry, KeePass's default
KEEP = object()  # "leave this unchanged" marker for update_entry(expiry=...)


class VaultError(Exception):
    pass


# ---------------------------------------------------------------- storage

def write_private(path: Path, data: bytes) -> None:
    """Atomically write data to path, readable only by the owner. A symlinked path (say, a vault
    kept in a synced folder) has its target replaced, not the link."""
    path = Path(os.path.realpath(path))
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def check_master_key(password: str, keyfile) -> None:
    """A vault needs a strong password, or a key file (with or without a password)."""
    if not keyfile and len(password) < MIN_MASTER_LEN:
        raise VaultError(f"use a master password of at least {MIN_MASTER_LEN} characters, or a key file")
    if keyfile and not Path(keyfile).is_file():
        raise VaultError(f"key file not found: {keyfile}")


def generate_keyfile(path: Path) -> None:
    """Create a random key file. O_EXCL checks and creates in one step, so a file (or symlink)
    that appears at path meanwhile is never overwritten; it also works on FAT USB sticks."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise VaultError(f"{path} already exists")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(secrets.token_bytes(KEYFILE_LEN))
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _read_variant_dict(data: bytes) -> dict:
    """Integer values of a KDBX 4 VariantDictionary (the KDF parameters)."""
    out, pos = {}, 2  # skip the 2-byte format version
    while pos < len(data) and data[pos] != 0:
        vtype = data[pos]
        klen = int.from_bytes(data[pos + 1:pos + 5], "little")
        key = data[pos + 5:pos + 5 + klen].decode("utf-8", "replace")
        pos += 5 + klen
        vlen = int.from_bytes(data[pos:pos + 4], "little")
        value = data[pos + 4:pos + 4 + vlen]
        pos += 4 + vlen
        if vtype in (0x04, 0x05, 0x0C, 0x0D):  # UInt32, UInt64, Int32, Int64
            out[key] = int.from_bytes(value, "little")
    return out


def check_kdf_params(blob: bytes) -> None:
    """Parse just the outer header and bound the key-derivation cost before anything runs it.
    (pykeepass derives the key while parsing, even with decrypt=False, so it can't do this.)"""
    if blob[:8] != KDBX_SIGNATURE or len(blob) < 12:
        raise VaultError("not a KeePass database")
    major = int.from_bytes(blob[10:12], "little")
    size_len = 4 if major >= 4 else 2
    pos = 12
    while True:
        if pos + 1 + size_len > len(blob):
            raise VaultError("vault file is truncated or corrupted")
        field = blob[pos]
        size = int.from_bytes(blob[pos + 1:pos + 1 + size_len], "little")
        data = blob[pos + 1 + size_len:pos + 1 + size_len + size]
        pos += 1 + size_len + size
        if len(data) < size:
            raise VaultError("vault file is truncated or corrupted")
        if field == 0:  # end of header
            return
        if field == 6:  # KDBX 3 AES-KDF rounds
            limits = {"R": int.from_bytes(data, "little")}
        elif field == 11:  # KDBX 4 KDF parameters
            limits = _read_variant_dict(data)
        else:
            continue
        memory, passes = limits.get("M", 0), limits.get("I", 0)
        if (memory > MAX_KDF_MEMORY or passes > MAX_KDF_ITERATIONS or memory * passes > MAX_KDF_WORK
                or limits.get("P", 0) > MAX_KDF_PARALLELISM or limits.get("R", 0) > MAX_KDF_ROUNDS):
            raise VaultError("vault file asks for an unreasonable amount of memory or time to unlock")


def check_xml_parser() -> None:
    if etree.LXML_VERSION[:2] < MIN_LXML:
        raise VaultError(f"lxml {etree.__version__} is too old to open vaults safely; "
                         f"install lxml {'.'.join(map(str, MIN_LXML))} or newer (pip install -U lxml)")


class Vault:
    """An unlocked KeePass database plus the bookkeeping for safe saves."""

    def __init__(self, path: Path, kp: PyKeePass, disk_blob, transformed_key):
        self.path, self.kp = path, kp
        # File contents as last read or written by us; None for a vault not yet on disk.
        self.disk_blob = disk_blob
        # Derived key, reused so routine saves don't rerun Argon2. None after a key change.
        self.transformed_key = transformed_key

    @classmethod
    def create(cls, path: Path, password: str, keyfile=None) -> "Vault":
        check_master_key(password, keyfile)
        kp = PyKeePass(BLANK_DATABASE_LOCATION, BLANK_DATABASE_PASSWORD)
        kp.password, kp.keyfile = password or None, str(keyfile) if keyfile else None
        return cls(path, kp, None, None)

    @classmethod
    def open(cls, path: Path, password: str, keyfile=None) -> "Vault":
        try:
            blob = path.read_bytes()
        except FileNotFoundError:
            raise VaultError(f"no vault at {path}")
        check_kdf_params(blob)
        check_xml_parser()
        if keyfile and not Path(keyfile).is_file():
            raise VaultError(f"key file not found: {keyfile}")
        try:
            kp = PyKeePass(io.BytesIO(blob), password or None, str(keyfile) if keyfile else None)
        except CredentialsError:
            raise VaultError("wrong master password or key file")
        except PayloadChecksumError:
            raise VaultError("vault file is corrupted")
        except Exception:
            raise VaultError("vault file is truncated or corrupted")
        return cls(path, kp, blob, kp.transformed_key)

    def save(self) -> None:
        self._prune_binaries()
        buf = io.BytesIO()
        self.kp.save(buf, transformed_key=self.transformed_key)
        blob = buf.getvalue()
        target = Path(os.path.realpath(self.path))  # lock the real file, however it was reached
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        lock_fd = os.open(target.with_name(target.name + ".lock"), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            # Serialize writers (CLI and GUI) and refuse to overwrite changes made by another one.
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            current = target.read_bytes() if target.exists() else None
            if current != self.disk_blob:
                raise VaultError("the vault file was changed by another program since it was "
                                 "unlocked; nothing was saved — unlock it again and redo your change")
            write_private(target, blob)
            self.disk_blob = blob
        finally:
            os.close(lock_fd)
        if self.transformed_key is None:
            # First save after create/rekey ran Argon2 with a fresh salt; learn the new key.
            self.transformed_key = PyKeePass(io.BytesIO(blob), self.kp.password, self.kp.keyfile).transformed_key

    def rekey(self, password: str, keyfile=None) -> None:
        check_master_key(password, keyfile)
        self.kp.password, self.kp.keyfile = password or None, str(keyfile) if keyfile else None
        self.transformed_key = None

    def _prune_binaries(self) -> None:
        """Drop attachment data no entry or history version refers to any more, so deleted
        attachments don't linger (decryptable) inside the file."""
        used = {a.id for a in self.kp.find_attachments(filename=".*", regex=True, history=True)}
        for i in reversed(range(len(self.kp.binaries))):
            if i not in used:
                self.kp.delete_binary(i)

    # ------------------------------------------------------------ groups

    @property
    def root(self):
        return self.kp.root_group

    @property
    def recycle_bin(self):
        return self.kp.recyclebin_group

    def in_recycle_bin(self, item) -> bool:
        bin_ = self.recycle_bin
        if bin_ is None:
            return False
        node = item
        while node is not None:
            if node.uuid == bin_.uuid:
                return True
            node = node.parentgroup
        return False

    def group_path(self, group) -> str:
        """'Root/Work/Email' — the same form KeePassXC uses in its CSV export."""
        return "/".join([self.root.name] + [p for p in (group.path or []) if p])

    def groups(self, include_bin=False) -> list:
        """Every group, root first, in tree order."""
        out = []

        def walk(g):
            if include_bin or not self.in_recycle_bin(g):
                out.append(g)
                for sub in sorted(g.subgroups, key=lambda s: (s.name or "").lower()):
                    walk(sub)
        walk(self.root)
        return out

    def get_group(self, path: str, create=False):
        """Find a group by 'A/B/C' path (relative to root); optionally create it."""
        group = self.root
        parts = [p for p in path.strip("/").split("/") if p]
        if parts and parts[0] == self.root.name:
            parts = parts[1:]
        for name in parts:
            sub = next((g for g in group.subgroups if g.name == name), None)
            if sub is None:
                if not create:
                    raise VaultError(f"no group '{path}'")
                sub = self.kp.add_group(group, name)
            group = sub
        return group

    def add_group(self, parent, name: str):
        if not name.strip():
            raise VaultError("group name can't be empty")
        return self.kp.add_group(parent, name.strip())

    def rename_group(self, group, name: str) -> None:
        if not name.strip():
            raise VaultError("group name can't be empty")
        group.name = name.strip()
        group.touch(modify=True)

    def delete_group(self, group) -> None:
        """Move to the recycle bin; delete permanently if it is already there."""
        if group.uuid == self.root.uuid or (self.recycle_bin and group.uuid == self.recycle_bin.uuid):
            raise VaultError("this group can't be deleted")
        if self.in_recycle_bin(group):
            self.kp.delete_group(group)
        else:
            self.kp.trash_group(group)

    # ------------------------------------------------------------ entries

    def entries(self, group=None, query: str = "") -> list:
        """Entries directly in group, or matching query anywhere outside the recycle bin."""
        if query:
            q = query.lower()
            return [e for e in self.kp.entries if not self.in_recycle_bin(e)
                    and any(q in (v or "").lower() for v in (e.title, e.username, e.url, e.notes))]
        return list((group or self.root).entries)

    def add_entry(self, group, title, username, password, url="", notes="", expiry=None):
        # pykeepass puts title and username into an XPath duplicate check (pointless with
        # force_creation) that breaks on a double quote, so set them afterwards.
        entry = self.kp.add_entry(group or self.root, "", "", password or "",
                                  url=url or None, notes=notes or None, force_creation=True)
        entry.title, entry.username = title or "", username or ""
        set_expiry(entry, expiry)
        return entry

    FIELDS = ("title", "username", "password", "url", "notes")

    def update_entry(self, entry, fields: dict, group=None, expiry=KEEP,
                     add_attachments=(), remove_attachments=()) -> None:
        """Apply changes, archiving the previous version in the entry's history first.
        Changing nothing is a no-op: it adds no history version and doesn't touch the entry."""
        changed = (any(k in fields and (fields[k] or "") != (getattr(entry, k) or "") for k in self.FIELDS)
                   or (expiry is not KEEP and expiry != (entry.expiry_time if entry.expires else None))
                   or bool(add_attachments) or bool(remove_attachments)
                   or (group is not None and group.uuid != entry.group.uuid))
        if not changed:
            return
        entry.save_history()
        while len(entry.history) > HISTORY_MAX:
            entry.delete_history(entry.history[0])  # oldest first
        for k in self.FIELDS:
            if k in fields:
                setattr(entry, k, fields[k] or "")
        if expiry is not KEEP:
            set_expiry(entry, expiry)
        for att in remove_attachments:
            entry.delete_attachment(att)
        for name, data in add_attachments:
            entry.add_attachment(self.kp.add_binary(data), name)
        if group is not None and group.uuid != entry.group.uuid:
            self.kp.move_entry(entry, group)
        entry.touch(modify=True)

    def restore_history(self, entry, version) -> None:
        """Make an old version current again (the current one goes into history)."""
        self.update_entry(entry, {k: getattr(version, k) for k in self.FIELDS},
                          expiry=version.expiry_time if version.expires else None)

    def delete_entry(self, entry) -> None:
        """Move to the recycle bin; delete permanently if it is already there."""
        if self.in_recycle_bin(entry):
            self.kp.delete_entry(entry)
        else:
            self.kp.trash_entry(entry)

    def restore_entry(self, entry, group=None) -> None:
        self.kp.move_entry(entry, group or self.root)

    def empty_recycle_bin(self) -> int:
        bin_ = self.recycle_bin
        if bin_ is None:
            return 0
        count = len(bin_.entries) + len(bin_.subgroups)
        self.kp.empty_group(bin_)
        return count

    def add_attachment(self, entry, name: str, data: bytes):
        return entry.add_attachment(self.kp.add_binary(data), name)


def set_expiry(entry, expiry) -> None:
    """expiry: an aware datetime, or None for 'never expires'."""
    entry.expires = expiry is not None
    if expiry is not None:
        entry.expiry_time = expiry


def expiry_from_date(text: str):
    """'YYYY-MM-DD' (local) -> aware datetime at the start of that day; '' -> None."""
    text = text.strip()
    if not text:
        return None
    try:
        return datetime.strptime(text, "%Y-%m-%d").astimezone()
    except ValueError:
        raise VaultError(f"expiry date must look like 2027-01-31, not '{text}'")


def fmt_time(dt) -> str:
    return dt.astimezone().strftime("%Y-%m-%d %H:%M") if dt else "—"


# ---------------------------------------------------------------- password generator

LOOKALIKES = set("Il1O0o|`'\"")
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/~"


def generate_password(length: int = 24, upper=True, lower=True, digits=True, symbols=True,
                      exclude_lookalikes=False) -> str:
    if length < MIN_GENERATED_LEN:
        raise VaultError(f"generated passwords must be at least {MIN_GENERATED_LEN} characters")
    classes = [c for c, on in ((string.ascii_uppercase, upper), (string.ascii_lowercase, lower),
                               (string.digits, digits), (SYMBOLS, symbols)) if on]
    if exclude_lookalikes:
        classes = [''.join(ch for ch in c if ch not in LOOKALIKES) for c in classes]
    if not classes:
        raise VaultError("pick at least one character type")
    alphabet = "".join(classes)
    while True:  # length >= 8 >= number of classes, so this terminates quickly
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(ch in c for ch in pw) for c in classes):
            return pw


def strength(password: str) -> tuple:
    """Rough entropy estimate (bits) from length and the character types used, plus a label."""
    pool = sum(len(c) for c in (string.ascii_lowercase, string.ascii_uppercase, string.digits)
               if any(ch in c for ch in password))
    if any(not ch.isascii() or not ch.isalnum() for ch in password):
        pool += 33
    bits = int(len(password) * math.log2(pool)) if password and pool else 0
    label = "weak" if bits < 50 else "fair" if bits < 75 else "strong" if bits < 110 else "very strong"
    return bits, label


# ---------------------------------------------------------------- clipboard

# (copy command, read-back command, clear command). wl-copy --sensitive marks the data as a
# password (x-kde-passwordManagerHint) so clipboard managers like Klipper keep it out of history;
# plain wl-copy is the fallback for wl-clipboard < 2.2.
CLIPBOARD_TOOLS = [
    (["wl-copy", "--sensitive"], "wl-paste -n", "wl-copy --clear"),
    (["wl-copy"], "wl-paste -n", "wl-copy --clear"),
    (["xclip", "-selection", "clipboard"], "xclip -selection clipboard -o", "printf '' | xclip -selection clipboard"),
    (["xsel", "-ib"], "xsel -ob", "xsel -cb"),
]


def copy_to_clipboard(text: str) -> bool:
    for cmd, paste, clear in CLIPBOARD_TOOLS:
        if not shutil.which(cmd[0]):
            continue
        try:
            subprocess.run(cmd, input=text.encode(), check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except (subprocess.CalledProcessError, OSError):
            continue
        # Clear the clipboard later in a detached process, but only if it still holds what we put
        # there. The expected hash goes in the environment (private to this user), not argv.
        subprocess.Popen(
            ["sh", "-c", f'sleep {CLIPBOARD_CLEAR_SECONDS}; '
                         f'[ "$({paste} 2>/dev/null | sha256sum)" = "$PWV_CLIP_SHA" ] && {clear}'],
            env={**os.environ, "PWV_CLIP_SHA": hashlib.sha256(text.encode()).hexdigest() + "  -"},
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True)
        return True
    return False


# ---------------------------------------------------------------- import

# Column names (lower-cased) used by the CSV exports of:
#   Chrome / Edge / Brave / Vivaldi / Opera: name,url,username,password,note
#   Firefox: url,username,password,httpRealm,formActionOrigin,guid,...
#   KeePass / KeePassXC: Group,Title,Username,Password,URL,Notes,...
#   Bitwarden: folder,...,name,notes,...,login_uri,login_username,login_password,...
#   LastPass: url,username,password,totp,extra,name,grouping,fav
#   1Password: Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes
CSV_COLUMNS = {
    "title": ("title", "name", "account"),
    "url": ("url", "login_uri", "website", "web site"),
    "username": ("username", "login_username", "user name", "login name"),
    "password": ("password", "login_password"),
    "notes": ("notes", "note", "extra", "comments"),
    "group": ("group", "grouping", "folder"),
}


def read_csv_export(path: Path) -> list:
    """Read a password-manager or browser CSV export into plain dicts."""
    try:
        return _read_csv_export(path)
    except UnicodeDecodeError:
        raise VaultError(f"{path} isn't UTF-8 text; re-export it as UTF-8 CSV")
    except csv.Error as e:
        raise VaultError(f"{path} isn't a valid CSV file ({e})")


def _read_csv_export(path: Path) -> list:
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        ours = tuple(reader.fieldnames or ()) == EXPORT_HEADER  # may be spreadsheet-escaped
        cols = {c.strip().lower(): c for c in (reader.fieldnames or [])}
        mapping = {field: next((cols[a] for a in aliases if a in cols), None)
                   for field, aliases in CSV_COLUMNS.items()}
        if not mapping["password"] or not (mapping["url"] or mapping["title"]):
            raise VaultError(f"{path} doesn't look like a password export "
                             f"(columns found: {reader.fieldnames})")
        out = []
        for row in reader:
            rec = {k: (row.get(col) or "") if col else "" for k, col in mapping.items()}
            if ours:
                rec = {k: spreadsheet_unescape(v) for k, v in rec.items()}
            for k in ("title", "url", "username", "notes", "group"):
                rec[k] = rec[k].strip()
            if not any(rec[k] for k in ("title", "url", "username", "password")):
                continue
            if not rec["title"]:
                rec["title"] = rec["url"].split("//", 1)[-1].split("/", 1)[0] or rec["url"]
            out.append(rec)
        return out


def merge_key(title: str, url: str, username: str) -> tuple:
    """Identity of a login for import matching. Without a URL, the title is what tells logins apart."""
    return (url or "", username or "", "" if url else title or "")


def merge_records(vault: Vault, records: list) -> tuple:
    """Add new logins, update changed passwords. Returns (added, updated)."""
    existing = {merge_key(e.title, e.url, e.username): e
                for e in vault.kp.entries if not vault.in_recycle_bin(e)}
    added = updated = 0
    for r in records:
        key = merge_key(r["title"], r["url"], r["username"])
        old = existing.get(key)
        if old is None:
            group = vault.get_group(r["group"], create=True) if r["group"] else vault.root
            existing[key] = vault.add_entry(
                group, r["title"], r["username"], r["password"], r["url"], r["notes"])
            added += 1
        elif (old.password or "") != r["password"]:
            vault.update_entry(old, {"password": r["password"]})
            updated += 1
    return added, updated


SHRED_CAVEAT = ("The file was overwritten and deleted, but on SSDs and copy-on-write filesystems "
                "(like Fedora's default btrfs) old copies of the data can survive until the disk "
                "reuses that space. Full-disk encryption is what protects it there.")


def shred(path: Path) -> None:
    """Best-effort overwrite before deleting; see SHRED_CAVEAT for why it's not a guarantee."""
    if path.is_symlink():  # overwriting would destroy whatever file the link points at
        raise VaultError(f"{path} is a symbolic link; delete it yourself")
    with open(os.open(path, os.O_RDWR | os.O_NOFOLLOW), "r+b") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise VaultError(f"{path} is not a regular file")
        f.write(secrets.token_bytes(st.st_size))
        f.flush()
        os.fsync(f.fileno())
    path.unlink()


# ---------------------------------------------------------------- export

EXPORT_FORMATS = ("csv", "html", "xml", "txt")
EXPORT_WARNING = "Exported files are NOT encrypted — delete them as soon as you're done."
EXPORT_HEADER = ("Group", "Title", "Username", "Password", "URL", "Notes", "Last Modified", "Created")
# Spreadsheet apps run a cell that starts with one of these as a formula, so an entry from a
# hostile vault or CSV could make LibreOffice or Excel send the other cells (every password) to
# a web server when you open the export.
FORMULA_START = ("=", "+", "-", "@", "\t", "\r")
CSV_ESCAPE_NOTE = ("Values starting with = + - or @ were prefixed with ' so spreadsheet apps don't run "
                   "them as formulas. pwvault's import removes the prefix; to move to another password "
                   "manager, export the CSV in raw form instead.")


def spreadsheet_escape(value: str) -> str:
    """Prefix ' to formula-like values (OWASP's CSV-injection advice). A value that already starts
    with ' gets one too, so spreadsheet_unescape restores every value exactly."""
    return "'" + value if value.startswith(FORMULA_START + ("'",)) else value


def spreadsheet_unescape(value: str) -> str:
    return value[1:] if value[:1] == "'" and value[1:].startswith(FORMULA_START + ("'",)) else value


def export(vault: Vault, path: Path, fmt: str, raw: bool = False) -> int:
    """Write every entry outside the recycle bin in plain text. Returns the entry count.
    csv is spreadsheet-safe unless raw (see FORMULA_START); xml is the full KeePass XML
    (readable by KeePass's own XML import)."""
    if path.exists() and any(Path(p).exists() and os.path.samefile(path, p)
                             for p in (vault.path, vault.kp.keyfile) if p):
        raise VaultError(f"{path} is the vault or its key file; export to a different file")
    entries =[e for e in vault.kp.entries if not vault.in_recycle_bin(e)]
    rows = [(vault.group_path(e.group), e.title or "", e.username or "", e.password or "",
             e.url or "", e.notes or "", fmt_time(e.mtime), fmt_time(e.ctime)) for e in entries]
    header = EXPORT_HEADER
    if fmt == "csv":  # same columns as KeePassXC's CSV export
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(header)
        w.writerows(rows if raw else ([spreadsheet_escape(c) for c in r] for r in rows))
        data = buf.getvalue().encode()
    elif fmt == "html":
        cells = lambda r, tag: "".join(f"<{tag}>{html.escape(c)}</{tag}>" for c in r)
        data = ("<!doctype html><meta charset='utf-8'><title>pwvault export</title>"
                "<style>body{font:14px sans-serif}table{border-collapse:collapse}"
                "td,th{border:1px solid #bbb;padding:4px 8px;text-align:left;vertical-align:top}"
                "th{background:#eee}td{white-space:pre-wrap}</style>"
                f"<table><tr>{cells(header, 'th')}</tr>"
                + "".join(f"<tr>{cells(r, 'td')}</tr>" for r in rows) + "</table>").encode()
    elif fmt == "txt":
        data = "\n".join("\n".join(f"{h + ':':<15}{v}" for h, v in zip(header, r) if v) + "\n"
                         for r in rows).encode()
    elif fmt == "xml":
        data = vault.kp.xml()
    else:
        raise VaultError(f"unknown export format '{fmt}' (choose from {', '.join(EXPORT_FORMATS)})")
    write_private(path, data)
    return len(entries)


# ---------------------------------------------------------------- legacy (.pwv) migration

def read_legacy_vault(path: Path, password: str) -> list:
    """Decrypt a vault written by pwvault before it switched to KeePass format."""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    blob = path.read_bytes()
    if blob[:4] != b"PWV1" or len(blob) < 26 + 12 + 16:
        raise VaultError(f"{path} is not an old-format pwvault file")
    n, r, p, salt = int.from_bytes(blob[4:8], "big"), blob[8], blob[9], blob[10:26]
    if not (2**14 <= n <= 2**20 and n & (n - 1) == 0 and 1 <= r <= 16 and 1 <= p <= 4):
        raise VaultError("old vault file has invalid key-derivation parameters")
    key = Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(password.encode())
    try:
        return json.loads(AESGCM(key).decrypt(blob[26:38], blob[38:], blob[:26]))
    except InvalidTag:
        raise VaultError("wrong master password for the old vault")


def migrate_legacy(old: Path, new: Path, password: str, keyfile=None) -> Vault:
    """Create a KeePass vault at `new` with the old vault's entries; `old` is left untouched."""
    if new.exists():
        raise VaultError(f"{new} already exists")
    records = read_legacy_vault(old, password)
    vault = Vault.create(new, password, keyfile)
    for e in records:
        try:
            title, username, secret, url = e["name"], e["username"], e["password"], e["url"]
        except (KeyError, TypeError):
            raise VaultError(f"old vault {old} has an entry in an unexpected format; nothing was converted")
        entry = vault.add_entry(vault.root, title, username, secret, url, e.get("note", ""))
        if e.get("updated"):
            entry.mtime = entry.ctime = datetime.fromtimestamp(e["updated"], timezone.utc)
    vault.save()
    return vault


# ---------------------------------------------------------------- CLI helpers

def prompt_new_master(keyfile=None) -> str:
    while True:
        pw = getpass.getpass("New master password" + (" (may be blank with a key file): " if keyfile else ": "))
        if not keyfile and len(pw) < MIN_MASTER_LEN:
            print(f"Use at least {MIN_MASTER_LEN} characters (a passphrase of 4+ random words is ideal).")
            continue
        if getpass.getpass("Confirm master password: ") != pw:
            print("Passwords didn't match, try again.")
            continue
        return pw


def unlock(args) -> Vault:
    if not args.vault.exists():
        hint = " — run `pwvault migrate`" if LEGACY_VAULT.exists() else " — run `pwvault init` first"
        sys.exit(f"error: no vault at {args.vault}{hint}")
    return Vault.open(args.vault, getpass.getpass("Master password: "), args.keyfile)


def find(vault: Vault, query: str, in_bin=False) -> list:
    if in_bin:
        q = query.lower()
        return [e for e in vault.kp.entries if vault.in_recycle_bin(e)
                and any(q in (v or "").lower() for v in (e.title, e.username, e.url))]
    return vault.entries(query=query)


def pick_one(matches: list, query: str):
    if not matches:
        sys.exit(f"No entries match '{query}'.")
    if len(matches) == 1:
        return matches[0]
    for i, e in enumerate(matches, 1):
        print(f"  {i}. {e.title}  ({e.username})")
    choice = input("Which one? ")
    try:
        index = int(choice)
    except ValueError:
        sys.exit("Invalid choice.")
    if not 1 <= index <= len(matches):  # 0 and negatives would index from the end
        sys.exit("Invalid choice.")
    return matches[index - 1]


def copy_and_report(entry) -> None:
    if copy_to_clipboard(entry.password or ""):
        print(f"Password copied to clipboard (clears in {CLIPBOARD_CLEAR_SECONDS}s).")
    else:
        print("No clipboard tool found (install wl-clipboard or xclip); use --show to print it.")


# ---------------------------------------------------------------- commands

def cmd_init(args):
    if args.vault.exists():
        sys.exit(f"error: a vault already exists at {args.vault}")
    keyfile = args.new_keyfile or args.keyfile
    print("Choose a master password. It can't be recovered if you forget it.")
    password = prompt_new_master(keyfile)
    if args.new_keyfile:  # only now, so aborting at the prompt leaves no stray key file
        generate_keyfile(args.new_keyfile)
        print(f"Created key file {args.new_keyfile}. Back it up: without it the vault can't be opened.")
    Vault.create(args.vault, password, keyfile).save()
    print(f"Created encrypted KeePass vault at {args.vault}")


def cmd_migrate(args):
    password = getpass.getpass(f"Master password for {args.old}: ")
    vault = migrate_legacy(args.old, args.vault, password, args.keyfile)
    print(f"Converted {len(vault.kp.entries)} entries to {args.vault} (same master password).\n"
          f"The old file {args.old} was left as is; delete it once you've checked the new vault.")


def cmd_import(args):
    vault = unlock(args)
    records = read_csv_export(args.csv)
    added, updated = merge_records(vault, records)
    vault.save()
    print(f"Imported {len(records)} rows: {added} new, {updated} updated, "
          f"{len(records) - added - updated} unchanged.")
    if args.shred:
        shred(args.csv)
        print(f"Deleted {args.csv}. {SHRED_CAVEAT}")
    else:
        print(f"⚠  {args.csv} still contains your passwords in plain text. "
              f"Delete it (or rerun with --shred).")


def cmd_export(args):
    vault = unlock(args)
    n = export(vault, args.out, args.format, raw=args.raw)
    print(f"Exported {n} entries to {args.out}.\n⚠  {EXPORT_WARNING}")
    if args.format == "csv" and not args.raw:
        print(CSV_ESCAPE_NOTE.replace("in raw form", "with --raw"))


def cmd_list(args):
    vault = unlock(args)
    if args.group:
        entries = vault.entries(vault.get_group(args.group))
    else:
        entries = vault.entries(query=args.query) if args.query else \
            [e for e in vault.kp.entries if not vault.in_recycle_bin(e)]
    for e in sorted(entries, key=lambda e: (e.title or "").lower()):
        flag = "  [expired]" if e.expired else ""
        print(f"{e.title or '':<30} {e.username or '':<30} {vault.group_path(e.group):<20} {e.url or ''}{flag}")
    print(f"\n{len(entries)} entr{'y' if len(entries) == 1 else 'ies'}")


def cmd_get(args):
    vault = unlock(args)
    e = pick_one(find(vault, args.query), args.query)
    print(f"Title:    {e.title}\nGroup:    {vault.group_path(e.group)}\nURL:      {e.url or ''}\n"
          f"Username: {e.username}")
    if e.notes:
        print(f"Notes:    {e.notes}")
    if e.expires:
        print(f"Expires:  {fmt_time(e.expiry_time)}" + ("  (EXPIRED)" if e.expired else ""))
    if args.show:
        print(f"Password: {e.password}")
    else:
        copy_and_report(e)


def cmd_add(args):
    vault = unlock(args)
    group = vault.get_group(args.group, create=True) if args.group else vault.root
    title = input("Title (e.g. GitHub): ").strip()
    url = input("URL: ").strip()
    username = input("Username: ").strip()
    if args.generate:
        password = generate_password(args.length)
        print("Generated a strong password.")
    else:
        password = getpass.getpass("Password (blank = generate one): ") or generate_password(args.length)
    entry = vault.add_entry(group, title or url, username, password, url)
    vault.save()
    print(f"Saved '{entry.title}' in {vault.group_path(group)}.")
    copy_and_report(entry)


def cmd_remove(args):
    vault = unlock(args)
    e = pick_one(find(vault, args.query), args.query)
    if input(f"Move '{e.title}' ({e.username}) to the recycle bin? [y/N] ").lower() != "y":
        return print("Cancelled.")
    vault.delete_entry(e)
    vault.save()
    print("Moved to the recycle bin (`pwvault trash` to list, restore or empty it).")


def cmd_trash(args):
    vault = unlock(args)
    if args.action == "list":
        items = find(vault, "", in_bin=True)
        for e in items:
            print(f"{e.title or '':<35} {e.username or '':<30} {e.url or ''}")
        print(f"\n{len(items)} entr{'y' if len(items) == 1 else 'ies'} in the recycle bin")
    elif args.action == "restore":
        if not args.query:
            sys.exit("error: say which entry to restore, e.g. `pwvault trash restore github`")
        e = pick_one(find(vault, args.query, in_bin=True), args.query)
        vault.restore_entry(e)
        vault.save()
        print(f"Restored '{e.title}' to {vault.root.name}.")
    else:
        if input("Permanently delete everything in the recycle bin? [y/N] ").lower() != "y":
            return print("Cancelled.")
        n = vault.empty_recycle_bin()
        vault.save()
        print(f"Permanently deleted {n} item{'s' if n != 1 else ''}.")


def cmd_generate(args):
    pw = generate_password(args.length, symbols=not args.no_symbols, exclude_lookalikes=args.no_lookalikes)
    bits, label = strength(pw)
    if args.show or not copy_to_clipboard(pw):
        print(pw)
    else:
        print(f"Copied to clipboard (clears in {CLIPBOARD_CLEAR_SECONDS}s).")
    print(f"Strength: ~{bits} bits ({label})")


def cmd_passwd(args):
    vault = unlock(args)
    keyfile = None if args.no_keyfile else (args.new_keyfile or args.keyfile)
    password = prompt_new_master(keyfile)
    if args.new_keyfile:  # only now, so aborting at the prompt leaves no stray key file
        generate_keyfile(args.new_keyfile)
        print(f"Created key file {args.new_keyfile}. Back it up: without it the vault can't be opened.")
    vault.rekey(password, keyfile)
    vault.save()
    print("Master key changed." + (f" The vault now also needs {keyfile}." if keyfile else ""))


def cmd_keyfile(args):
    generate_keyfile(args.out)
    print(f"Created key file {args.out}. Back it up: without it a vault that uses it can't be opened.")


def length_arg(value: str) -> int:
    n = int(value)
    if n < MIN_GENERATED_LEN:
        raise argparse.ArgumentTypeError(f"must be at least {MIN_GENERATED_LEN}")
    return n


def main():
    os.umask(0o077)  # anything we write (vaults, key files, exports) is private by default
    ap = argparse.ArgumentParser(prog="pwvault", description="Local password manager (KeePass .kdbx vault).")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    ap.add_argument("--vault", type=Path, default=DEFAULT_VAULT, help=f"vault file (default {DEFAULT_VAULT})")
    ap.add_argument("--keyfile", type=Path, help="key file that unlocks the vault")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="create a new vault")
    p.add_argument("--new-keyfile", type=Path, metavar="PATH", help="also create and require a new key file")
    p.set_defaults(fn=cmd_init)

    p = sub.add_parser("migrate", help="convert an old-format pwvault (.pwv) to KeePass format")
    p.add_argument("old", type=Path, nargs="?", default=LEGACY_VAULT)
    p.set_defaults(fn=cmd_migrate)

    p = sub.add_parser("import", help="import a browser or password-manager CSV export")
    p.add_argument("csv", type=Path)
    p.add_argument("--shred", action="store_true", help="delete the CSV after importing (best-effort overwrite first)")
    p.set_defaults(fn=cmd_import)

    p = sub.add_parser("export", help="export entries to an unencrypted file")
    p.add_argument("format", choices=EXPORT_FORMATS)
    p.add_argument("out", type=Path)
    p.add_argument("--raw", action="store_true",
                   help="csv: write values exactly, for importing into another password manager "
                        "(unsafe to open in a spreadsheet app)")
    p.set_defaults(fn=cmd_export)

    p = sub.add_parser("list", help="list entries (passwords hidden)")
    p.add_argument("query", nargs="?")
    p.add_argument("--group", help="only entries directly in this group, e.g. Work/Email")
    p.set_defaults(fn=cmd_list)

    p = sub.add_parser("get", help="copy a password to the clipboard")
    p.add_argument("query")
    p.add_argument("--show", action="store_true", help="print the password instead")
    p.set_defaults(fn=cmd_get)

    p = sub.add_parser("add", help="add an entry")
    p.add_argument("-g", "--generate", action="store_true", help="generate the password")
    p.add_argument("-l", "--length", type=length_arg, default=24)
    p.add_argument("--group", help="group path, created if missing, e.g. Work/Email")
    p.set_defaults(fn=cmd_add)

    p = sub.add_parser("remove", help="move an entry to the recycle bin")
    p.add_argument("query")
    p.set_defaults(fn=cmd_remove)

    p = sub.add_parser("trash", help="list, restore from, or empty the recycle bin")
    p.add_argument("action", choices=("list", "restore", "empty"))
    p.add_argument("query", nargs="?")
    p.set_defaults(fn=cmd_trash)

    p = sub.add_parser("generate", help="generate a strong password")
    p.add_argument("-l", "--length", type=length_arg, default=24)
    p.add_argument("--no-symbols", action="store_true")
    p.add_argument("--no-lookalikes", action="store_true", help="avoid characters like l, 1, O and 0")
    p.add_argument("--show", action="store_true")
    p.set_defaults(fn=cmd_generate)

    p = sub.add_parser("passwd", help="change the master password and/or key file")
    p.add_argument("--new-keyfile", type=Path, metavar="PATH", help="create and require a new key file")
    p.add_argument("--no-keyfile", action="store_true", help="stop requiring a key file")
    p.set_defaults(fn=cmd_passwd)

    p = sub.add_parser("keyfile", help="create a new random key file")
    p.add_argument("out", type=Path)
    p.set_defaults(fn=cmd_keyfile)

    args = ap.parse_args()
    try:
        args.fn(args)
    except VaultError as e:
        sys.exit(f"error: {e}")
    except OSError as e:
        sys.exit(f"error: {e.filename}: {e.strerror}" if e.filename and e.strerror else f"error: {e}")
    except (KeyboardInterrupt, EOFError):
        sys.exit("\nAborted.")


if __name__ == "__main__":
    main()
