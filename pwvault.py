#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 jherney
"""pwvault — a small, local password manager that stores its vault as a KeePass (.kdbx) file.

The vault opens in KeePass, KeePassXC and KeePass-compatible phone apps, and pwvault can
open databases those apps create.

Security model:
  * KDBX 4: AES-256 encryption, Argon2d key derivation (64 MiB, KeePassXC's defaults)
  * Unlock with a master password, a key file, or both
  * Atomic writes, file mode 0600; a save refuses to overwrite changes made by another session
  * Each save first keeps the file it replaces in <vault>.backups/ (last 10)
  * Attachment data is pruned from the file when no entry or history version uses it

Features: nested groups, entry history, recycle bin, expiry dates, file attachments,
TOTP (2FA) codes stored the way KeePassXC stores them,
import from browser / KeePass / Bitwarden / LastPass / 1Password CSV exports,
export to CSV, HTML, XML and TXT, and a configurable password generator.
"""

import argparse
import base64
import bisect
import concurrent.futures
import csv
import fcntl
import getpass
import gzip
import hashlib
import hmac
import html
import http.client
import io
import itertools
import json
import math
import os
import re
import secrets
import shutil
import stat
import string
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import uuid
import zlib
import copy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from lxml import etree
from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError, PayloadChecksumError
from pykeepass.pykeepass import BLANK_DATABASE_LOCATION, BLANK_DATABASE_PASSWORD

__version__ = "1.3.0"

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
# into its XML (and into the next save). lxml < 6.1 has an advisory (GHSA-vfmq-68hx-4jfw) for the
# default iterparse() and ETCompatXMLParser() configurations. pykeepass doesn't pin lxml, so check here.
MIN_LXML = (6, 1)
KDBX_SIGNATURE = bytes.fromhex("03d9a29a67fb4bb5")
KEYFILE_LEN = 32  # KeePass and KeePassXC use a 32-byte key file as the raw key
HISTORY_MAX = 10  # versions kept per entry, KeePass's default
BACKUP_KEEP = 10  # previous vault files kept in <vault>.backups/
BACKUP_STAMP = "%Y%m%dT%H%M%S.%f"  # UTC, so backup names sort by age
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


def backup_dir(path: Path) -> Path:
    """Where previous versions of the vault at path are kept: beside the real file, so a
    symlinked vault keeps its backups next to its target."""
    target = Path(os.path.realpath(path))
    return target.with_name(target.name + ".backups")


def list_backups(path: Path) -> list:
    """(time, path) for each backup of the vault at path, newest first. Files in the backup
    directory that pwvault didn't name are ignored."""
    stem = Path(os.path.realpath(path)).stem
    try:
        names = os.listdir(backup_dir(path))
    except FileNotFoundError:
        return []
    found = []
    for name in names:
        if not (name.startswith(stem + "-") and name.endswith(".kdbx")):
            continue
        try:
            when = datetime.strptime(name[len(stem) + 1:-5], BACKUP_STAMP).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        found.append((when, backup_dir(path) / name))
    return sorted(found, reverse=True)


def remove_backups(path: Path, keep: int = 0) -> int:
    """Delete all but the newest `keep` backups and return how many went. A plain unlink: the
    backups are encrypted, and overwriting first achieves nothing on copy-on-write filesystems
    (btrfs, Fedora's default) or SSDs."""
    removed = 0
    for _, old in list_backups(path)[keep:]:
        try:
            old.unlink()
            removed += 1
        except OSError:
            pass  # a leftover backup is harmless; failing the save over it is not
    return removed


REKEY_MARKER = ".rekey-pending"  # in the backup folder; not named like a backup, so listings skip it


def _rekey_marker(path: Path) -> Path:
    return backup_dir(path) / REKEY_MARKER


def _write_rekey_marker(path: Path, blob: bytes) -> None:
    """Record the digest of the file a re-key is about to write, before writing it."""
    backup_dir(path).mkdir(parents=True, exist_ok=True, mode=0o700)
    write_private(_rekey_marker(path), hashlib.sha256(blob).hexdigest().encode())


def _finish_interrupted_rekey(path: Path, blob: bytes) -> None:
    """A re-key that crashed after writing the new file, before purging the backups made with the
    old key, is finished here. If the vault on disk is the file the marker recorded, the purge
    runs; otherwise the write never happened, so only the marker goes."""
    marker = _rekey_marker(path)
    try:
        recorded = marker.read_text().strip()
    except FileNotFoundError:
        return
    if recorded == hashlib.sha256(blob).hexdigest():
        remove_backups(path)
    marker.unlink(missing_ok=True)


def check_master_key(password: str, keyfile, yubikey=None) -> None:
    """A vault needs a strong password, or a key file or YubiKey (with or without a password)."""
    if not keyfile and not yubikey and len(password) < MIN_MASTER_LEN:
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
    """Integer and byte-array values of a KDBX 4 VariantDictionary (the KDF parameters)."""
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
        elif vtype == 0x42:  # byte array: the KDF's UUID ($UUID) and salt (S)
            out[key] = value
    return out


def read_kdf_params(blob: bytes) -> tuple:
    """(major version, KDF parameters) from the outer header, without deriving any key.
    (pykeepass derives the key while parsing, even with decrypt=False, so it can't do this.)"""
    if blob[:8] != KDBX_SIGNATURE or len(blob) < 12:
        raise VaultError("not a KeePass database")
    major = int.from_bytes(blob[10:12], "little")
    size_len = 4 if major >= 4 else 2
    pos, params = 12, {}
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
            return major, params
        if field == 6:  # KDBX 3 AES-KDF rounds
            params = {"R": int.from_bytes(data, "little")}
        elif field == 11:  # KDBX 4 KDF parameters
            params = _read_variant_dict(data)


def check_kdf_params(blob: bytes) -> None:
    """Bound the key-derivation cost from the header before anything runs it."""
    _, limits = read_kdf_params(blob)
    memory, passes = limits.get("M", 0), limits.get("I", 0)
    if (memory > MAX_KDF_MEMORY or passes > MAX_KDF_ITERATIONS or memory * passes > MAX_KDF_WORK
            or limits.get("P", 0) > MAX_KDF_PARALLELISM or limits.get("R", 0) > MAX_KDF_ROUNDS):
        raise VaultError("vault file asks for an unreasonable amount of memory or time to unlock")


def check_xml_parser() -> None:
    if etree.LXML_VERSION[:2] < MIN_LXML:
        raise VaultError(f"lxml {etree.__version__} is too old to open vaults safely; "
                         f"install lxml {'.'.join(map(str, MIN_LXML))} or newer (pip install -U lxml)")


# ---------------------------------------------------------------- YubiKey challenge-response
#
# The same scheme as KeePassXC 2.8 for KDBX 4 (src/keys/CompositeKey.cpp): the YubiKey's
# HMAC-SHA1 slot is challenged with the KDF salt, and SHA-256 of its 20-byte response joins the
# password and key-file hashes in the raw key that Argon2 then transforms. Nothing about the
# YubiKey is stored in the file. pykeepass can't add the response itself, so pwvault derives the
# transformed key and hands it to pykeepass.

ARGON2_KDFS = {bytes.fromhex("ef636ddf8c29444b91f7a9a403e30a0c"): "d",    # Argon2d
               bytes.fromhex("9e298b1956db4773b23dfc3ec6f0a1e6"): "id"}  # Argon2id
YUBIKEY_TIMEOUT = 15  # seconds to wait for a touch
YUBIKEY_NEEDS = "YubiKey unlock needs a KDBX 4 vault with Argon2 (pwvault creates those)"


@dataclass(frozen=True)
class YubiKeySlot:
    """Which YubiKey slot answers the challenge; the serial picks one of several keys."""
    slot: int
    serial: int | None = None

    @classmethod
    def parse(cls, text: str) -> "YubiKeySlot":
        """'2' or '2:12345678', the form keepassxc-cli's -y takes."""
        slot, _, serial = str(text).partition(":")
        if slot not in ("1", "2") or (serial and not serial.isdigit()):
            raise VaultError(f"YubiKey slot must be 1 or 2, optionally with a serial (e.g. 2:12345678), not {text!r}")
        return cls(int(slot), int(serial) if serial else None)

    def __str__(self) -> str:
        return f"{self.slot}:{self.serial}" if self.serial else str(self.slot)


def yubikey_challenge_block(challenge: bytes) -> bytes:
    """The 64-byte block KeePassXC sends: PKCS#7-style padding, which a YubiKey in variable-length
    mode strips (with any challenge bytes equal to the pad value) before computing the HMAC."""
    pad = 64 - len(challenge)
    return challenge + bytes([pad]) * pad


def yubikey_touch_prompt() -> None:
    """Shown once when the YubiKey waits for a touch. The GUI points this at its own status text."""
    print("Touch your YubiKey…", file=sys.stderr, flush=True)


def challenge_response(yubikey: YubiKeySlot, challenge: bytes) -> bytes:
    """Ask a plugged-in YubiKey for the HMAC-SHA1 response to challenge, through yubikey-manager
    (an optional dependency, imported only here)."""
    try:
        from ykman.device import list_all_devices
        from yubikit.core.otp import OtpConnection
        from yubikit.yubiotp import SLOT, YubiOtpSession
    except ImportError:
        raise VaultError("YubiKey support needs the yubikey extra: pip install 'pwvault-manager[yubikey]'")
    devices = [(d, i) for d, i in list_all_devices() if yubikey.serial in (None, i.serial)]
    if not devices:
        which = f" with serial {yubikey.serial}" if yubikey.serial else ""
        raise VaultError(f"no YubiKey{which} found; plug it in and try again")
    if len(devices) > 1:
        raise VaultError("more than one YubiKey is plugged in; choose one with its serial, "
                         f"e.g. --yubikey {yubikey.slot}:{devices[0][1].serial} (see `ykman list`)")
    device, _ = devices[0]
    slot = SLOT.ONE if yubikey.slot == 1 else SLOT.TWO
    cancel = threading.Event()
    timer = threading.Timer(YUBIKEY_TIMEOUT, cancel.set)
    prompted = []

    def keepalive(_status):
        """Prompt for a YubiKey touch only on the first keepalive callback."""
        if not prompted:
            prompted.append(True)
            yubikey_touch_prompt()
    try:
        with device.open_connection(OtpConnection) as conn:
            session = YubiOtpSession(conn)
            if not session.get_config_state().is_configured(slot):
                raise VaultError(f"YubiKey slot {yubikey.slot} is not set up for challenge-response "
                                 f"(set it up with: ykman otp chalresp --generate {yubikey.slot})")
            timer.start()
            return bytes(session.calculate_hmac_sha1(slot, yubikey_challenge_block(challenge),
                                                     cancel, keepalive))
    except VaultError:
        raise
    except Exception as e:
        if cancel.is_set():
            raise VaultError("timed out waiting for a touch on the YubiKey")
        raise VaultError(f"the YubiKey didn't answer the challenge ({e})")
    finally:
        timer.cancel()


def keyfile_key(keyfile) -> bytes:
    """The key a key file contributes, by the rules pykeepass and KeePass use: XML v1 (base64) or
    v2 (hex, checked), a 32-byte binary or 64-character hex file, otherwise SHA-256 of the file."""
    data = Path(keyfile).read_bytes()
    try:
        tree = etree.fromstring(data, etree.XMLParser(resolve_entities=False, no_network=True))
        version = tree.findtext("Meta/Version") or ""
        text = tree.findtext("Key/Data") or ""
        if version.startswith("1.0"):
            return base64.b64decode(text)
        if version.startswith("2.0"):
            key = bytes.fromhex("".join(text.split()))
            if hashlib.sha256(key).digest()[:4] != bytes.fromhex(tree.find("Key/Data").get("Hash", "")):
                raise VaultError(f"key file {keyfile} is damaged (its hash doesn't match)")
            return key
    except etree.XMLSyntaxError:
        pass
    if len(data) == 32:
        return data
    if len(data) == 64:
        try:
            return bytes.fromhex(data.decode("ascii"))
        except (UnicodeDecodeError, ValueError):
            pass
    return hashlib.sha256(data).digest()


def yubikey_transformed_key(params: dict, password, keyfile, yubikey: YubiKeySlot) -> bytes:
    """The Argon2-transformed key for password + key file + YubiKey, given the KDF parameters
    (with the salt the YubiKey is challenged with)."""
    kind = ARGON2_KDFS.get(params.get("$UUID"))
    if kind is None or not params.get("S"):
        raise VaultError(YUBIKEY_NEEDS)
    # From the file's header: a crafted file gets a clean error, not a crash. The salt is the
    # challenge, and a YubiKey challenge holds at most 63 bytes plus padding.
    if (not all(isinstance(params.get(k), int) and params[k] > 0 for k in ("I", "M", "P", "V"))
            or params["M"] // 1024 < 8 * params["P"]
            or params["V"] not in (0x10, 0x13)  # the only Argon2 versions
            or not isinstance(params["S"], bytes)
            or not 8 <= len(params["S"]) <= 63):
        raise VaultError("vault file has invalid key-derivation settings")
    import argon2.low_level as argon2_ll  # pykeepass's own dependency
    response = challenge_response(yubikey, params["S"])
    raw = hashlib.sha256((hashlib.sha256(password.encode()).digest() if password is not None else b"")
                         + (keyfile_key(keyfile) if keyfile else b"")
                         + hashlib.sha256(response).digest()).digest()
    return argon2_ll.hash_secret_raw(
        secret=raw, salt=params["S"], hash_len=32, time_cost=params["I"],
        memory_cost=params["M"] // 1024, parallelism=params["P"], version=params["V"],
        type=argon2_ll.Type.ID if kind == "id" else argon2_ll.Type.D)


def load_kdbx(blob: bytes, password, keyfile, yubikey: YubiKeySlot | None = None) -> PyKeePass:
    check_kdf_params(blob)
    check_xml_parser()
    transformed = None
    if yubikey is not None:
        major, params = read_kdf_params(blob)
        if major < 4:
            raise VaultError(YUBIKEY_NEEDS)
        transformed = yubikey_transformed_key(params, password, keyfile, yubikey)
    try:
        return PyKeePass(io.BytesIO(blob), password, keyfile, transformed_key=transformed)
    except CredentialsError:
        raise VaultError("wrong master password or key file")
    except PayloadChecksumError:
        raise VaultError("vault file is corrupted")
    except Exception:
        raise VaultError("vault file is truncated or corrupted")


class Vault:
    """An unlocked KeePass database plus the bookkeeping for safe saves."""

    def __init__(self, path: Path, kp: PyKeePass, disk_blob, transformed_key):
        self.path, self.kp = path, kp
        # File contents as last read or written by us; None for a vault not yet on disk.
        self.disk_blob = disk_blob
        # Derived key, reused so routine saves don't rerun Argon2. None after a key change.
        self.transformed_key = transformed_key
        self.rekeyed = False  # key changed and not yet saved; backups still use the old key
        self.purged_backups = 0  # old-key backups the last save deleted
        self.yubikey = None  # YubiKeySlot that is part of the master key, if any

    @classmethod
    def create(cls, path: Path, password: str, keyfile=None, yubikey=None) -> "Vault":
        check_master_key(password, keyfile, yubikey)
        kp = PyKeePass(BLANK_DATABASE_LOCATION, BLANK_DATABASE_PASSWORD)
        kp.password, kp.keyfile = password or None, str(keyfile) if keyfile else None
        vault = cls(path, kp, None, None)
        vault.yubikey = yubikey
        return vault

    @classmethod
    def open(cls, path: Path, password: str, keyfile=None, yubikey=None) -> "Vault":
        try:
            blob = path.read_bytes()
        except FileNotFoundError:
            raise VaultError(f"no vault at {path}")
        if keyfile and not Path(keyfile).is_file():
            raise VaultError(f"key file not found: {keyfile}")
        kp = load_kdbx(blob, password or None, str(keyfile) if keyfile else None, yubikey)
        _finish_interrupted_rekey(path, blob)
        vault = cls(path, kp, blob, kp.transformed_key)
        vault.yubikey = yubikey
        return vault

    def restore(self, backup: Path) -> None:
        """Make a backup the vault file again, once it's shown to open with this vault's key. The
        file it replaces is backed up first, like any save."""
        blob = backup.read_bytes()
        try:
            kp = load_kdbx(blob, self.kp.password, self.kp.keyfile, self.yubikey)
        except VaultError as e:
            raise VaultError(f"backup {backup.name} can't be restored: {e}")
        self._write(blob)
        self.kp, self.transformed_key = kp, kp.transformed_key

    def save(self) -> None:
        self.purged_backups = 0
        new_key = self.transformed_key is None  # first save after create/rekey: a fresh salt
        if new_key and self.yubikey is not None:
            # pykeepass can't include the YubiKey, so pick the new salt here, challenge the key with
            # it and derive the transformed key; saving with it keeps that salt.
            params = self.kp.kdbx.header.value.dynamic_header.kdf_parameters.data.dict \
                if self.kp.version >= (4, 0) else {}
            if ARGON2_KDFS.get(params["$UUID"].value if "$UUID" in params else None) is None:
                raise VaultError(YUBIKEY_NEEDS)
            params["S"].value = secrets.token_bytes(32)
            self.transformed_key = yubikey_transformed_key(
                {k: v.value for k, v in params.items()}, self.kp.password, self.kp.keyfile, self.yubikey)
        self._prune_binaries()
        buf = io.BytesIO()
        self.kp.save(buf, transformed_key=self.transformed_key)
        blob = buf.getvalue()
        if self.rekeyed:
            _write_rekey_marker(self.path, blob)  # so a crash before the purge is finished on open
        self._write(blob)
        if new_key:
            if self.transformed_key is None:
                # pykeepass ran Argon2 with a fresh salt; learn the new key.
                self.transformed_key = PyKeePass(io.BytesIO(blob), self.kp.password, self.kp.keyfile).transformed_key
            if self.rekeyed:
                # The new file opens with the new key, so the backups, all made with the retired
                # key (perhaps changed because it leaked), can go.
                self.purged_backups = remove_backups(self.path)
                _rekey_marker(self.path).unlink(missing_ok=True)
                self.rekeyed = False

    def _write(self, blob: bytes) -> None:
        """Replace the vault file with blob, first keeping the file it replaces as a backup."""
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
            if current is not None:
                # Under the lock and from the bytes just checked, so it's exactly what gets replaced.
                # If the backup can't be written, neither is the vault.
                stamp = datetime.now(timezone.utc).strftime(BACKUP_STAMP)
                write_private(backup_dir(target) / f"{target.stem}-{stamp}.kdbx", current)
            write_private(target, blob)
            self.disk_blob = blob
            remove_backups(target, keep=BACKUP_KEEP)
        finally:
            os.close(lock_fd)

    def rekey(self, password: str, keyfile=None, yubikey=None) -> None:
        """Change the master key. yubikey is the slot the new key includes (None: no YubiKey)."""
        check_master_key(password, keyfile, yubikey)
        self.kp.password, self.kp.keyfile = password or None, str(keyfile) if keyfile else None
        self.yubikey = yubikey
        self.transformed_key = None
        self.rekeyed = True

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
            self._record_deleted(group)
            self.kp.delete_group(group)
        else:
            self.kp.trash_group(group)
            self._moved(group)

    def _moved(self, item) -> None:
        """Stamp LocationChanged, which pykeepass never updates on a move, so a merge (here or in
        KeePassXC) knows this side's location is the newer one."""
        node = item._element.find("Times/LocationChanged")
        if node is None:
            node = etree.SubElement(item._element.find("Times"), "LocationChanged")
        node.text = self.kp._encode_time(datetime.now(timezone.utc))

    # ------------------------------------------------------------ entries

    def entries(self, group=None, query: str = "") -> list:
        """Entries directly in group, or matching query anywhere outside the recycle bin."""
        if query:
            q = query.lower()
            return [e for e in self.kp.entries if not self.in_recycle_bin(e)
                    and any(q in (v or "").lower() for v in (e.title, e.username, e.url, e.notes))]
        return list((group or self.root).entries)

    def add_entry(self, group, title, username, password, url="", notes="", expiry=None, otp=""):
        # pykeepass puts title and username into an XPath duplicate check (pointless with
        # force_creation) that breaks on a double quote, so set them afterwards.
        entry = self.kp.add_entry(group or self.root, "", "", password or "",
                                  url=url or None, notes=notes or None, force_creation=True)
        entry.title, entry.username = title or "", username or ""
        set_expiry(entry, expiry)
        set_otp(entry, otp)
        return entry

    # "otp" holds the TOTP setting; callers pass it through normalize_totp() first.
    FIELDS = ("title", "username", "password", "url", "notes", "otp")

    def update_entry(self, entry, fields: dict, group=None, expiry=KEEP,
                     add_attachments=(), remove_attachments=()) -> None:
        """Apply changes, archiving the previous version in the entry's history first.
        Changing nothing is a no-op: it adds no history version and doesn't touch the entry."""
        changed = (any(k in fields and field_differs(entry, k, fields[k]) for k in self.FIELDS)
                   or (expiry is not KEEP and expiry != (entry.expiry_time if entry.expires else None))
                   or bool(add_attachments) or bool(remove_attachments)
                   or (group is not None and group.uuid != entry.group.uuid))
        if not changed:
            return
        entry.save_history()
        while len(entry.history) > HISTORY_MAX:
            entry.delete_history(entry.history[0])  # oldest first
        for k in self.FIELDS:
            if k == "otp" and k in fields:
                set_otp(entry, fields[k])
            elif k in fields:
                setattr(entry, k, fields[k] or "")
        if expiry is not KEEP:
            set_expiry(entry, expiry)
        for att in remove_attachments:
            entry.delete_attachment(att)
        for name, data in add_attachments:
            entry.add_attachment(self.kp.add_binary(data), name)
        if group is not None and group.uuid != entry.group.uuid:
            self.kp.move_entry(entry, group)
            self._moved(entry)
        entry.touch(modify=True)

    def restore_history(self, entry, version) -> None:
        """Make an old version current again (the current one goes into history)."""
        fields = {k: getattr(version, k) for k in self.FIELDS}
        if not version.otp and version.get_custom_property("TOTP Seed"):
            # The old version kept its TOTP in the legacy fields. If the entry still does, leave
            # them alone; if it has since moved to "otp", bring the old secret back there.
            del fields["otp"]
            if entry.otp:
                try:
                    fields["otp"] = totp_uri(entry_totp(version), version.title, version.username)
                except VaultError:
                    pass  # unreadable then, unreadable now: keep the current setting
        self.update_entry(entry, fields, expiry=version.expiry_time if version.expires else None)

    def delete_entry(self, entry) -> None:
        """Move to the recycle bin; delete permanently if it is already there."""
        if self.in_recycle_bin(entry):
            self._record_deleted(entry)
            self.kp.delete_entry(entry)
        else:
            self._set_previous_group(entry, entry.group)
            self.kp.trash_entry(entry)
            self._moved(entry)

    def restore_entry(self, entry, group=None) -> None:
        """Restore to the given group, else to the group it was trashed from, else to the root."""
        target = group or self._previous_group(entry) or self.root
        self.kp.move_entry(entry, target)
        self._moved(entry)
        self._clear_previous_group(entry)

    # The group an entry was trashed from is stored in the standard PreviousParentGroup element
    # (base64 UUID of the group), the same element KeePassXC writes, so both apps restore alike.
    def _set_previous_group(self, entry, group) -> None:
        el = entry._element.find("PreviousParentGroup")
        if el is None:
            el = etree.SubElement(entry._element, "PreviousParentGroup")
        el.text = base64.b64encode(group.uuid.bytes).decode()

    def _previous_group(self, entry):
        el = entry._element.find("PreviousParentGroup")
        if el is None or not el.text:
            return None
        try:
            group_uuid = uuid.UUID(bytes=base64.b64decode(el.text, validate=True))
        except (ValueError, TypeError):
            return None  # a damaged element means "unknown", so the entry goes to the root
        group = self.kp.find_groups(uuid=group_uuid, first=True)
        if group is None or self.in_recycle_bin(group):
            return None
        return group

    def _clear_previous_group(self, entry) -> None:
        el = entry._element.find("PreviousParentGroup")
        if el is not None:
            entry._element.remove(el)

    def empty_recycle_bin(self) -> int:
        bin_ = self.recycle_bin
        if bin_ is None:
            return 0
        count = len(bin_.entries) + len(bin_.subgroups)
        for item in bin_.subgroups + bin_.entries:
            self._record_deleted(item)
        self.kp.empty_group(bin_)
        return count

    def _record_deleted(self, item) -> None:
        """Note a permanent delete in the standard DeletedObjects list, as KeePassXC does, so a
        merge with an older copy that still has the item removes it instead of bringing it back.
        A group records everything inside it too."""
        root = self.kp.tree.getroot().find("Root")
        deleted = root.find("DeletedObjects")
        if deleted is None:
            deleted = etree.SubElement(root, "DeletedObjects")
        el = item._element
        items = [el] + [e for e in el.iter("Entry", "Group")
                        if e is not el and e.getparent().tag == "Group"]  # not History versions
        stamp = self.kp._encode_time(datetime.now(timezone.utc))
        for e in items:
            obj = etree.SubElement(deleted, "DeletedObject")
            etree.SubElement(obj, "UUID").text = e.findtext("UUID")
            etree.SubElement(obj, "DeletionTime").text = stamp

    def add_attachment(self, entry, name: str, data: bytes):
        return entry.add_attachment(self.kp.add_binary(data), name)


def field_differs(entry, key: str, value) -> bool:
    if key == "otp":  # no TOTP differs from a TOTP kept in the legacy fields
        return (value or "") != (entry.otp or "") or (not value and bool(entry.get_custom_property("TOTP Seed")))
    return (value or "") != (getattr(entry, key) or "")


def set_otp(entry, value: str) -> None:
    """Store a TOTP setting in "otp" (protected, as KeePassXC does), or remove the entry's TOTP if
    value is empty. A change also drops the legacy TOTP fields, so an entry never holds two secrets."""
    if not field_differs(entry, "otp", value):
        return
    for key in TOTP_LEGACY_FIELDS:
        remove_string_field(entry, key)
    if value:
        entry.otp = value
    else:
        remove_string_field(entry, "otp")


def remove_string_field(entry, key: str) -> None:
    # pykeepass's delete_custom_property() refuses "otp" (a reserved key) and builds an XPath
    # from the key, so compare the Key text directly.
    for s in entry._element.findall("String"):
        if s.findtext("Key") == key:
            entry._element.remove(s)


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


# ---------------------------------------------------------------- TOTP (2FA) codes

# Stored the way KeePassXC stores it: an otpauth:// URI in the entry's "otp" field. Also read, as
# KeePassXC does: KeeOtp's "key=…&step=…&size=…" in that field, and the older KeeTrayTOTP fields
# "TOTP Seed" + "TOTP Settings" ("30;6", or "30;S" for Steam).
TOTP_LEGACY_FIELDS = ("TOTP Seed", "TOTP Settings")
TOTP_ALGORITHMS = {"SHA1": "sha1", "SHA256": "sha256", "SHA512": "sha512"}
STEAM_ALPHABET = "23456789BCDFGHJKMNPQRTVWXY"


@dataclass(frozen=True)
class Totp:
    secret: bytes
    digits: int = 6
    period: int = 30
    algorithm: str = "SHA1"
    steam: bool = False  # Steam Guard: characters from STEAM_ALPHABET instead of digits


def _totp_secret(text: str) -> bytes:
    """Decode base32 as sites display it: any case, with spaces or dashes, padding optional."""
    s = "".join(text.split()).replace("-", "").upper().rstrip("=")
    try:
        secret = base64.b32decode(s + "=" * (-len(s) % 8))
    except ValueError:  # includes binascii.Error and non-ASCII input
        raise VaultError("TOTP secret isn't valid base32")
    if not secret:
        raise VaultError("TOTP secret is empty")
    return secret


def _make_totp(secret: str, digits, period, algorithm="SHA1", steam=False) -> Totp:
    algo = (algorithm or "SHA1").upper().replace("-", "")
    if algo not in TOTP_ALGORITHMS:
        raise VaultError(f"unknown TOTP algorithm {algorithm}")
    try:
        period = int(period)
    except (TypeError, ValueError):
        period = 0
    if period <= 0:
        raise VaultError("TOTP period must be a positive number of seconds")
    # Steam codes are 5 characters. KeePassXC makes them as long as an otpauth URI's digits=
    # (it writes digits=5 itself), so honour that, but default to Steam's 5 rather than its 6.
    low = 5 if steam else 6
    try:
        digits = int(digits if digits not in (None, "") else low)
    except (TypeError, ValueError):
        digits = 0
    if not low <= digits <= 10:
        raise VaultError(f"TOTP digits must be {low}–10")
    return Totp(_totp_secret(secret), digits, period, algo, steam)


def parse_totp(text: str) -> Totp:
    """Read an otpauth://totp URI or a KeeOtp "key=…" string, as KeePassXC does."""
    text = (text or "").strip()
    if text.lower().startswith("otpauth://"):
        url = urllib.parse.urlsplit(text)
        kind = url.netloc.lower()
        if kind == "hotp":
            raise VaultError("HOTP (counter-based) codes aren't supported")
        if kind != "totp":
            raise VaultError("TOTP setting isn't an otpauth://totp URI")
        q = {k.lower(): v for k, v in urllib.parse.parse_qsl(url.query)}
        return _make_totp(q.get("secret", ""), q.get("digits"), q.get("period", 30),
                          q.get("algorithm", "SHA1"), q.get("encoder", "").lower() == "steam")
    q = {k.lower(): v for k, v in urllib.parse.parse_qsl(text)}
    if "key" in q:
        return _make_totp(q["key"], q.get("size", 6), q.get("step", 30), q.get("otphashmode", "SHA1"))
    raise VaultError("TOTP setting isn't an otpauth:// URI or a KeeOtp key=… string")


def entry_totp(entry):
    """The entry's TOTP settings, or None if it has none. Raises VaultError if they're unreadable."""
    if entry.otp:
        return parse_totp(entry.otp)
    seed = entry.get_custom_property("TOTP Seed")
    if not seed:
        return None
    period, digits = ((entry.get_custom_property("TOTP Settings") or "").split(";") + ["", ""])[:2]
    steam = digits.strip().upper() == "S"
    return _make_totp(seed, None if steam else digits.strip(), period.strip() or 30, steam=steam)


def totp_code(t: Totp, now=None) -> tuple:
    """(current code, seconds until it changes), per RFC 6238 (and Steam's variant of it)."""
    now = int(time.time() if now is None else now)
    counter, elapsed = divmod(now, t.period)
    mac = hmac.new(t.secret, struct.pack(">Q", counter), TOTP_ALGORITHMS[t.algorithm]).digest()
    offset = mac[-1] & 0x0F
    n = int.from_bytes(mac[offset:offset + 4], "big") & 0x7FFFFFFF  # RFC 4226 dynamic truncation
    if t.steam:
        code = ""
        for _ in range(t.digits):
            n, i = divmod(n, len(STEAM_ALPHABET))
            code += STEAM_ALPHABET[i]
    else:
        code = str(n % 10 ** t.digits).zfill(t.digits)
    return code, t.period - elapsed


def fmt_totp_code(code: str) -> str:
    """'123 456', '1234 5678'; Steam codes as they are. For display only, never for copying."""
    if not code.isdigit():
        return code
    half = (len(code) + 1) // 2
    return f"{code[:half]} {code[half:]}"


def totp_uri(t: Totp, title: str, username: str) -> str:
    """The otpauth URI KeePassXC writes for these settings."""
    issuer = urllib.parse.quote(title or "pwvault", safe="")
    secret = base64.b32encode(t.secret).decode().rstrip("=")
    uri = (f"otpauth://totp/{issuer}:{urllib.parse.quote(username or '', safe='')}"
           f"?secret={secret}&period={t.period}&digits={t.digits}&issuer={issuer}")
    if t.steam:
        uri += "&encoder=steam"
    if t.algorithm != "SHA1":
        uri += f"&algorithm={t.algorithm}"
    return uri


def normalize_totp(text: str, title: str = "", username: str = "") -> str:
    """What to store in "otp" for what the user typed: a valid otpauth URI as is (KeePassXC keeps
    extra parameters too), or a bare base32 secret as a standard 30 s / 6-digit URI."""
    text = (text or "").strip()
    if text.lower().startswith("otpauth://"):
        parse_totp(text)
        return text
    return totp_uri(Totp(_totp_secret(text)), title, username)


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


# ---------------------------------------------------------------- merge two vaults
#
# Follows KeePassXC's merge (src/core/Merger.cpp, 2.8) in its Synchronize mode. Entries and groups
# are matched by UUID. For an entry the newer LastModificationTime wins and both sides' versions
# end up in its history; an item goes where the side with the newer LocationChanged put it; and
# permanent deletions recorded in either DeletedObjects list apply, unless the item was changed
# after it was deleted. Unlike KeePassXC's default mode (KeepNewer), deletions are not ignored.

TIME_TAGS = ("CreationTime", "LastModificationTime", "LastAccessTime", "ExpiryTime",
             "LocationChanged", "DeletionTime")
EPOCH = datetime(1, 1, 1, tzinfo=timezone.utc)


@dataclass
class MergeReport:
    """Changes a merge made, each as (group path, title); groups have a trailing '/'."""
    added: list = field(default_factory=list)
    updated: list = field(default_factory=list)
    moved: list = field(default_factory=list)
    deleted: list = field(default_factory=list)
    metadata: bool = False  # DeletedObjects, custom icons, recycle bin or group times changed

    @property
    def changed(self) -> bool:
        return bool(self.added or self.updated or self.moved or self.deleted or self.metadata)


def check_other_copy(vault_path: Path, other: Path) -> None:
    """The other copy must exist and be a different file from the vault (symlinks count)."""
    if not other.is_file():
        raise VaultError(f"no file at {other}")
    if vault_path.exists() and os.path.samefile(other, vault_path):
        raise VaultError(f"{other} is this vault itself; give the path of another copy")


def open_other_copy(vault_path: Path, other: Path, password, keyfile, yubikey=None) -> PyKeePass:
    """Open another copy of the vault for merge_vaults, read-only (it is never written). Used by
    both the CLI and the GUI; errors name the file."""
    check_other_copy(vault_path, other)
    if keyfile and not Path(keyfile).is_file():
        raise VaultError(f"key file not found: {keyfile}")
    try:
        return load_kdbx(other.read_bytes(), password or None, str(keyfile) if keyfile else None, yubikey)
    except VaultError as e:
        raise VaultError(f"{other}: {e}")


def merge_vaults(vault: Vault, other: PyKeePass) -> MergeReport:
    """Merge another copy of the vault into this one, in memory. `other` is only read; the caller
    saves `vault` (so the merge is backed up and conflict-checked like any save)."""
    return _Merger(vault.kp, other).run()


class _Merger:
    def __init__(self, target: PyKeePass, source: PyKeePass):
        self.t, self.s = target, source
        self.report = MergeReport()
        self.entries, self.groups = {}, {}  # target's live entries and groups, by UUID
        for g in target.root_group._element.iter("Group"):
            self.groups[g.findtext("UUID")] = g
            for e in g.findall("Entry"):
                self.entries[e.findtext("UUID")] = e
        self.binary_refs = {}  # source binary id -> target binary id
        self.added = {}  # UUID -> report item, so an item added and then deleted shows as neither

    def run(self) -> MergeReport:
        self.merge_group(self.s.root_group._element, self.t.root_group._element)
        self.merge_deletions()
        self.merge_metadata()
        return self.report

    # ---- helpers

    @staticmethod
    def time(kp, el, tag="LastModificationTime") -> datetime:
        text = el.findtext(f"Times/{tag}")
        return kp._decode_time(text).replace(microsecond=0) if text else EPOCH

    @staticmethod
    def title(el) -> str:
        for s in el.findall("String"):
            if s.findtext("Key") == "Title":
                return s.findtext("Value") or ""
        return ""

    @staticmethod
    def path(el) -> str:
        names = [g.findtext("Name") or "" for g in el.iterancestors("Group")]
        return "/".join(reversed(names))

    def item(self, el):
        if el.tag == "Group":
            return (self.path(el), (el.findtext("Name") or "") + "/")
        return (self.path(el), self.title(el))

    def adopt(self, el):
        """A copy of a source element in the target's terms: times in the target's encoding (KDBX 3
        and 4 differ) and attachments pointing at copies in the target's binary pool."""
        el = copy.deepcopy(el)
        if self.s.version != self.t.version:
            for times in el.iter("Times"):
                for child in times:
                    if child.tag in TIME_TAGS and child.text:
                        child.text = self.t._encode_time(self.s._decode_time(child.text))
        for value in el.iter("Value"):
            ref = value.get("Ref")
            if ref is not None and value.getparent().tag == "Binary":
                value.set("Ref", str(self.binary(int(ref))))
        return el

    def binary(self, ref: int) -> int:
        if ref not in self.binary_refs:
            data = self.s.binaries[ref]
            existing = self.t.binaries
            self.binary_refs[ref] = existing.index(data) if data in existing else self.t.add_binary(data)
        return self.binary_refs[ref]

    def set_time(self, source_el, target_el, tag) -> None:
        text = source_el.findtext(f"Times/{tag}")
        node = target_el.find(f"Times/{tag}")
        if text is not None and node is not None:
            node.text = self.t._encode_time(self.s._decode_time(text))

    @staticmethod
    def put_entry(group, entry) -> None:
        """Place (or move) an entry into a group, before its subgroups as KeePass writes them."""
        first_group = next((i for i, c in enumerate(group) if c.tag == "Group"), None)
        if first_group is None:
            group.append(entry)
        else:
            group.insert(first_group, entry)

    # ---- groups and entries

    def merge_group(self, s_group, t_group) -> None:
        for s_entry in s_group.findall("Entry"):
            uid = s_entry.findtext("UUID")
            t_entry = self.entries.get(uid)
            if t_entry is None:
                new = self.adopt(s_entry)
                self.put_entry(t_group, new)
                self.entries[uid] = new
                self.added[uid] = self.item(new)
                self.report.added.append(self.added[uid])
                continue
            if (self.time(self.t, t_entry, "LocationChanged") < self.time(self.s, s_entry, "LocationChanged")
                    and t_entry.getparent() is not t_group):
                self.put_entry(t_group, t_entry)
                self.report.moved.append(self.item(t_entry))
            self.resolve_entry(s_entry, t_entry)

        for s_child in s_group.findall("Group"):
            uid = s_child.findtext("UUID")
            t_child = self.groups.get(uid)
            if t_child is None:
                shell = etree.Element("Group")
                for c in s_child:
                    if c.tag not in ("Entry", "Group"):
                        shell.append(copy.deepcopy(c))
                t_child = self.adopt(shell)
                t_group.append(t_child)
                self.groups[uid] = t_child
                self.added[uid] = self.item(t_child)
                self.report.added.append(self.added[uid])
            else:
                if (self.time(self.t, t_child, "LocationChanged") < self.time(self.s, s_child, "LocationChanged")
                        and t_child.getparent() is not t_group):
                    t_group.append(t_child)
                    self.set_time(s_child, t_child, "LocationChanged")
                    self.report.moved.append(self.item(t_child))
                self.resolve_group(s_child, t_child)
            self.merge_group(s_child, t_child)

    def resolve_group(self, s_group, t_group) -> None:
        """The newer side's name, notes, icon and expiry win."""
        if not self.time(self.t, t_group) < self.time(self.s, s_group):
            return
        differs = False
        for tag in ("Name", "Notes", "IconID", "CustomIconUUID"):
            s_node, t_node = s_group.find(tag), t_group.find(tag)
            if (s_node.text if s_node is not None else None) == (t_node.text if t_node is not None else None):
                continue
            differs = True
            if s_node is None:
                t_group.remove(t_node)
            elif t_node is None:
                t_group.insert(list(t_group).index(t_group.find("UUID")) + 1, copy.deepcopy(s_node))
            else:
                t_node.text = s_node.text
        s_expires, t_expires = s_group.find("Times/Expires"), t_group.find("Times/Expires")
        if s_expires is not None and t_expires is not None and (
                s_expires.text != t_expires.text
                or self.time(self.s, s_group, "ExpiryTime") != self.time(self.t, t_group, "ExpiryTime")):
            differs = True
            t_expires.text = s_expires.text
            self.set_time(s_group, t_group, "ExpiryTime")
        self.set_time(s_group, t_group, "LastModificationTime")
        self.report.metadata = True
        if differs:
            self.report.updated.append(self.item(t_group))

    def resolve_entry(self, s_entry, t_entry) -> None:
        if self.time(self.t, t_entry) < self.time(self.s, s_entry):
            # The other side is newer: it becomes current, this side's versions join its history.
            new = self.adopt(s_entry)
            self.merge_history(t_entry, self.t, new)
            t_entry.getparent().replace(t_entry, new)
            self.entries[new.findtext("UUID")] = new
            self.report.updated.append(self.item(new))
        elif self.merge_history(s_entry, self.s, t_entry):
            self.report.updated.append(self.item(t_entry))

    def merge_history(self, src, src_kp, dst) -> bool:
        """Add src's history (and src itself, if older) to dst's history: one version per
        modification time, oldest first, the newest HISTORY_MAX kept. Returns whether it changed."""
        take = self.adopt if src_kp is self.s else copy.deepcopy
        src_time, dst_time = self.time(src_kp, src), self.time(self.t, dst)
        dst_hist = dst.find("History")
        old = list(dst_hist) if dst_hist is not None else []
        merged = {self.time(self.t, h): h for h in old}
        for h in (src.find("History") if src.find("History") is not None else []):
            when = self.time(src_kp, h)
            if src_time > dst_time:
                merged.pop(when, None)  # same time on both sides: the newer entry's version wins
            if when not in merged:
                merged[when] = take(h)
        if dst_time > src_time and src_time not in merged:
            version = take(src)
            for h in version.findall("History"):
                version.remove(h)
            merged[src_time] = version
        new = [merged[k] for k in sorted(merged)][-HISTORY_MAX:]
        if [etree.tostring(h) for h in new] == [etree.tostring(h) for h in old[-HISTORY_MAX:]]:
            return False
        if dst_hist is None:
            dst_hist = etree.SubElement(dst, "History")
        for h in list(dst_hist):
            dst_hist.remove(h)
        dst_hist.extend(new)
        return True

    # ---- deletions and metadata

    def merge_deletions(self) -> None:
        """Apply both sides' DeletedObjects (the earliest time per UUID). An item changed after
        it was deleted, or a group that still holds anything, stays, and its deletion is dropped."""
        when, order = {}, []
        for kp in (self.t, self.s):
            for obj in kp.tree.getroot().findall("Root/DeletedObjects/DeletedObject"):
                uid, text = obj.findtext("UUID"), obj.findtext("DeletionTime")
                if not uid or not text:
                    continue
                t = kp._decode_time(text).replace(microsecond=0)
                if uid not in when:
                    order.append(uid)
                    when[uid] = t
                elif t < when[uid]:
                    when[uid] = t
        keep = []
        for uid in order:
            entry = self.entries.get(uid)
            if entry is None:
                if uid not in self.groups:
                    keep.append(uid)  # already gone here: keep the record for the next merge
                continue
            if self.time(self.t, entry) <= when[uid]:
                self.deleted(uid, entry)
                del self.entries[uid]
                keep.append(uid)
        root_uid = self.t.root_group._element.findtext("UUID")
        groups = [u for u in order if u in self.groups and u != root_uid]
        groups.sort(key=lambda u: -len(list(self.groups[u].iterancestors())))  # children first
        for uid in groups:
            group = self.groups[uid]
            if (self.time(self.t, group) > when[uid] or group.find("Entry") is not None
                    or group.find("Group") is not None):
                continue
            self.deleted(uid, group)
            del self.groups[uid]
            keep.append(uid)
        keep.sort(key=order.index)
        records = [(u, self.t._encode_time(when[u])) for u in keep]
        container = self.t.tree.getroot().find("Root/DeletedObjects")
        current = [(o.findtext("UUID"), o.findtext("DeletionTime")) for o in container] \
            if container is not None else []
        if records != current:
            if container is None:
                container = etree.SubElement(self.t.tree.getroot().find("Root"), "DeletedObjects")
            for o in list(container):
                container.remove(o)
            for uid, stamp in records:
                obj = etree.SubElement(container, "DeletedObject")
                etree.SubElement(obj, "UUID").text = uid
                etree.SubElement(obj, "DeletionTime").text = stamp
            self.report.metadata = True

    def deleted(self, uid, el) -> None:
        item = self.added.pop(uid, None)
        if item is not None:
            self.report.added.remove(item)  # came from the other side and was deleted here
        else:
            self.report.deleted.append(self.item(el))
        el.getparent().remove(el)

    def merge_metadata(self) -> None:
        t_meta, s_meta = self.t.tree.getroot().find("Meta"), self.s.tree.getroot().find("Meta")
        s_icons = s_meta.find("CustomIcons")
        if s_icons is not None:
            t_icons = t_meta.find("CustomIcons")
            if t_icons is None:
                t_icons = etree.SubElement(t_meta, "CustomIcons")
            have = {i.findtext("UUID") for i in t_icons}
            for icon in s_icons:
                if icon.findtext("UUID") not in have:
                    new = copy.deepcopy(icon)
                    stamp = new.find("LastModificationTime")
                    if stamp is not None and stamp.text and self.s.version != self.t.version:
                        stamp.text = self.t._encode_time(self.s._decode_time(stamp.text))
                    t_icons.append(new)
                    self.report.metadata = True
        # A copy that never had a recycle bin adopts the other side's (KeePassXC leaves it a plain
        # group), so entries trashed over there show as trashed here too.
        t_bin, s_bin = t_meta.find("RecycleBinUUID"), s_meta.findtext("RecycleBinUUID")
        no_bin = t_bin is None or not t_bin.text or base64.b64decode(t_bin.text) == bytes(16)
        if no_bin and s_bin and s_bin in self.groups:
            if t_bin is None:
                t_bin = etree.SubElement(t_meta, "RecycleBinUUID")
            t_bin.text = s_bin
            enabled = t_meta.find("RecycleBinEnabled")
            if enabled is None:
                enabled = etree.SubElement(t_meta, "RecycleBinEnabled")
            enabled.text = "True"
            self.report.metadata = True


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
    if path.exists():  # an export is a copy of the vault; never replace a file the user may still need
        raise VaultError(f"{path} already exists; choose another name")
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


# ---------------------------------------------------------------- offline breach check
#
# Have I Been Pwned's Pwned Passwords list, kept on this machine so a check sends nothing anywhere.
# HIBP publishes it only as 16^5 range files (api.pwnedpasswords.com/range/XXXXX), one per 5-hex
# SHA-1 prefix; downloading every range reveals nothing about any password. The store keeps, for
# each range in order, the next PWNED_RECORD bytes of each hash, sorted, plus an index of where
# each range starts. That is 68 bits per hash, so a false match is about N / 2^68 per password
# (around 1 in 10^11 for the ~2.6 billion hashes HIBP had in 2026). Counts are not kept.
#
# Layout under breach_dir(): store-<stamp>/{hashes.bin,index.bin,meta.json}, a "current" symlink
# to the live one, and partial/ (download) or import-partial/ (import) while a build runs. A
# finished build is renamed and the symlink swapped in one step, so a check never sees half a store.

PWNED_API = "https://api.pwnedpasswords.com/range/"
PWNED_RANGES = 1 << 20  # 16^5 prefixes
PWNED_RECORD = 6  # bytes kept per hash after the 5-hex prefix
PWNED_BATCH = 4096  # ranges fetched, written and fsynced together; a resume restarts here
PWNED_WORKERS = 16
PWNED_TRIES = 5
PWNED_MIN_FREE = 20 << 30  # the full list is ~16 GB in this format (~2,500 hashes per range)
PWNED_FORMAT = 1
_PWNED_RANGE_LINE = re.compile(rb"([0-9A-F]{35}):(\d+)")
_PWNED_FILE_LINE = re.compile(rb"([0-9A-F]{40}):(\d+)")


def breach_dir() -> Path:
    """Where the breach list lives: the cache directory, never the vault's folder, since it is
    large and can always be downloaded again."""
    base = os.environ.get("XDG_CACHE_HOME")
    return (Path(base) if base else Path.home() / ".cache") / "pwvault" / "pwned"


def parse_range(body: bytes, prefix: str) -> bytes:
    """The store records for one range from its 'SUFFIX:COUNT' lines, sorted."""
    suffixes = []
    for line in body.split(b"\n"):
        line = line.strip()
        if not line:
            continue
        m = _PWNED_RANGE_LINE.fullmatch(line)
        if not m:
            raise VaultError(f"range {prefix} has malformed data")
        if int(m[2]):  # padding lines have a count of 0
            suffixes.append(m[1])
    suffixes.sort()
    if any(a == b for a, b in zip(suffixes, suffixes[1:])):
        raise VaultError(f"range {prefix} lists a hash twice")
    return b"".join(base64.b16decode(h[:2 * PWNED_RECORD]) for h in suffixes)


def fetch_range(prefix: str) -> bytes:
    """One range from the HIBP API, gzip-compressed in transit (about half the size)."""
    req = urllib.request.Request(PWNED_API + prefix, headers={
        "User-Agent": f"pwvault-manager/{__version__}", "Accept-Encoding": "gzip"})
    with urllib.request.urlopen(req, timeout=30) as r:
        body, encoding = r.read(), r.headers.get("Content-Encoding", "")
    if encoding == "gzip":
        try:
            return gzip.decompress(body)
        except (OSError, EOFError, zlib.error):
            raise VaultError(f"range {prefix} arrived damaged")
    return body


def _fetch_checked(prefix: str, fetch) -> bytes:
    err = None
    for attempt in range(PWNED_TRIES):
        try:
            records = parse_range(fetch(prefix), prefix)
            if not records:  # every real range holds hundreds of hashes
                raise VaultError(f"range {prefix} came back empty")
            return records
        except (OSError, http.client.HTTPException, VaultError) as e:  # urllib's errors are OSErrors
            err = e
            if attempt < PWNED_TRIES - 1:
                time.sleep(min(2 ** attempt, 30))
    raise VaultError(f"couldn't download range {prefix} after {PWNED_TRIES} tries ({err})")


class _BreachBuild:
    """A store under construction, in partial/ (download) or import-partial/ (import):
    hashes.bin grows range by range and index.bin holds the offsets of the ranges finished so
    far, so its length is the resume point."""

    def __init__(self, root: Path, fresh: bool, name: str = "partial"):
        self.root, self.dir = root, root / name
        if fresh and self.dir.exists():
            shutil.rmtree(self.dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        hashes, index = self.dir / "hashes.bin", self.dir / "index.bin"
        offsets = index.read_bytes() if index.exists() else b""
        offsets = offsets[:len(offsets) // 8 * 8] or struct.pack("<Q", 0)
        if len(offsets) // 8 - 1 > PWNED_RANGES:
            offsets = struct.pack("<Q", 0)
        self.done = len(offsets) // 8 - 1
        self.total = struct.unpack_from("<Q", offsets, len(offsets) - 8)[0]
        for path in (hashes, index):
            path.touch()
        self._hashes, self._index = open(hashes, "r+b"), open(index, "r+b")
        # Anything past the last recorded offset came from a batch that didn't finish.
        self._hashes.truncate(self.total * PWNED_RECORD)
        self._hashes.seek(0, os.SEEK_END)
        self._index.truncate(len(offsets))
        self._index.seek(0)
        self._index.write(offsets)

    @property
    def size(self) -> int:
        return self.total * PWNED_RECORD

    def append(self, ranges) -> None:
        """Add the next ranges' records, then make them durable before recording them done."""
        offsets = []
        for records in ranges:
            self._hashes.write(records)
            self.total += len(records) // PWNED_RECORD
            offsets.append(self.total)
        self._hashes.flush()
        os.fsync(self._hashes.fileno())
        self._index.write(struct.pack(f"<{len(offsets)}Q", *offsets))
        self._index.flush()
        os.fsync(self._index.fileno())
        self.done += len(offsets)

    def finish(self, source: str) -> int:
        if self.done != PWNED_RANGES:
            raise VaultError(f"breach list incomplete ({self.done} of {PWNED_RANGES} ranges)")
        self.close()
        meta = {"format": PWNED_FORMAT, "source": source, "hashes": self.total,
                "completed": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        with open(self.dir / "meta.json", "w") as f:
            json.dump(meta, f)
            f.flush()
            os.fsync(f.fileno())
        store = self.root / f"store-{datetime.now(timezone.utc).strftime(BACKUP_STAMP)}"
        os.rename(self.dir, store)
        self._make_current(store)
        for old in self.root.glob("store-*"):
            if old != store:
                shutil.rmtree(old, ignore_errors=True)
        return self.total

    def _make_current(self, store: Path) -> None:
        """Point the "current" symlink at store in one atomic, durable step."""
        link = self.root / "current.new"
        if link.is_symlink() or link.exists():
            link.unlink()
        link.symlink_to(store.name)
        os.replace(link, self.root / "current")
        fd = os.open(self.root, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def close(self) -> None:
        self._hashes.close()
        self._index.close()


def _check_free_space(root: Path, already: int) -> None:
    free = shutil.disk_usage(root).free
    if free + already < PWNED_MIN_FREE:
        need = (PWNED_MIN_FREE - already) / (1 << 30)
        raise VaultError(f"the breach list needs about {need:.0f} GB free in {root} "
                         f"({free / (1 << 30):.1f} GB free)")


def update_breach_list(fetch=None, progress=None) -> int:
    """Download the whole list from HIBP, resuming an interrupted download. Returns the hash count."""
    fetch = fetch or fetch_range
    root = breach_dir()
    root.mkdir(parents=True, exist_ok=True)
    build = _BreachBuild(root, fresh=False)
    try:
        _check_free_space(root, build.size)
        pool = concurrent.futures.ThreadPoolExecutor(PWNED_WORKERS)
        try:
            for start in range(build.done, PWNED_RANGES, PWNED_BATCH):
                prefixes = [f"{r:05X}" for r in range(start, min(start + PWNED_BATCH, PWNED_RANGES))]
                build.append(pool.map(lambda p: _fetch_checked(p, fetch), prefixes))
                if progress:
                    progress(build.done, PWNED_RANGES)
        except BaseException:
            pool.shutdown(wait=False, cancel_futures=True)
            raise
        pool.shutdown()
        return build.finish(PWNED_API)
    finally:
        build.close()


def import_breach_list(path: Path, progress=None) -> int:
    """Build the store from a 'HASH:COUNT' text file sorted by hash (the output of HIBP's
    PwnedPasswordsDownloader), read line by line. Returns the hash count."""
    root = breach_dir()
    root.mkdir(parents=True, exist_ok=True)

    def ranges():
        current, records, last = 0, [], b""
        with open(path, "rb") as f:
            for n, line in enumerate(f, 1):
                line = line.strip().upper()
                if not line:
                    continue
                m = _PWNED_FILE_LINE.fullmatch(line)
                if not m or m[1] <= last:
                    raise VaultError(f"{path}: line {n} is not a HASH:COUNT line in hash order")
                last = m[1]
                r = int(m[1][:5], 16)
                while current < r:
                    yield b"".join(records)
                    records, current = [], current + 1
                if int(m[2]):
                    records.append(base64.b16decode(m[1][5:5 + 2 * PWNED_RECORD]))
        while current < PWNED_RANGES:
            yield b"".join(records)
            records, current = [], current + 1

    build = _BreachBuild(root, fresh=True, name="import-partial")  # never touches a paused download
    try:
        _check_free_space(root, 0)
        it = ranges()
        for _ in range(0, PWNED_RANGES, PWNED_BATCH):
            build.append(itertools.islice(it, PWNED_BATCH))
            if progress:
                progress(build.done, PWNED_RANGES)
        return build.finish(f"file {Path(path).name}")
    finally:
        build.close()


class BreachStore:
    """The live breach list, read in place: a lookup reads two index entries and one range."""

    DAMAGED = "the breach list is damaged — run `pwvault breach update`"

    def __init__(self, root: Path | None = None):
        root = root or breach_dir()
        if not (root / "current").exists():
            raise VaultError("no breach list yet — run `pwvault breach update`")
        store = Path(os.path.realpath(root / "current"))  # resolve once: a later swap can't mix stores
        try:
            self.meta = json.loads((store / "meta.json").read_text())
            self._hashes = os.open(store / "hashes.bin", os.O_RDONLY)
            self._index = os.open(store / "index.bin", os.O_RDONLY)
        except (OSError, ValueError):
            self.close()
            raise VaultError(self.DAMAGED)
        if (not isinstance(self.meta, dict) or self.meta.get("format") != PWNED_FORMAT
                or os.fstat(self._index).st_size != (PWNED_RANGES + 1) * 8
                or os.fstat(self._hashes).st_size != self.meta.get("hashes", -1) * PWNED_RECORD):
            self.close()
            raise VaultError(self.DAMAGED)

    def contains(self, password: str) -> bool:
        digest = hashlib.sha1(password.encode()).digest()  # HIBP hashes the UTF-8 password
        bits = int.from_bytes(digest[:9], "big") >> 4  # the top 68 bits
        r = bits >> (8 * PWNED_RECORD)
        key = (bits & ((1 << (8 * PWNED_RECORD)) - 1)).to_bytes(PWNED_RECORD, "big")
        lo, hi = struct.unpack("<QQ", os.pread(self._index, 16, r * 8))
        data = os.pread(self._hashes, (hi - lo) * PWNED_RECORD, lo * PWNED_RECORD)
        def record_at(i):
            return data[i * PWNED_RECORD:(i + 1) * PWNED_RECORD]
        count = len(data) // PWNED_RECORD
        i = bisect.bisect_left(range(count), key, key=record_at)
        return i < count and record_at(i) == key

    def close(self) -> None:
        for fd in (getattr(self, "_hashes", None), getattr(self, "_index", None)):
            if fd is not None:
                os.close(fd)
        self._hashes = self._index = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


@dataclass
class Finding:
    entry: object
    issues: list  # of "breached", "reused", "weak"
    reused_with: list = field(default_factory=list)


def checked_entries(vault) -> list:
    """Entries a check looks at: not in the recycle bin, with a password."""
    return [e for e in vault.kp.entries if e.password and not vault.in_recycle_bin(e)]


def check_vault(vault, store: BreachStore | None = None) -> list:
    """Entries whose password is breached (when a store is given), reused or weak, in entry order."""
    entries = checked_entries(vault)
    by_password = {}
    for e in entries:
        by_password.setdefault(e.password, []).append(e)
    findings = []
    for e in entries:
        others = [o for o in by_password[e.password] if o is not e]
        issues = []
        if store is not None and store.contains(e.password):
            issues.append("breached")
        if others:
            issues.append("reused")
        if strength(e.password)[1] == "weak":
            issues.append("weak")
        if issues:
            findings.append(Finding(e, issues, others))
    return findings


# ---------------------------------------------------------------- CLI helpers

def prompt_new_master(keyfile=None, yubikey=None) -> str:
    while True:
        pw = getpass.getpass("New master password" + (" (may be blank with a key file or YubiKey): "
                                                      if keyfile or yubikey else ": "))
        if not keyfile and not yubikey and len(pw) < MIN_MASTER_LEN:
            print(f"Use at least {MIN_MASTER_LEN} characters (a passphrase of 4+ random words is ideal).")
            continue
        if getpass.getpass("Confirm master password: ") != pw:
            print("Passwords didn't match, try again.")
            continue
        return pw


def yubikey_arg(text: str) -> YubiKeySlot:
    try:
        return YubiKeySlot.parse(text)
    except VaultError as e:
        raise argparse.ArgumentTypeError(str(e))


def unlock(args) -> Vault:
    if not args.vault.exists():
        hint = " — run `pwvault migrate`" if LEGACY_VAULT.exists() else " — run `pwvault init` first"
        sys.exit(f"error: no vault at {args.vault}{hint}")
    return Vault.open(args.vault, getpass.getpass("Master password: "), args.keyfile, args.yubikey)


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
    password = prompt_new_master(keyfile, args.yubikey)
    if args.new_keyfile:  # only now, so aborting at the prompt leaves no stray key file
        generate_keyfile(args.new_keyfile)
        print(f"Created key file {args.new_keyfile}. Back it up: without it the vault can't be opened.")
    Vault.create(args.vault, password, keyfile, args.yubikey).save()
    print(f"Created encrypted KeePass vault at {args.vault}")
    if args.yubikey:
        print(f"It also needs YubiKey slot {args.yubikey.slot} (--yubikey {args.yubikey}). "
              f"Keep a second key with the same secret: without it the vault can't be opened.")


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


def cmd_merge(args):
    check_other_copy(args.vault, args.other)  # before asking for any password
    if args.same_credentials and (args.other_keyfile or args.other_yubikey):
        raise VaultError("use either --same-credentials or --other-keyfile/--other-yubikey, not both")
    vault = unlock(args)
    if args.same_credentials:
        password, keyfile, yubikey = vault.kp.password, vault.kp.keyfile, vault.yubikey
    else:
        password = getpass.getpass(f"Master password for {args.other}: ")
        keyfile, yubikey = args.other_keyfile, args.other_yubikey
    report = merge_vaults(vault, open_other_copy(args.vault, args.other, password, keyfile, yubikey))
    for mark, items in (("+", report.added), ("~", report.updated), (">", report.moved),
                        ("-", report.deleted)):
        for path, title in items:
            print(f"  {mark} {path}/{title}")
    if not report.changed:
        print("Already up to date.")
        return
    print(f"{len(report.added)} added, {len(report.updated)} updated, {len(report.moved)} moved, "
          f"{len(report.deleted)} deleted.")
    if args.dry_run:
        print("Dry run: nothing saved.")
        return
    vault.save()
    print(f"Merged {args.other} into {args.vault}. The version before the merge is kept as a backup "
          f"(`pwvault backup list`).")


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
    try:
        if entry_totp(e):
            print(f"TOTP:     set — `pwvault totp {args.query}`")
    except VaultError as err:
        print(f"TOTP:     unreadable ({err})")
    if args.show:
        print(f"Password: {e.password}")
    else:
        copy_and_report(e)


def cmd_totp(args):
    vault = unlock(args)
    e = pick_one(find(vault, args.query), args.query)
    if args.set:
        value = normalize_totp(getpass.getpass("TOTP secret or otpauth:// URI: "), e.title, e.username)
        vault.update_entry(e, {"otp": value})
        vault.save()
        code, left = totp_code(entry_totp(e))
        return print(f"TOTP set for '{e.title}'. Current code: {fmt_totp_code(code)} ({left}s left).")
    if args.clear:
        if not field_differs(e, "otp", ""):
            raise VaultError(f"'{e.title}' has no TOTP secret")
        if input(f"Remove the TOTP secret from '{e.title}'? [y/N] ").lower() != "y":
            return print("Cancelled.")
        vault.update_entry(e, {"otp": ""})
        vault.save()
        return print("TOTP removed.")
    totp = entry_totp(e)
    if totp is None:
        raise VaultError(f"'{e.title}' has no TOTP secret — add one with `pwvault totp {args.query} --set`")
    code, left = totp_code(totp)
    if args.show:
        print(f"{fmt_totp_code(code)}  ({left}s left)")
    elif copy_to_clipboard(code):
        print(f"Code copied to clipboard (valid {left}s more; clipboard clears in {CLIPBOARD_CLEAR_SECONDS}s).")
    else:
        print("No clipboard tool found (install wl-clipboard or xclip); use --show to print it.")


def cmd_add(args):
    vault = unlock(args)
    group = vault.get_group(args.group, create=True) if args.group else vault.root
    title = input("Title (e.g. GitHub): ").strip()
    url = input("URL: ").strip()
    if not (title or url):
        raise VaultError("an entry needs a title or a URL")
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


def cmd_check(args):
    vault = unlock(args)
    try:
        store, note = BreachStore(), None
    except VaultError as e:
        store, note = None, str(e)
    try:
        findings = check_vault(vault, store)
    finally:
        if store:
            store.close()
    for f in findings:
        _print_finding(vault, f)
    count = {i: sum(i in f.issues for f in findings) for i in ("breached", "reused", "weak")}
    checked = len(checked_entries(vault))
    print(f"\n{len(findings)} of {checked} entr{'y' if checked == 1 else 'ies'} flagged"
          + (f" ({count['breached']} breached, {count['reused']} reused, {count['weak']} weak)" if findings else ""))
    if store is None:
        print(f"Breached passwords not checked: {note}")


def _print_finding(vault, finding) -> None:
    e = finding.entry
    print(f"{e.title or '(no title)'}  ({e.username or 'no username'})  in {vault.group_path(e.group)}")
    line = "  " + ", ".join(finding.issues)
    if finding.reused_with:
        line += "; same password as: " + ", ".join(o.title or "(no title)" for o in finding.reused_with)
    print(line)


def _breach_progress():
    """A progress callback that prints ranges done and time left on a terminal, else nothing."""
    start = []

    def show(done, total):
        if not sys.stderr.isatty():
            return
        if not start:
            start.extend((time.monotonic(), done))
        rate = (done - start[1]) / max(time.monotonic() - start[0], 1e-9)
        left = f", about {(total - done) / rate / 60:.0f} min left" if rate else ""
        print(f"\r  {done:,} of {total:,} ranges{left}   ", end="" if done < total else "\n",
              file=sys.stderr, flush=True)
    return show


def _print_breach_status() -> None:
    try:
        with BreachStore() as store:
            m = store.meta
            print(f"Breach list: {m['hashes']:,} password hashes, completed {m['completed']}\n"
                  f"Stored in {breach_dir()}")
    except VaultError as e:
        print(e)
    index = breach_dir() / "partial" / "index.bin"
    if index.exists():
        done = max(index.stat().st_size // 8 - 1, 0)
        print(f"Unfinished download: {done:,} of {PWNED_RANGES:,} ranges — `pwvault breach update` resumes it")


def cmd_breach(args):
    if args.action == "status":
        _print_breach_status()
        return
    if args.action == "import":
        if not args.file:
            sys.exit("error: `pwvault breach import` needs the hash list file")
        n = import_breach_list(args.file, _breach_progress())
    else:
        if args.file:
            sys.exit("error: `pwvault breach update` takes no file (use `breach import FILE`)")
        print(f"Downloading the Pwned Passwords list from Have I Been Pwned into {breach_dir()}.\n"
              "This is about 1 million requests (~55 GB downloaded, ~16 GB stored) and takes hours;\n"
              "it can be stopped and resumed. Nothing about your passwords is sent.",
              file=sys.stderr)
        try:
            n = update_breach_list(progress=_breach_progress())
        except KeyboardInterrupt:
            sys.exit("\nStopped. Run `pwvault breach update` again to continue where it left off.")
    print(f"Breach list ready: {n:,} password hashes.")


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
    yubikey = None if args.no_yubikey else (args.new_yubikey or args.yubikey)
    password = prompt_new_master(keyfile, yubikey)
    if args.new_keyfile:  # only now, so aborting at the prompt leaves no stray key file
        generate_keyfile(args.new_keyfile)
        print(f"Created key file {args.new_keyfile}. Back it up: without it the vault can't be opened.")
    vault.rekey(password, keyfile, yubikey)
    vault.save()
    needs = [str(keyfile)] if keyfile else []
    needs += [f"YubiKey slot {yubikey.slot} (--yubikey {yubikey})"] if yubikey else []
    print("Master key changed." + (f" The vault now also needs {' and '.join(needs)}." if needs else ""))
    if vault.purged_backups:
        print(f"Removed {vault.purged_backups} backups made with the old master key.")


def cmd_backup(args):
    backups = list_backups(args.vault)
    if args.action == "list":
        if not backups:
            print("No backups yet.")
        for i, (when, path) in enumerate(backups, 1):
            print(f"{i:3}. {when.astimezone():%Y-%m-%d %H:%M:%S}  {path.stat().st_size / 1024:.1f} KB")
        return
    if args.number is None:
        raise VaultError("say which backup to restore, e.g. `pwvault backup restore 1` (see `backup list`)")
    if not 1 <= args.number <= len(backups):
        raise VaultError(f"no backup {args.number}; there are {len(backups)} (see `backup list`)")
    when, path = backups[args.number - 1]
    vault = unlock(args)
    vault.restore(path)
    print(f"Restored backup {args.number} ({when.astimezone():%Y-%m-%d %H:%M:%S}). "
          "The previous vault was backed up first.")


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
    ap.add_argument("--yubikey", type=yubikey_arg, metavar="SLOT[:SERIAL]",
                    help="YubiKey HMAC-SHA1 challenge-response slot that is part of the key (as keepassxc-cli -y)")
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

    p = sub.add_parser("merge", help="merge another copy of the vault into this one")
    p.add_argument("other", type=Path, help="the other copy, e.g. a sync conflict file")
    p.add_argument("--dry-run", action="store_true", help="show what would change, save nothing")
    p.add_argument("--same-credentials", action="store_true",
                   help="the other copy opens with this vault's password and key file")
    p.add_argument("--other-keyfile", type=Path, metavar="PATH", help="key file of the other copy")
    p.add_argument("--other-yubikey", type=yubikey_arg, metavar="SLOT[:SERIAL]",
                   help="YubiKey slot of the other copy")
    p.set_defaults(fn=cmd_merge)

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

    p = sub.add_parser("totp", help="copy the current 2FA (TOTP) code, or set/clear the secret")
    p.add_argument("query")
    p.add_argument("--show", action="store_true", help="print the code instead")
    change = p.add_mutually_exclusive_group()
    change.add_argument("--set", action="store_true", help="set the secret (asked for, hidden)")
    change.add_argument("--clear", action="store_true", help="remove the secret")
    p.set_defaults(fn=cmd_totp)

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

    p = sub.add_parser("check", help="list entries with breached, reused or weak passwords (offline)")
    p.set_defaults(fn=cmd_check)

    p = sub.add_parser("breach", help="download, import or show the offline breach list used by `check`")
    p.add_argument("action", choices=("update", "import", "status"))
    p.add_argument("file", type=Path, nargs="?", help="for import: a HASH:COUNT file sorted by hash")
    p.set_defaults(fn=cmd_breach)

    p = sub.add_parser("passwd", help="change the master password and/or key file")
    p.add_argument("--new-keyfile", type=Path, metavar="PATH", help="create and require a new key file")
    p.add_argument("--no-keyfile", action="store_true", help="stop requiring a key file")
    yk = p.add_mutually_exclusive_group()
    yk.add_argument("--new-yubikey", type=yubikey_arg, metavar="SLOT[:SERIAL]",
                    help="require this YubiKey slot from now on (default: keep the current one)")
    yk.add_argument("--no-yubikey", action="store_true", help="stop requiring a YubiKey")
    p.set_defaults(fn=cmd_passwd)

    p = sub.add_parser("backup", help=f"list or restore the last {BACKUP_KEEP} versions of the vault")
    p.add_argument("action", choices=("list", "restore"))
    p.add_argument("number", type=int, nargs="?", help="backup to restore, as numbered by `backup list`")
    p.set_defaults(fn=cmd_backup)

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
