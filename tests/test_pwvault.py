"""Regression tests for pwvault. Run: python3 -m unittest discover -s tests"""

import importlib.util
import json
import secrets
import struct
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from pykeepass import PyKeePass

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import pwvault  # noqa: E402
from pwvault import Vault, VaultError  # noqa: E402

PW = "correct horse battery staple"


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.dir.name)
        self.path = self.tmp / "vault.kdbx"

    def tearDown(self):
        self.dir.cleanup()

    def new_vault(self, keyfile=None, password=PW):
        v = Vault.create(self.path, password, keyfile)
        v.add_entry(v.root, "GitHub", "me", "s3cret", "https://github.com")
        v.save()
        return v

    def reopen(self, password=PW, keyfile=None):
        return Vault.open(self.path, password, keyfile)

    def write_csv(self, text):
        p = self.tmp / "export.csv"
        p.write_text(text)
        return p


class StorageTests(Base):
    def test_round_trip_and_repeated_saves(self):
        v = self.new_vault()
        v.add_entry(v.root, "Two", "me", "x", "https://two")
        v.save()  # a second save from the same session must not be seen as a conflict
        self.assertEqual(sorted(e.title for e in self.reopen().kp.entries), ["GitHub", "Two"])
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_file_is_plain_kdbx(self):
        self.new_vault()
        kp = PyKeePass(str(self.path), PW)
        self.assertEqual(kp.version, (4, 0))
        self.assertEqual(kp.kdf_algorithm, "argon2")
        self.assertEqual(kp.entries[0].password, "s3cret")

    def test_wrong_password(self):
        self.new_vault()
        with self.assertRaisesRegex(VaultError, "wrong master password"):
            self.reopen("nope nope nope")

    def test_weak_master_password_needs_keyfile(self):
        with self.assertRaises(VaultError):
            Vault.create(self.path, "short")

    def test_keyfile_alone_and_with_password(self):
        kf = self.tmp / "key"
        pwvault.generate_keyfile(kf)
        self.assertEqual(len(kf.read_bytes()), pwvault.KEYFILE_LEN)
        self.new_vault(keyfile=kf, password="")
        self.assertEqual(len(self.reopen("", kf).kp.entries), 1)
        with self.assertRaises(VaultError):
            self.reopen("")  # key file missing
        with self.assertRaises(VaultError):
            pwvault.generate_keyfile(kf)  # never overwrite a key file

    def test_rekey_adds_keyfile(self):
        v = self.new_vault()
        kf = self.tmp / "key"
        pwvault.generate_keyfile(kf)
        v.rekey("a brand new passphrase", kf)
        v.save()
        v.add_entry(v.root, "After", "u", "p")
        v.save()  # save after rekey uses the newly derived key
        self.assertEqual(len(self.reopen("a brand new passphrase", kf).kp.entries), 2)
        with self.assertRaises(VaultError):
            self.reopen("a brand new passphrase")

    def test_concurrent_session_change_is_not_overwritten(self):
        self.new_vault()
        gui, cli = self.reopen(), self.reopen()
        cli.add_entry(cli.root, "From CLI", "me", "x")
        cli.save()
        gui.add_entry(gui.root, "From GUI", "me", "y")
        with self.assertRaisesRegex(VaultError, "changed by another"):
            gui.save()
        self.assertIn("From CLI", [e.title for e in self.reopen().kp.entries])

    def test_create_refuses_to_clobber_existing_file(self):
        self.new_vault()
        with self.assertRaises(VaultError):
            Vault.create(self.path, PW).save()

    def test_truncated_and_foreign_files(self):
        blob = self.new_vault().disk_blob
        for data in (blob[:5], blob[:100], blob[:-50], b"not a vault at all" * 10):
            self.path.write_bytes(data)
            with self.assertRaises(VaultError):
                self.reopen()

    def test_hostile_kdf_params_rejected_before_key_derivation(self):
        blob = self.new_vault().disk_blob
        # Patch the header's Argon2 values in place; if the check didn't run first, unlocking
        # would try to allocate 4 GiB or loop for billions of passes.
        for key, value in ((b"M", 4 << 30), (b"I", 2**40)):
            tlv = lambda v: b"\x05" + struct.pack("<I", 1) + key + struct.pack("<I", 8) + struct.pack("<Q", v)
            current = {b"M": 64 << 20, b"I": 14}[key]
            self.assertEqual(blob.count(tlv(current)), 1)
            self.path.write_bytes(blob.replace(tlv(current), tlv(value)))
            with self.assertRaisesRegex(VaultError, "unreasonable"):
                self.reopen()

    def test_hostile_kdf_work_and_parallelism_rejected(self):
        # Each value is under the old per-field caps but still means minutes to hours of work
        # (64 MiB x 600 passes) or one thread per lane (100k lanes).
        blob = self.new_vault().disk_blob
        cases = ((b"I", b"\x05", "<Q", 14, 600), (b"P", b"\x04", "<I", 2, 100_000))
        for key, vtype, fmt, current, value in cases:
            size = struct.calcsize(fmt)
            tlv = lambda v: vtype + struct.pack("<I", 1) + key + struct.pack("<I", size) + struct.pack(fmt, v)
            self.assertEqual(blob.count(tlv(current)), 1)
            self.path.write_bytes(blob.replace(tlv(current), tlv(value)))
            with self.subTest(key=key), self.assertRaisesRegex(VaultError, "unreasonable"):
                self.reopen()

    def test_hostile_aes_kdf_rounds_rejected(self):
        # KDBX 3 header: signatures, version 3.1, TransformRounds (field 6), end of header.
        def header(rounds):
            return (pwvault.KDBX_SIGNATURE + struct.pack("<HH", 1, 3)
                    + b"\x06" + struct.pack("<H", 8) + struct.pack("<Q", rounds) + b"\x00\x00\x00")
        pwvault.check_kdf_params(header(6_000_000))
        with self.assertRaisesRegex(VaultError, "unreasonable"):
            pwvault.check_kdf_params(header(10**9))

    def test_old_lxml_is_refused(self):
        # lxml < 5 expands external entities, which a crafted vault could use to read local files.
        self.new_vault()
        with patch.object(pwvault.etree, "LXML_VERSION", (4, 9, 3, 0)):
            with self.assertRaisesRegex(VaultError, "lxml"):
                self.reopen()

    def test_symlinked_vault_stays_a_symlink(self):
        # Regression: saving through a symlink (e.g. into a synced folder) replaced the link with a file.
        real = self.tmp / "sync" / "vault.kdbx"
        Vault.create(real, PW).save()
        link = self.tmp / "link.kdbx"
        link.symlink_to(real)
        v = Vault.open(link, PW)
        v.add_entry(v.root, "Via link", "u", "p")
        v.save()
        self.assertTrue(link.is_symlink())
        self.assertEqual([e.title for e in Vault.open(real, PW).kp.entries], ["Via link"])


class EntryTests(Base):
    def test_groups(self):
        v = self.new_vault()
        g = v.get_group("Work/Email", create=True)
        v.add_entry(g, "Mail", "me", "pw")
        v.save()
        v = self.reopen()
        self.assertEqual([v.group_path(x) for x in v.groups()], ["Root", "Root/Work", "Root/Work/Email"])
        self.assertEqual([e.title for e in v.entries(v.get_group("Work/Email"))], ["Mail"])
        v.rename_group(v.get_group("Work"), "Job")
        self.assertEqual(v.group_path(v.get_group("Job/Email")), "Root/Job/Email")
        with self.assertRaises(VaultError):
            v.delete_group(v.root)

    def test_history_and_restore(self):
        v = self.new_vault()
        e = v.entries(query="github")[0]
        for i in range(pwvault.HISTORY_MAX + 3):
            v.update_entry(e, {"password": f"pw{i}"})
        self.assertEqual(len(e.history), pwvault.HISTORY_MAX)
        v.restore_history(e, e.history[-1])  # newest version: pw{N-2}
        self.assertEqual(e.password, f"pw{pwvault.HISTORY_MAX + 1}")
        v.save()
        self.assertEqual(len(self.reopen().entries(query="github")[0].history), pwvault.HISTORY_MAX)

    def test_unchanged_edit_adds_no_history(self):
        # Regression: saving an edit with nothing changed used to archive a duplicate version.
        v = self.new_vault()
        e = v.entries(query="github")[0]
        modified = e.mtime
        v.update_entry(e, {"title": e.title, "username": e.username, "password": e.password,
                           "url": e.url, "notes": ""}, expiry=None)
        self.assertEqual(len(e.history), 0)
        self.assertEqual(e.mtime, modified)
        v.update_entry(e, {"password": "changed"})  # a real change still archives
        self.assertEqual(len(e.history), 1)

    def test_update_keeps_expiry_unless_changed(self):
        v = self.new_vault()
        e = v.entries(query="github")[0]
        when = datetime.now(timezone.utc) - timedelta(days=1)
        v.update_entry(e, {}, expiry=when)
        self.assertTrue(e.expired)
        v.update_entry(e, {"password": "new"})
        self.assertTrue(e.expires)
        v.update_entry(e, {}, expiry=None)
        self.assertFalse(e.expires)
        self.assertEqual(pwvault.expiry_from_date("2027-01-31").date().isoformat(), "2027-01-31")
        with self.assertRaises(VaultError):
            pwvault.expiry_from_date("31/01/2027")

    def test_recycle_bin(self):
        v = self.new_vault()
        e = v.entries(query="github")[0]
        v.delete_entry(e)
        self.assertTrue(v.in_recycle_bin(e))
        self.assertEqual(v.entries(query="github"), [])  # search skips the bin
        v.restore_entry(e)
        self.assertFalse(v.in_recycle_bin(e))
        v.delete_entry(e)
        v.delete_entry(e)  # second delete, from inside the bin, is permanent
        self.assertEqual(v.kp.entries, [])
        v.add_entry(v.root, "Other", "u", "p")
        v.delete_entry(v.kp.find_entries(title="Other", first=True))
        self.assertEqual(v.empty_recycle_bin(), 1)
        v.save()
        self.assertEqual(self.reopen().kp.entries, [])

    def test_attachment_data_is_pruned(self):
        v = self.new_vault()
        e = v.entries(query="github")[0]
        v.add_attachment(e, "id.txt", b"top secret attachment")
        v.save()
        v = self.reopen()
        e = v.entries(query="github")[0]
        self.assertEqual(e.attachments[0].data, b"top secret attachment")
        v.update_entry(e, {}, remove_attachments=e.attachments)
        v.save()
        self.assertEqual(len(v.kp.binaries), 1)  # still used by the history version
        e.delete_history(all=True)
        v.save()
        self.assertEqual(len(self.reopen().kp.binaries), 0)


class ImportExportTests(Base):
    def test_csv_formats(self):
        cases = {
            "chrome": "name,url,username,password,note\nGitHub,https://github.com,me,new,\n",
            "firefox": "url,username,password,httpRealm,formActionOrigin,guid\nhttps://ff.com,a,b,,,{x}\n",
            "keepassxc": '"Group","Title","Username","Password","URL","Notes"\n"Root/Work","VPN","u","p","https://vpn",""\n',
            "bitwarden": "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n"
                         "Banks,,login,Bank,,,0,https://bank,me,pw,\n",
            "lastpass": "url,username,password,totp,extra,name,grouping,fav\nhttps://lp,u,p,,note,LP,Social,0\n",
        }
        v = self.new_vault()
        for name, text in cases.items():
            pwvault.merge_records(v, pwvault.read_csv_export(self.write_csv(text)))
        titles = {e.title: v.group_path(e.group) for e in v.kp.entries}
        self.assertEqual(titles, {"GitHub": "Root", "ff.com": "Root", "VPN": "Root/Work",
                                  "Bank": "Root/Banks", "LP": "Root/Social"})
        gh = v.entries(query="github")[0]
        self.assertEqual((gh.password, len(gh.history)), ("new", 1))  # chrome row updated it
        with self.assertRaises(VaultError):
            pwvault.read_csv_export(self.write_csv("a,b\n1,2\n"))

    def test_export_formats(self):
        v = self.new_vault()
        v.add_entry(v.get_group("Work", create=True), "<b>Tag</b>", "u", "p&q", "https://x", "line1\nline2")
        v.delete_entry(v.add_entry(v.root, "Binned", "u", "p"))
        for fmt in pwvault.EXPORT_FORMATS:
            out = self.tmp / f"out.{fmt}"
            self.assertEqual(pwvault.export(v, out, fmt), 2)
            self.assertEqual(out.stat().st_mode & 0o777, 0o600)
        self.assertIn("&lt;b&gt;Tag&lt;/b&gt;", (self.tmp / "out.html").read_text())
        self.assertNotIn("Binned", (self.tmp / "out.csv").read_text())
        records = pwvault.read_csv_export(self.tmp / "out.csv")  # our CSV re-imports
        self.assertEqual({(r["title"], r["group"]) for r in records}, {("GitHub", "Root"), ("<b>Tag</b>", "Root/Work")})

    def test_unreadable_csv_is_a_clean_error(self):
        p = self.tmp / "latin1.csv"
        p.write_bytes("name,url,username,password\nCaf\xe9,,u,p\n".encode("latin-1"))
        with self.assertRaisesRegex(VaultError, "UTF-8"):
            pwvault.read_csv_export(p)

    def test_shred_overwrites_and_deletes(self):
        p = self.write_csv("name,password\nx,y\n")
        pwvault.shred(p)
        self.assertFalse(p.exists())

    def test_shred_refuses_symlinks(self):
        # Overwriting through a link would destroy the file it points at.
        target = self.tmp / "important.txt"
        target.write_text("keep me")
        link = self.tmp / "export.csv"
        link.symlink_to(target)
        with self.assertRaises(VaultError):
            pwvault.shred(link)
        self.assertEqual(target.read_text(), "keep me")

    def test_logins_without_url_are_not_merged_by_username(self):
        # Regression: two logins with the same username and no URL used to collapse into one entry,
        # overwriting the first password.
        v = Vault.create(self.path, PW)  # in memory only; no save needed
        csv_path = self.write_csv("name,url,username,password\n"
                                  "Bank A,,admin,pw1\nBank B,,admin,pw2\n")
        self.assertEqual(pwvault.merge_records(v, pwvault.read_csv_export(csv_path)), (2, 0))
        self.assertEqual(sorted((e.title, e.password) for e in v.kp.entries),
                         [("Bank A", "pw1"), ("Bank B", "pw2")])

    def test_reimport_without_url_is_unchanged(self):
        v = Vault.create(self.path, PW)
        csv_path = self.write_csv("name,url,username,password\nBank A,,admin,pw1\nBank B,,admin,pw2\n")
        pwvault.merge_records(v, pwvault.read_csv_export(csv_path))
        self.assertEqual(pwvault.merge_records(v, pwvault.read_csv_export(csv_path)), (0, 0))
        self.assertEqual(len(v.kp.entries), 2)


class CliTests(Base):
    def run_cli(self, *argv):
        with patch.object(sys, "argv", ["pwvault", "--vault", str(self.path), *argv]), \
                patch("getpass.getpass", return_value=PW), self.assertRaises(SystemExit) as cm:
            pwvault.main()
        return cm.exception.code

    def test_os_errors_are_reported_without_a_traceback(self):
        self.new_vault()
        (self.tmp / "file").write_text("")
        self.assertRegex(self.run_cli("import", str(self.tmp / "missing.csv")), r"^error: .*missing\.csv")
        self.assertRegex(self.run_cli("export", "csv", str(self.tmp / "file" / "out.csv")), r"^error: ")

    def test_umask_is_private(self):
        import os
        old = os.umask(0o022)
        try:
            self.run_cli("--version")
            self.assertEqual(os.umask(old), 0o077)
        finally:
            os.umask(old)


class PickOneTests(unittest.TestCase):
    # Regression: entering "0" used to pick the last match, because matches[0 - 1] is matches[-1].
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        v = Vault.create(Path(self.dir.name) / "v.kdbx", PW)
        self.matches = [v.add_entry(v.root, "GitHub", "alice", "a"),
                        v.add_entry(v.root, "GitLab", "bob", "b")]

    def tearDown(self):
        self.dir.cleanup()

    def pick(self, answer):
        with patch("builtins.input", return_value=answer):
            return pwvault.pick_one(self.matches, "git")

    def test_valid_numbers_pick_that_entry(self):
        self.assertEqual(self.pick("1").title, "GitHub")
        self.assertEqual(self.pick("2").title, "GitLab")

    def test_out_of_range_and_non_numeric_choices_are_rejected(self):
        for answer in ("0", "-1", "-2", "3", "x", ""):
            with self.subTest(answer=answer), self.assertRaises(SystemExit):
                self.pick(answer)


@unittest.skipUnless(importlib.util.find_spec("tkinter"), "needs tkinter (python3-tk)")
class GuiGuardTests(unittest.TestCase):
    def test_add_entry_on_unlock_screen_does_nothing(self):
        # Regression: Ctrl+N on the unlock screen (vault locked) raised AttributeError.
        # Imports tkinter but never opens a window.
        import pwvault_gui
        app = SimpleNamespace(vault=None, current_group=object())
        self.assertIsNone(pwvault_gui.App.add_entry(app))

    def test_attachment_names_from_the_vault_are_plain_file_names(self):
        import pwvault_gui
        for stored, offered in (("id.txt", "id.txt"), ("../../.bashrc", "bashrc"), ("/etc/passwd", "passwd"),
                                ("..\\..\\x.exe", "x.exe"), ("..", "attachment"), (None, "attachment")):
            with self.subTest(stored=stored):
                self.assertEqual(pwvault_gui.safe_filename(stored), offered)


def display_available() -> bool:
    try:
        import tkinter
        tkinter.Tk().destroy()
        return True
    except Exception:
        return False


@unittest.skipUnless(display_available(), "needs a display; run under xvfb-run")
class AutoLockTests(Base):
    # Regression: the idle timer locked the vault and destroyed an open edit dialog, losing its typed text.
    def setUp(self):
        super().setUp()
        import pwvault_gui
        self.new_vault()
        self.app = pwvault_gui.App(self.path)
        self.app.vault = self.reopen()
        self.app.show_main()
        self.app.root.update()

    def tearDown(self):
        self.app.root.destroy()
        super().tearDown()

    def test_idle_timer_waits_while_an_edit_dialog_is_open(self):
        import pwvault_gui
        dialog = pwvault_gui.EntryDialog(self.app)
        dialog.vars["title"].set("half-typed")
        self.app.root.update()
        self.app.auto_lock()
        self.app.root.update()
        self.assertIsNotNone(self.app.vault)
        self.assertTrue(dialog.winfo_exists())
        self.assertEqual(dialog.vars["title"].get(), "half-typed")
        self.assertIsNotNone(self.app.lock_job)  # timer re-armed, not dropped

    def test_idle_timer_locks_once_the_dialog_is_closed(self):
        import pwvault_gui
        dialog = pwvault_gui.EntryDialog(self.app)
        self.app.root.update()
        self.app.auto_lock()
        dialog.destroy()
        self.app.root.update()
        self.app.auto_lock()
        self.assertIsNone(self.app.vault)

    def test_open_dialog_cannot_hold_the_vault_past_the_cap(self):
        import pwvault_gui
        dialog = pwvault_gui.EntryDialog(self.app)
        self.app.root.update()
        clock = [1000.0]
        with patch("pwvault_gui.monotonic", side_effect=lambda: clock[0]):
            self.app.auto_lock()  # first idle check: the hold starts
            clock[0] += pwvault_gui.DIALOG_HOLD_SECONDS - 1
            self.app.auto_lock()
            self.assertIsNotNone(self.app.vault)
            clock[0] += 1
            self.app.auto_lock()  # cap reached
        self.assertIsNone(self.app.vault)
        self.assertFalse(dialog.winfo_exists())

    def test_activity_restarts_the_dialog_hold(self):
        import pwvault_gui
        dialog = pwvault_gui.EntryDialog(self.app)
        self.app.root.update()
        clock = [1000.0]
        with patch("pwvault_gui.monotonic", side_effect=lambda: clock[0]):
            self.app.auto_lock()
            clock[0] += pwvault_gui.DIALOG_HOLD_SECONDS - 1
            self.app.touch()  # any key or click counts as activity
            self.assertIsNone(self.app.hold_since)
            clock[0] += pwvault_gui.DIALOG_HOLD_SECONDS - 1
            self.app.auto_lock()
        self.assertIsNotNone(self.app.vault)
        self.assertTrue(dialog.winfo_exists())


class MigrationTests(Base):
    def write_legacy(self, path, password, entries):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
        header = b"PWV1" + (2**14).to_bytes(4, "big") + bytes([8, 1]) + salt
        key = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(password.encode())
        path.write_bytes(header + nonce + AESGCM(key).encrypt(nonce, json.dumps(entries).encode(), header))

    def test_malformed_legacy_entry_is_a_clean_error(self):
        # Regression: a legacy entry missing a field used to raise KeyError and could leave a partial file.
        old = self.tmp / "bad.pwv"
        self.write_legacy(old, PW, [{"name": "No password or URL", "username": "u"}])
        with self.assertRaises(VaultError):
            pwvault.migrate_legacy(old, self.path, PW)
        self.assertFalse(self.path.exists())

    def test_migrate_legacy_vault(self):
        old = self.tmp / "vault.pwv"
        self.write_legacy(old, PW, [{"id": "1", "name": "Old", "url": "https://old", "username": "u",
                                     "password": "p", "note": "n", "updated": 1700000000}])
        with self.assertRaises(VaultError):
            pwvault.migrate_legacy(old, self.path, "wrong password!!")
        self.assertFalse(self.path.exists())
        pwvault.migrate_legacy(old, self.path, PW)
        e = self.reopen().kp.entries[0]
        self.assertEqual((e.title, e.url, e.username, e.password, e.notes), ("Old", "https://old", "u", "p", "n"))
        self.assertEqual(e.mtime.year, 2023)
        self.assertTrue(old.exists())
        with self.assertRaises(VaultError):
            pwvault.migrate_legacy(old, self.path, PW)  # never overwrites


class GeneratorTests(unittest.TestCase):
    def test_too_short_raises_instead_of_hanging(self):
        for n in (-1, 0, 3, 7):
            with self.assertRaises(VaultError):
                pwvault.generate_password(n)

    def test_options(self):
        pw = pwvault.generate_password(64, symbols=False, exclude_lookalikes=True)
        self.assertTrue(pw.isalnum())
        self.assertFalse(set(pw) & pwvault.LOOKALIKES)
        self.assertTrue(pwvault.generate_password(8, upper=False, lower=False, symbols=False).isdigit())
        with self.assertRaises(VaultError):
            pwvault.generate_password(16, upper=False, lower=False, digits=False, symbols=False)

    def test_strength(self):
        self.assertEqual(pwvault.strength("abc")[1], "weak")
        self.assertIn(pwvault.strength(pwvault.generate_password(24))[1], ("strong", "very strong"))


if __name__ == "__main__":
    unittest.main()
