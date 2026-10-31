"""Tests for automatic vault backups. Run: python3 -m unittest discover -s tests"""

import io
import stat
import sys
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from test_pwvault import PW, Base, pwvault
from pwvault import Vault, VaultError

NEW_PW = "a different long master password"


def in_backup_dir(path) -> bool:
    return str(path).endswith(".kdbx") and pwvault.Path(path).parent.name.endswith(".backups")


def leftovers(vault_path) -> list:
    """Temp files write_private would leave behind if a write went wrong."""
    dirs = [vault_path.parent, pwvault.backup_dir(vault_path)]
    return [p for d in dirs if d.exists() for p in d.iterdir() if p.name.startswith(".")]


class BackupOnSaveTests(Base):
    def backups(self):
        return [p for _, p in pwvault.list_backups(self.path)]

    def test_first_save_makes_no_backup(self):
        self.new_vault()
        self.assertEqual(self.backups(), [])

    def test_save_keeps_previous_file_byte_for_byte(self):
        v = self.new_vault()
        before = self.path.read_bytes()
        v.add_entry(v.root, "GitLab", "me", "pw2")
        v.save()
        [backup] = self.backups()
        self.assertEqual(backup.read_bytes(), before)
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(backup.parent.stat().st_mode), 0o700)
        self.assertEqual(backup.parent, self.tmp / "vault.kdbx.backups")
        # A backup is a complete vault that opens with the master password.
        self.assertEqual([e.title for e in pwvault.PyKeePass(str(backup), PW).entries], ["GitHub"])

    def test_symlinked_vault_keeps_backups_beside_the_real_file(self):
        real = self.tmp / "sync" / "vault.kdbx"
        real.parent.mkdir()
        self.path.symlink_to(real)
        v = self.new_vault()
        v.save()
        self.assertEqual(len(pwvault.list_backups(real)), 1)
        self.assertTrue((real.parent / "vault.kdbx.backups").is_dir())
        self.assertFalse((self.tmp / "vault.kdbx.backups").exists())

    def test_only_newest_backups_are_kept_and_strays_survive(self):
        v = self.new_vault()
        stray = pwvault.backup_dir(self.path) / "notes.txt"
        stray.parent.mkdir()
        stray.write_text("mine")
        saved = []
        for i in range(pwvault.BACKUP_KEEP + 2):
            saved.append(self.path.read_bytes())
            v.add_entry(v.root, f"Site {i}", "me", "pw")
            v.save()
        backups = self.backups()
        self.assertEqual(len(backups), pwvault.BACKUP_KEEP)
        # Newest first, and they are the most recent previous versions.
        self.assertEqual([b.read_bytes() for b in backups], saved[::-1][:pwvault.BACKUP_KEEP])
        self.assertEqual(stray.read_text(), "mine")

    def test_failed_backup_blocks_the_save(self):
        v = self.new_vault()
        before = self.path.read_bytes()
        real_write = pwvault.write_private

        def failing(path, data):
            if in_backup_dir(path):
                raise OSError(28, "No space left on device")
            real_write(path, data)

        v.add_entry(v.root, "GitLab", "me", "pw2")
        with patch.object(pwvault, "write_private", failing), self.assertRaises(OSError):
            v.save()
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(self.backups(), [])
        self.assertEqual(leftovers(self.path), [])
        v.save()  # nothing on disk changed, so a retry goes through
        self.assertEqual(len(self.backups()), 1)

    def test_rekey_purges_old_key_backups(self):
        v = self.new_vault()
        for i in range(3):
            v.add_entry(v.root, f"Site {i}", "me", "pw")
            v.save()
        self.assertEqual(len(self.backups()), 3)
        v.rekey(NEW_PW)
        v.save()
        self.assertEqual(v.purged_backups, 4)  # three earlier ones plus the pre-rekey copy
        self.assertEqual(self.backups(), [])
        self.reopen(NEW_PW)
        v.add_entry(v.root, "After", "me", "pw")
        v.save()  # later saves back up as usual and purge nothing
        self.assertEqual(v.purged_backups, 0)
        self.assertEqual(len(self.backups()), 1)
        pwvault.PyKeePass(str(self.backups()[0]), NEW_PW)

    def test_crash_after_rekey_write_is_finished_on_next_open(self):
        v = self.new_vault()
        v.add_entry(v.root, "GitLab", "me", "pw2")
        v.save()
        real_remove = pwvault.remove_backups

        def crash_on_purge(path, keep=0):
            if keep == 0:  # the re-key purge; the routine prune passes keep=10
                raise RuntimeError("simulated crash")
            return real_remove(path, keep)

        v.rekey(NEW_PW)
        with patch.object(pwvault, "remove_backups", crash_on_purge), self.assertRaises(RuntimeError):
            v.save()
        self.assertTrue(self.backups())  # old-key backups survive the crash...
        self.assertTrue(pwvault._rekey_marker(self.path).exists())
        self.reopen(NEW_PW)              # ...and the next open finishes the purge
        self.assertEqual(self.backups(), [])
        self.assertFalse(pwvault._rekey_marker(self.path).exists())

    def test_crash_before_rekey_write_keeps_backups(self):
        v = self.new_vault()
        v.add_entry(v.root, "GitLab", "me", "pw2")
        v.save()
        before = set(self.backups())

        def crash_before_write(self_, blob):
            raise RuntimeError("simulated crash")

        v.rekey(NEW_PW)
        with patch.object(pwvault.Vault, "_write", crash_before_write), self.assertRaises(RuntimeError):
            v.save()
        self.reopen(PW)                  # the vault still has the old key
        self.assertEqual(set(self.backups()), before)  # nothing purged: the new file never landed
        self.assertFalse(pwvault._rekey_marker(self.path).exists())

    def test_failed_rekey_save_keeps_backups(self):
        v = self.new_vault()
        v.add_entry(v.root, "GitLab", "me", "pw2")
        v.save()
        old = set(self.backups())
        real_write = pwvault.write_private

        def failing(path, data):
            if not in_backup_dir(path):
                raise OSError(5, "Input/output error")
            real_write(path, data)

        v.rekey(NEW_PW)
        with patch.object(pwvault, "write_private", failing), self.assertRaises(OSError):
            v.save()
        self.assertTrue(old <= set(self.backups()))
        self.assertEqual(v.purged_backups, 0)
        self.reopen(PW)  # the vault still has the old key
        with self.assertRaises(VaultError):
            self.reopen(NEW_PW)


class InterruptedSaveTests(Base):
    """A save that fails at any point leaves the vault file as it was, and the session usable."""

    def fails_cleanly(self, failure, exc=OSError):
        v = self.new_vault()
        before = self.path.read_bytes()
        v.add_entry(v.root, "GitLab", "me", "pw2")
        with failure(v), self.assertRaises(exc):
            v.save()
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual([e.title for e in self.reopen().kp.entries], ["GitHub"])
        self.assertEqual(leftovers(self.path), [])
        v.save()  # no false "changed by another program": the file on disk is what we last saw
        self.assertEqual(sorted(e.title for e in self.reopen().kp.entries), ["GitHub", "GitLab"])

    @staticmethod
    def nth_fsync_raises(n, exc):
        """Fail the nth fsync: the backup's is first, the vault's second."""
        real, calls = pwvault.os.fsync, []

        def fsync(fd):
            calls.append(fd)
            if len(calls) == n:
                raise exc
            real(fd)
        return patch.object(pwvault.os, "fsync", fsync)

    def test_serialization_fails(self):
        self.fails_cleanly(lambda v: patch.object(v.kp, "save", side_effect=RuntimeError("boom")),
                           RuntimeError)

    def test_fsync_of_new_vault_fails(self):
        self.fails_cleanly(lambda v: self.nth_fsync_raises(2, OSError(5, "Input/output error")))

    def test_rename_into_place_fails(self):
        real = pwvault.os.replace

        def replace(src, dst):
            if not in_backup_dir(dst):
                raise OSError(18, "Invalid cross-device link")
            real(src, dst)
        self.fails_cleanly(lambda v: patch.object(pwvault.os, "replace", replace))

    def test_interrupted_by_ctrl_c(self):
        self.fails_cleanly(lambda v: self.nth_fsync_raises(2, KeyboardInterrupt()), KeyboardInterrupt)


class BackupCliTests(Base):
    def run_cli(self, *argv, prompts=()):
        """Run pwvault's CLI; returns (exit code or None, stdout)."""
        out = io.StringIO()
        with patch.object(sys, "argv", ["pwvault", "--vault", str(self.path), *argv]), \
                patch("getpass.getpass", side_effect=list(prompts)), redirect_stdout(out):
            try:
                pwvault.main()
            except SystemExit as e:
                return e.code, out.getvalue()
        return None, out.getvalue()

    def three_versions(self):
        """Vault saved three times: backup 1 holds two entries, backup 2 holds one."""
        v = self.new_vault()
        v.add_entry(v.root, "GitLab", "me", "pw2")
        v.save()
        v.add_entry(v.root, "Codeberg", "me", "pw3")
        v.save()
        return v

    def titles(self):
        return sorted(e.title for e in self.reopen().kp.entries)

    def test_list_with_no_backups(self):
        self.new_vault()
        self.assertEqual(self.run_cli("backup", "list"), (None, "No backups yet.\n"))

    def test_list_numbers_newest_first(self):
        self.three_versions()
        code, out = self.run_cli("backup", "list")
        self.assertIsNone(code)
        lines = out.splitlines()
        self.assertEqual([line.split(".")[0].strip() for line in lines], ["1", "2"])
        self.assertTrue(all(line.endswith(" KB") for line in lines))

    def test_restore_brings_back_an_older_version_and_backs_up_first(self):
        self.three_versions()
        latest = self.path.read_bytes()
        code, out = self.run_cli("backup", "restore", "2", prompts=[PW])
        self.assertIsNone(code)
        self.assertIn("Restored backup 2", out)
        self.assertEqual(self.titles(), ["GitHub"])
        # The vault that was replaced is now the newest backup, so the restore can be undone.
        self.assertEqual(pwvault.list_backups(self.path)[0][1].read_bytes(), latest)
        self.run_cli("backup", "restore", "1", prompts=[PW])
        self.assertEqual(self.titles(), ["Codeberg", "GitHub", "GitLab"])

    def test_restore_with_wrong_password_changes_nothing(self):
        self.three_versions()
        before = self.path.read_bytes()
        backups = pwvault.list_backups(self.path)
        code, _ = self.run_cli("backup", "restore", "1", prompts=["wrong password entirely"])
        self.assertEqual(code, "error: wrong master password or key file")
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(pwvault.list_backups(self.path), backups)

    def test_restore_refuses_backup_with_another_key(self):
        v = self.three_versions()
        # A backup the purge missed (or one copied in) that only opens with a different key.
        other = pwvault.backup_dir(self.path) / "vault-29990101T000000.000000.kdbx"
        stranger = Vault.create(self.tmp / "other.kdbx", NEW_PW)
        stranger.save()
        other.write_bytes((self.tmp / "other.kdbx").read_bytes())
        before = self.path.read_bytes()
        code, _ = self.run_cli("backup", "restore", "1", prompts=[PW])
        self.assertIn("can't be restored: wrong master password or key file", code)
        self.assertEqual(self.path.read_bytes(), before)
        v.save()  # the open session is unaffected

    def test_restore_number_out_of_range_or_missing(self):
        self.three_versions()
        before = self.path.read_bytes()
        for argv in (("3",), ("0",), ()):
            code, _ = self.run_cli("backup", "restore", *argv)  # no password prompt either
            self.assertTrue(code.startswith("error: "), code)
        self.assertEqual(self.path.read_bytes(), before)

    def test_passwd_reports_purged_backups(self):
        self.three_versions()
        code, out = self.run_cli("passwd", prompts=[PW, NEW_PW, NEW_PW])
        self.assertIsNone(code)
        self.assertIn("Removed 3 backups made with the old master key.", out)
        self.assertEqual(pwvault.list_backups(self.path), [])


if __name__ == "__main__":
    unittest.main()
