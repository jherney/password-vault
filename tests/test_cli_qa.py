"""Regression tests from the 04-03 CLI QA pass. Run: python3 -m unittest discover -s tests"""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import pwvault  # noqa: E402
from pwvault import Vault  # noqa: E402

PW = "correct horse battery staple"


class CliQaTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.dir.name)
        self.path = self.tmp / "vault.kdbx"
        Vault.create(self.path, PW).save()

    def tearDown(self):
        self.dir.cleanup()

    def run_cli(self, *argv, prompts=(), inputs=()):
        """Run the CLI with scripted master password, getpass prompts and input() answers."""
        pw_iter = iter((PW, *prompts))
        in_iter = iter(inputs)
        with patch.object(sys, "argv", ["pwvault", "--vault", str(self.path), *argv]), \
                patch("getpass.getpass", side_effect=lambda *a, **k: next(pw_iter)), \
                patch("builtins.input", side_effect=lambda *a, **k: next(in_iter)), \
                patch.object(pwvault, "copy_to_clipboard", return_value=False), \
                patch("sys.stdout"), patch("sys.stderr"), \
                self.assertRaises(SystemExit) as cm:
            pwvault.main()
        return cm.exception.code

    def entries(self):
        return Vault.open(self.path, PW).kp.entries

    # Regression: `export` overwrote an existing file without asking, destroying the user's own
    # data (QA 04-03, CLI-01). It now refuses, the same way `keyfile` and `init` refuse.
    def test_export_never_overwrites_an_existing_file(self):
        target = self.tmp / "notes.csv"
        target.write_text("precious data")
        code = self.run_cli("export", "csv", str(target))
        self.assertRegex(str(code), r"already exists")
        self.assertEqual(target.read_text(), "precious data")

    # Regression: `add` with a blank title and URL saved an entry with no title, which then showed
    # as blank in `list` and as 'None' in messages (QA 04-03, CLI-02). It now asks for a title.
    def test_add_refuses_an_entry_with_no_title_or_url(self):
        code = self.run_cli("add", prompts=("pw-for-blank",), inputs=["", "", "alice"])
        self.assertRegex(str(code), r"title")
        self.assertEqual(self.entries(), [])

    # Regression: restoring from the recycle bin always put the entry in Root, so a Work/Dev entry
    # came back as a loose root entry (QA 04-03, CLI-03). The original group is now recorded when the
    # entry is trashed, using the PreviousParentGroup element KeePassXC uses too.
    def test_trash_restore_returns_entry_to_its_original_group(self):
        v = Vault.open(self.path, PW)
        group = v.get_group("Work/Dev", create=True)
        e = v.add_entry(group, "Bob", "bob", "pw")
        v.save()
        v.delete_entry(e)
        v.save()
        v = Vault.open(self.path, PW)
        e = next(x for x in v.kp.entries if x.title == "Bob")
        v.restore_entry(e)
        v.save()
        e = next(x for x in Vault.open(self.path, PW).kp.entries if x.title == "Bob")
        self.assertEqual(Vault.open(self.path, PW).group_path(e.group), "Root/Work/Dev")

    # The original group may have been deleted while the entry sat in the bin; restore then uses Root.
    def test_trash_restore_falls_back_to_root_when_group_is_gone(self):
        v = Vault.open(self.path, PW)
        group = v.get_group("Work/Dev", create=True)
        e = v.add_entry(group, "Bob", "bob", "pw")
        v.delete_entry(e)
        v.kp.delete_group(group)
        v.save()
        v = Vault.open(self.path, PW)
        e = next(x for x in v.kp.entries if x.title == "Bob")
        v.restore_entry(e)
        self.assertEqual(e.group.uuid, v.root.uuid)


if __name__ == "__main__":
    unittest.main()
