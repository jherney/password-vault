"""Tests for the GUI's Database > Merge another copy… dialog. Run under xvfb:
xvfb-run -a python3 -m unittest discover -s tests -v
"""

import shutil
import unittest

from test_merge import OTHER_PW, PW, MergeBase, get, snapshot
from test_pwvault import display_available, pwvault
from pwvault import Vault


@unittest.skipUnless(display_available(), "needs a display; run under xvfb-run")
class MergeDialogTests(MergeBase):
    def setUp(self):
        super().setUp()
        import pwvault_gui
        self.gui = pwvault_gui
        b = self.b()
        self.edit(b, "Y", 5, password="Y-b")
        b.delete_entry(get(b, self.ids["T"]))  # trashed in B
        b.add_entry(b.root, "From B", "bee", "b-pw")
        b.save()
        self.b_bytes = self.path_b.read_bytes()
        self.app = pwvault_gui.App(self.path)
        self.app.vault = self.a()
        self.app.show_main()
        self.app.root.update()

    def tearDown(self):
        self.app.root.destroy()
        super().tearDown()

    def dialog(self, other=None):
        d = self.gui.MergeDialog(self.app)
        d.other.set(str(other or self.path_b))
        return d

    def rows(self, d):
        return [tuple(d.tree.item(i, "values")) for i in d.tree.get_children()]

    def titles(self):
        return {e.title for e in self.app.vault.kp.entries}

    def test_merge_then_save(self):
        before = len(pwvault.list_backups(self.path))
        vault_bytes = self.path.read_bytes()
        d = self.dialog()
        d.merge()
        self.assertIn(("Updated", "Root", "Y"), self.rows(d))
        self.assertIn(("Added", "Root", "From B"), self.rows(d))
        self.assertIn(("Moved", "Root/Recycle Bin", "T"), self.rows(d))
        self.assertIn(("Added", "Root", "Recycle Bin/"), self.rows(d))  # A had no recycle bin yet
        self.assertEqual(self.path.read_bytes(), vault_bytes)  # nothing saved before Save
        d.save()
        self.app.root.update()
        self.assertFalse(d.winfo_exists())
        self.assertEqual(len(pwvault.list_backups(self.path)), before + 1)
        on_disk = Vault.open(self.path, PW)
        self.assertEqual(get(on_disk, self.ids["Y"]).password, "Y-b")
        self.assertTrue(on_disk.in_recycle_bin(get(on_disk, self.ids["T"])))
        self.assertIn("From B", self.titles())
        self.assertIn("Merged copy.kdbx: 2 added, 1 updated, 1 moved, 0 deleted.",
                      self.app.status_lbl.cget("text"))
        self.assertEqual(self.path_b.read_bytes(), self.b_bytes)  # the other copy is never written

    def check_discarded(self, leave):
        vault_bytes = self.path.read_bytes()
        before = snapshot(self.app.vault.kp)
        d = self.dialog()
        d.merge()
        self.assertIn("From B", self.titles())  # merged in memory
        leave(d)
        self.app.root.update()
        self.assertFalse(d.winfo_exists())
        self.assertEqual(self.path.read_bytes(), vault_bytes)
        self.assertEqual(snapshot(self.app.vault.kp), before)
        self.assertNotIn("From B", self.titles())

    def test_discard_reloads_from_disk(self):
        self.check_discarded(lambda d: d.close())

    def test_escape_discards(self):
        def escape(d):
            d.focus_force()
            d.event_generate("<Escape>")
        self.check_discarded(escape)

    def test_window_close_discards(self):
        self.check_discarded(lambda d: d.tk.call(d.protocol("WM_DELETE_WINDOW")))

    def test_other_copy_with_its_own_password_and_key_file(self):
        keyfile = self.tmp / "other.keyx"
        pwvault.generate_keyfile(keyfile)
        b = self.b()
        b.rekey(OTHER_PW, keyfile)
        b.save()
        d = self.dialog()
        d.same.set(False)
        d.toggle_credentials()
        d.password.set(OTHER_PW)
        d.keyfile.var.set(str(keyfile))
        d.merge()
        self.assertIn(("Added", "Root", "From B"), self.rows(d))
        d.close()

    def test_errors_are_shown_inline_and_change_nothing(self):
        link = self.tmp / "link.kdbx"
        link.symlink_to(self.path)
        junk = self.tmp / "junk.kdbx"
        junk.write_bytes(b"not a keepass file")
        before = snapshot(self.app.vault.kp)
        cases = [(self.path, True, "", "this vault itself"), (link, True, "", "this vault itself"),
                 (self.tmp / "nope.kdbx", True, "", "No file at"), (junk, True, "", "junk.kdbx"),
                 (self.path_b, False, "wrong password", "copy.kdbx: wrong master password")]
        for other, same, password, message in cases:
            d = self.dialog(other)
            d.same.set(same)
            d.toggle_credentials()
            d.password.set(password)
            d.merge()
            self.assertIn(message, d.error.cget("text"), other)
            self.assertFalse(d.merged)
            d.destroy()
        self.assertEqual(snapshot(self.app.vault.kp), before)

    def test_already_up_to_date(self):
        same = self.tmp / "same.kdbx"
        shutil.copyfile(self.path, same)
        d = self.dialog(same)
        d.merge()
        texts = [w.cget("text") for w in d.body.winfo_children() if w.winfo_class() == "TLabel"]
        self.assertIn("Already up to date.", texts)
        self.assertFalse(d.merged)

    def test_lock_drops_an_unsaved_merge(self):
        vault_bytes = self.path.read_bytes()
        d = self.dialog()
        d.merge()
        self.app.lock()
        self.app.root.update()
        self.assertFalse(d.winfo_exists())
        self.assertIsNone(self.app.vault)
        self.assertEqual(self.path.read_bytes(), vault_bytes)
        self.assertNotIn("From B", {e.title for e in Vault.open(self.path, PW).kp.entries})

    def test_menu_item_opens_the_dialog(self):
        self.app.open_merge()
        self.app.root.update()
        dialogs = [w for w in self.app.root.winfo_children() if isinstance(w, self.gui.MergeDialog)]
        self.assertEqual(len(dialogs), 1)
        dialogs[0].close()


if __name__ == "__main__":
    unittest.main()
