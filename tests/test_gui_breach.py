"""Tests for the GUI's Database > Check passwords… report. Run under xvfb:
xvfb-run -a python3 -m unittest discover -s tests -v

No test touches the network: the breach list is built with `breach import`, and every report is
opened with sockets disabled.
"""

import os
import unittest
from unittest.mock import patch

from test_breach import BREACHED, PW, SHARED, WEAK, BreachBase, make_check_vault, sha1
from test_pwvault import display_available, pwvault
from pwvault import Vault

NO_NETWORK = patch("socket.socket", side_effect=OSError("network used during check"))


def widget_texts(widget):
    """Every label and button text and every tree cell under widget."""
    texts = []
    try:
        texts.append(str(widget.cget("text")))
    except Exception:
        pass
    if widget.winfo_class() == "Treeview":
        texts += [str(v) for i in widget.get_children() for v in widget.item(i, "values")]
    for child in widget.winfo_children():
        texts += widget_texts(child)
    return texts


@unittest.skipUnless(display_available(), "needs a display; run under xvfb-run")
class CheckDialogTests(BreachBase):
    def setUp(self):
        super().setUp()
        import pwvault_gui
        self.gui = pwvault_gui
        self.path = make_check_vault(self.tmp)
        self.app = pwvault_gui.App(self.path)
        self.app.vault = Vault.open(self.path, PW)
        self.app.show_main()
        self.app.root.update()

    def tearDown(self):
        self.app.root.destroy()
        super().tearDown()

    def dialog(self):
        with NO_NETWORK:
            d = self.gui.CheckDialog(self.app)
        self.app.root.update()
        return d

    def rows(self, d):
        return [tuple(d.tree.item(i, "values")) for i in d.tree.get_children()]

    def select(self, d, title):
        iid = next(i for i, f in d.findings.items() if f.entry.title == title)
        d.tree.selection_set(iid)
        return d.findings[iid].entry

    def test_lists_flagged_entries_without_showing_passwords(self):
        self.import_hashes([sha1(BREACHED), sha1(BREACHED + "-old")])
        d = self.dialog()
        self.assertEqual(self.rows(d), [  # entry order, as check_vault() returns it
            ("Mail", "me@work", "Root/Work", "reused with Forum"),
            ("Leaked site", "me", "Root", "breached"),
            ("Forum", "me", "Root", "reused with Mail"),
            ("Router", "admin", "Root", "weak"),
        ])
        texts = widget_texts(d)
        self.assertIn("4 of 5 entries flagged (1 breached, 2 reused, 1 weak).", texts)
        self.assertFalse(any("not checked" in t for t in texts))
        for secret in (BREACHED, SHARED, WEAK, PW):
            self.assertFalse(any(secret in t for t in texts), secret)
        d.destroy()

    def test_without_a_breach_list(self):
        d = self.dialog()
        self.assertEqual([r[0] for r in self.rows(d)], ["Mail", "Forum", "Router"])
        note = next(t for t in widget_texts(d) if t.startswith("Breached passwords not checked."))
        self.assertIn("pwvault breach update", note)
        self.assertIn("3 of 5 entries flagged (0 breached, 2 reused, 1 weak).", widget_texts(d))
        d.destroy()

    def test_damaged_breach_list(self):
        root = pwvault.breach_dir()
        (root / "store-empty").mkdir(parents=True)
        os.symlink("store-empty", root / "current")
        d = self.dialog()
        note = next(t for t in widget_texts(d) if t.startswith("Breached passwords not checked."))
        self.assertIn("damaged", note)
        self.assertEqual([r[0] for r in self.rows(d)], ["Mail", "Forum", "Router"])
        d.destroy()

    def assert_jumped_to(self, d, entry):
        self.app.root.update()
        self.assertFalse(d.winfo_exists())
        self.assertEqual(self.app.current_group.uuid, entry.group.uuid)
        self.assertEqual(self.app.search.get(), "")
        self.assertEqual(self.app.selected().uuid, entry.uuid)

    def test_double_click_jumps_to_the_entry(self):
        d = self.dialog()
        self.select(d, "Router")
        iid, mail = next((i, f.entry) for i, f in d.findings.items() if f.entry.title == "Mail")
        x, y, _, h = d.tree.bbox(iid)
        # Two quick presses on the "Mail" row (in the Work subgroup) make Tk's <Double-1>; the
        # first one selects it, the second one closes the report.
        d.tree.event_generate("<ButtonPress-1>", x=x + 5, y=y + h // 2)
        d.tree.event_generate("<ButtonRelease-1>", x=x + 5, y=y + h // 2)
        d.tree.event_generate("<ButtonPress-1>", x=x + 5, y=y + h // 2)
        entry = mail
        self.assert_jumped_to(d, entry)

    def press_return(self, d):
        # Tk sends key presses to the focused widget, so press Return wherever the focus is: the
        # report must take it when it opens, without a click.
        focused = self.app.root.focus_get()
        self.assertTrue(str(focused).startswith(str(d)), focused)
        focused.event_generate("<Return>")

    def test_show_entry_button_and_return(self):
        for title, press in (("Router", lambda d: d.show_btn.invoke()),
                             ("Forum", self.press_return)):
            with self.subTest(title):
                self.app.search.set("nothing matches this")
                d = self.dialog()
                entry = self.select(d, title)
                press(d)
                self.assert_jumped_to(d, entry)

    def test_clean_vault(self):
        v = self.app.vault
        for e in list(v.kp.entries):
            if e.title in ("Mail", "Forum", "Router"):
                v.delete_entry(e)
        d = self.dialog()
        # Deleted entries go to the recycle bin, which isn't checked; with no breach list,
        # "Leaked site" and "Bank" are left and neither is reused or weak.
        self.assertIn("No problems found in 2 entries.", widget_texts(d))
        self.assertEqual(str(d.show_btn.cget("state")), "disabled")
        d.show_entry()  # nothing to show: no error, dialog stays
        self.assertTrue(d.winfo_exists())
        d.destroy()

    def test_lock_closes_the_report(self):
        d = self.dialog()
        self.app.lock()
        self.app.root.update()
        self.assertFalse(d.winfo_exists())

    def test_open_check(self):
        with NO_NETWORK:
            self.app.open_check()
        self.app.root.update()
        dialogs = [w for w in self.app.root.winfo_children() if isinstance(w, self.gui.CheckDialog)]
        self.assertEqual(len(dialogs), 1)
        dialogs[0].destroy()
        self.app.vault = None
        self.app.open_check()  # no vault open: nothing happens
        self.app.root.update()
        self.assertFalse([w for w in self.app.root.winfo_children() if isinstance(w, self.gui.CheckDialog)])


if __name__ == "__main__":
    unittest.main()
