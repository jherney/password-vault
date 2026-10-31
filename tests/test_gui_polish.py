"""Tests for the GUI polish: the Backups dialog, theme choice and contrast. Run under xvfb:
xvfb-run -a python3 -m unittest discover -s tests -v
"""

import os
import subprocess
import tempfile
import tkinter as tk
import unittest
from pathlib import Path
from unittest.mock import patch

from test_pwvault import Base, display_available, pwvault
from pwvault import VaultError


@unittest.skipUnless(display_available(), "needs a display; run under xvfb-run")
class BackupsDialogTests(Base):
    def setUp(self):
        super().setUp()
        import pwvault_gui
        self.pwvault_gui = pwvault_gui
        v = self.new_vault()                         # first save: no backup
        v.add_entry(v.root, "GitLab", "me", "pw2")
        v.save()                                     # backup 1: GitHub only
        v.add_entry(v.root, "Two", "me", "pw3")
        v.save()                                     # backup 2: GitHub + GitLab
        self.app = pwvault_gui.App(self.path)
        self.app.vault = self.reopen()
        self.app.show_main()
        self.app.root.update()
        self.palette_before = pwvault_gui.PALETTE_NAME

    def tearDown(self):
        # Theme tests switch the module's palette; put back the one the other tests expect.
        self.pwvault_gui.switch_palette(self.app.root, self.palette_before)
        self.app.root.destroy()
        super().tearDown()

    def dialog(self):
        return self.pwvault_gui.BackupsDialog(self.app)

    def test_switching_theme_recolours_open_widgets_and_dialogs(self):
        gui = self.pwvault_gui
        other = "light" if gui.PALETTE_NAME == "dark" else "dark"
        target = gui.LIGHT if other == "light" else gui.DARK
        probe = tk.Label(self.app.root, bg=gui.BG, fg=gui.FG)
        dlg = self.dialog()
        with tempfile.TemporaryDirectory() as cfg, patch.dict(os.environ, {"XDG_CONFIG_HOME": cfg}):
            self.app.set_theme(other)
        self.assertEqual(gui.PALETTE_NAME, other)
        self.assertEqual(str(self.app.root.cget("background")).lower(), target["BG"])
        self.assertEqual(str(probe.cget("background")).lower(), target["BG"])
        self.assertEqual(str(probe.cget("foreground")).lower(), target["FG"])
        self.assertEqual(str(dlg.cget("background")).lower(), target["BG"])
        probe.destroy()
        dlg.destroy()

    def test_lists_backups_newest_first(self):
        dlg = self.dialog()
        self.assertEqual(len(dlg.backups), 2)
        self.assertGreater(dlg.backups[0][0], dlg.backups[1][0])  # newest first
        self.assertEqual(len(dlg.tree.get_children()), 2)
        dlg.destroy()

    def test_restore_replaces_the_vault_after_confirmation(self):
        older = pwvault.list_backups(self.path)[-1][1]  # oldest backup: GitHub only
        dlg = self.dialog()
        dlg.tree.selection_set("1")                  # second row = the older backup
        with patch.object(self.pwvault_gui.messagebox, "askyesno", return_value=True) as ask:
            dlg.restore()
        self.assertTrue(ask.called, "restore must ask first")
        self.assertEqual(self.path.read_bytes(), older.read_bytes())
        self.assertIsNone(self.app.vault, "the vault locks so the restored file is read from disk")
        self.assertEqual([e.title for e in self.reopen().kp.entries], ["GitHub"])

    def test_cancelled_confirmation_changes_nothing(self):
        before = self.path.read_bytes()
        dlg = self.dialog()
        with patch.object(self.pwvault_gui.messagebox, "askyesno", return_value=False):
            dlg.restore()
        self.assertEqual(self.path.read_bytes(), before)
        self.assertIsNotNone(self.app.vault)
        dlg.destroy()

    def test_refused_backup_shows_error_and_changes_nothing(self):
        before = self.path.read_bytes()
        dlg = self.dialog()
        dlg.tree.selection_set("0")
        with patch.object(self.pwvault_gui.messagebox, "askyesno", return_value=True), \
                patch.object(pwvault.Vault, "restore",
                             side_effect=VaultError("backup x can't be restored: wrong key")):
            dlg.restore()
        self.assertIn("can't be restored", dlg.error.cget("text"))
        self.assertEqual(self.path.read_bytes(), before)
        self.assertIsNotNone(self.app.vault)
        dlg.destroy()

    def test_no_backups_says_so_and_disables_restore(self):
        for _, p in pwvault.list_backups(self.path):
            p.unlink()
        dlg = self.dialog()
        self.assertEqual(str(dlg.restore_btn.cget("state")), "disabled")
        dlg.destroy()

    def test_ctrl_shift_b_opens_backups_when_unlocked(self):
        self.app.root.focus_force()
        self.app.root.update()
        self.app.root.event_generate("<Control-Shift-B>", when="now")
        self.app.root.update()
        titles = [w.title() for w in self.app.root.winfo_children() if isinstance(w, tk.Toplevel)]
        self.assertIn("Backups", titles)

    def test_database_menu_has_backups_entry(self):
        labels = []
        menu_calls = []
        with patch.object(tk.Menu, "tk_popup", lambda self, *a: menu_calls.append(self)):
            self.app.database_menu()
        self.assertTrue(menu_calls)
        m = menu_calls[0]
        for i in range(m.index("end") + 1):
            if m.type(i) == "command":
                labels.append(m.entrycget(i, "label"))
        self.assertIn("Backups…", labels)
        m.destroy()

    def test_theme_button_cycles_and_saves_the_choice(self):
        with tempfile.TemporaryDirectory() as cfg, \
                patch.dict(os.environ, {"XDG_CONFIG_HOME": cfg}):
            expected = [("light", "Theme: Light"), ("dark", "Theme: Dark"), ("system", "Theme: System")]
            for choice, label in expected:
                self.app.theme_btn.invoke()
                self.assertEqual(self.pwvault_gui.read_theme_choice(), choice)
                self.assertEqual(self.app.theme_btn.cget("text"), label)


KDE_LIGHT = "[Colors:Window]\nBackgroundNormal=239,240,241\n"
KDE_DARK = "[Colors:Window]\nBackgroundNormal=30,31,38\n"


class FakeRun:
    """Stands in for subprocess.run; `out` is what gsettings prints, or an exception to raise."""
    def __init__(self, out="", error=None):
        self.out, self.error, self.calls = out, error, 0

    def __call__(self, *a, **kw):
        self.calls += 1
        if self.error:
            raise self.error
        return type("Done", (), {"stdout": self.out})()


class ThemeTests(unittest.TestCase):
    def setUp(self):
        import pwvault_gui
        self.gui = pwvault_gui
        self.dir = tempfile.TemporaryDirectory()
        self.home = Path(self.dir.name)

    def tearDown(self):
        self.dir.cleanup()

    def kde(self, text):
        (self.home / ".config").mkdir(exist_ok=True)
        (self.home / ".config" / "kdeglobals").write_text(text)

    def detect(self, run=None):
        return self.gui.detect_color_scheme(self.home, run or FakeRun())

    def test_kde_light_window_is_light(self):
        self.kde(KDE_LIGHT)
        run = FakeRun()
        self.assertEqual(self.detect(run), "light")
        self.assertEqual(run.calls, 0, "KDE's answer is final; gsettings isn't asked")

    def test_kde_dark_window_is_dark(self):
        self.kde(KDE_DARK)
        self.assertEqual(self.detect(FakeRun(out="'prefer-light'\n")), "dark")

    def test_gsettings_prefer_light_without_kde_file(self):
        self.assertEqual(self.detect(FakeRun(out="'prefer-light'\n")), "light")

    def test_gsettings_prefer_dark_is_dark(self):
        self.assertEqual(self.detect(FakeRun(out="'prefer-dark'\n")), "dark")

    def test_unreadable_values_fall_back_to_dark(self):
        self.kde("[Colors:Window]\nBackgroundNormal=not,a,colour\n")
        self.assertEqual(self.detect(FakeRun(out="")), "dark")
        self.kde("this is not an ini file ]][[\n")
        self.assertEqual(self.detect(FakeRun(out="")), "dark")

    def test_missing_settings_and_failing_gsettings_fall_back_to_dark(self):
        self.assertEqual(self.detect(FakeRun(error=OSError("no gsettings"))), "dark")
        self.assertEqual(self.detect(FakeRun(error=subprocess.TimeoutExpired("gsettings", 2))), "dark")

    def test_dark_palette_values(self):
        self.assertEqual(self.gui.DARK["BG"], "#1e1f26")
        self.assertEqual(self.gui.DARK["PANEL"], "#2a2c36")
        self.assertEqual(self.gui.DARK["FG"], "#e6e6eb")
        self.assertEqual(self.gui.DARK["MUTED"], "#9a9cab")
        self.assertEqual(self.gui.DARK["ACCENT"], "#4263eb")
        self.assertEqual(self.gui.DARK["DANGER"], "#e5636b")
        self.assertEqual(self.gui.DARK["FAIR"], "#e0b050")
        self.assertEqual(self.gui.DARK["STRONG"], "#6cc28a")


class ThemeChoiceTests(unittest.TestCase):
    def setUp(self):
        import pwvault_gui
        self.gui = pwvault_gui
        self.dir = tempfile.TemporaryDirectory()
        self.home = Path(self.dir.name)
        self.path = self.home / "pwvault" / "settings.ini"

    def tearDown(self):
        self.dir.cleanup()

    def test_missing_or_unreadable_file_means_system(self):
        self.assertEqual(self.gui.read_theme_choice(self.path), "system")
        self.path.parent.mkdir()
        self.path.write_text("[[[ not an ini file\n")
        self.assertEqual(self.gui.read_theme_choice(self.path), "system")

    def test_unknown_value_means_system(self):
        self.path.parent.mkdir()
        self.path.write_text("[ui]\ntheme = purple\n")
        self.assertEqual(self.gui.read_theme_choice(self.path), "system")

    def test_saved_choice_round_trips(self):
        for choice in ("light", "dark", "system"):
            self.gui.write_theme_choice(choice, self.path)
            self.assertEqual(self.gui.read_theme_choice(self.path), choice)

    def test_saved_choice_beats_the_desktop_setting(self):
        (self.home / ".config").mkdir()
        (self.home / ".config" / "kdeglobals").write_text(KDE_DARK)
        self.assertEqual(self.gui.theme_name("light", self.home, FakeRun()), "light")
        self.assertEqual(self.gui.theme_name("system", self.home, FakeRun()), "dark")

    def test_settings_path_follows_xdg_config_home(self):
        with patch.dict(os.environ, {"XDG_CONFIG_HOME": str(self.home)}):
            self.assertEqual(self.gui.settings_path(), self.home / "pwvault" / "settings.ini")


class PaletteValueTests(unittest.TestCase):
    def test_each_palette_has_distinct_colours(self):
        # A live theme switch maps each colour value to its counterpart, so a value used for two
        # roles in one palette would be mapped the wrong way for one of them.
        import pwvault_gui
        for name, palette in (("dark", pwvault_gui.DARK), ("light", pwvault_gui.LIGHT)):
            with self.subTest(palette=name):
                values = list(palette.values())
                self.assertEqual(len(set(values)), len(values))


def luminance(hex_colour: str) -> float:
    def channel(c):
        c = int(c, 16) / 255
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (channel(hex_colour[i:i + 2]) for i in (1, 3, 5))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a: str, b: str) -> float:
    hi, lo = sorted((luminance(a), luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


class ContrastTests(unittest.TestCase):
    # Text pairs drawn on screen: body and muted text on the background and on panels, the accent
    # button's label, and the error colour on the background.
    PAIRS = [("FG", "BG"), ("FG", "PANEL"), ("MUTED", "BG"), ("MUTED", "PANEL"),
             ("ON_ACCENT", "ACCENT"), ("ON_ACCENT", "ACCENT_ACTIVE"), ("DANGER", "BG")]

    def test_both_palettes_meet_4_5_to_1(self):
        import pwvault_gui
        for name, palette in (("dark", pwvault_gui.DARK), ("light", pwvault_gui.LIGHT)):
            for fg, bg in self.PAIRS:
                with self.subTest(palette=name, text=fg, on=bg):
                    self.assertGreaterEqual(contrast(palette[fg], palette[bg]), 4.5)


if __name__ == "__main__":
    unittest.main()
