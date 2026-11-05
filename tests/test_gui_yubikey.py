"""Tests for YubiKey support in the GUI. Run under xvfb:
xvfb-run -a python3 -m unittest discover -s tests -v
"""

import os
import shutil
import tempfile
import tkinter as tk
import unittest
from pathlib import Path
from unittest.mock import patch

from test_pwvault import PW, Base, display_available, pwvault
from test_yubikey import FakeYkman, SLOT2, yubikey
from pwvault import Vault, VaultError, YubiKeySlot

OTHER_PW = "the other copy has its own long password"


class SettingsTests(unittest.TestCase):
    """Remembered slots and the theme share settings.ini without losing each other."""

    def setUp(self):
        import pwvault_gui
        self.gui = pwvault_gui
        self.dir = tempfile.TemporaryDirectory()
        self.ini = Path(self.dir.name) / "pwvault" / "settings.ini"

    def tearDown(self):
        self.dir.cleanup()

    def test_slot_and_theme_keep_each_other(self):
        vault = Path(self.dir.name) / "a=b:c.kdbx"  # characters INI keys can't hold
        self.gui.write_theme_choice("dark", self.ini)
        self.gui.remember_yubikey(vault, SLOT2, self.ini)
        self.gui.write_theme_choice("light", self.ini)
        self.assertEqual(self.gui.remembered_yubikey(vault, self.ini), SLOT2)
        self.assertEqual(self.gui.read_theme_choice(self.ini), "light")
        self.assertIsNone(self.gui.remembered_yubikey(Path(self.dir.name) / "other.kdbx", self.ini))
        self.assertNotIn(str(vault), self.ini.read_text())  # only a hash of the path is stored
        self.gui.remember_yubikey(vault, None, self.ini)
        self.assertIsNone(self.gui.remembered_yubikey(vault, self.ini))
        self.assertEqual(self.gui.read_theme_choice(self.ini), "light")

    def test_unreadable_settings(self):
        self.ini.parent.mkdir(parents=True)
        self.ini.write_text("[yubikey\nnot ini at all")
        self.assertIsNone(self.gui.remembered_yubikey(self.ini, self.ini))

    def test_touch_hook_is_replaceable(self):
        calls = []
        with patch.object(pwvault, "yubikey_touch_prompt", lambda: calls.append(1)), FakeYkman(touch=True):
            pwvault.challenge_response(SLOT2, b"c")
        self.assertEqual(calls, [1])


def widgets(root):
    for w in root.winfo_children():
        yield w
        yield from widgets(w)


@unittest.skipUnless(display_available(), "needs a display; run under xvfb-run")
class GuiYubiKeyTests(Base):
    def setUp(self):
        super().setUp()
        import pwvault_gui
        self.gui = pwvault_gui
        self.config = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"XDG_CONFIG_HOME": self.config.name})
        self.env.start()
        with yubikey():
            v = Vault.create(self.path, PW, yubikey=SLOT2)
            v.add_entry(v.root, "GitHub", "me", "s3cret")
            v.save()
        self.app = None

    def tearDown(self):
        if self.app is not None:
            self.app.root.destroy()
        self.env.stop()
        self.config.cleanup()
        super().tearDown()

    def start(self, path=None):
        if self.app is not None:
            self.app.root.destroy()
        self.app = self.gui.App(path or self.path)
        self.app.show_unlock()
        self.app.root.update()
        return self.app

    def find(self, cls, root=None):
        return [w for w in widgets(root or self.app.root) if isinstance(w, cls)]

    def button(self, text, root=None):
        return next(w for w in widgets(root or self.app.root)
                    if isinstance(w, tk.ttk.Button) and w.cget("text") == text)

    def unlock(self, password=PW, slot=SLOT2):
        self.find(self.gui.PasswordField)[0].var.set(password)
        self.find(self.gui.YubiKeyField)[0].set(slot)
        self.button("Unlock").invoke()
        self.app.root.update()

    def error_text(self):
        return " ".join(w.cget("text") for w in self.find(tk.ttk.Label) if "Error" in str(w.cget("style")))

    def test_unlock_with_and_without_the_yubikey(self):
        self.start()
        with yubikey():
            self.unlock(slot=None)
            self.assertIsNone(self.app.vault)
            self.assertIn("Wrong master password", self.error_text())
            self.assertEqual(self.find(self.gui.PasswordField)[0].var.get(), "")  # cleared
            self.unlock()
        self.assertIsNotNone(self.app.vault)
        self.assertEqual(self.app.vault.yubikey, SLOT2)

    def test_slot_is_remembered_per_vault(self):
        self.start()
        self.assertIsNone(self.find(self.gui.YubiKeyField)[0].get())  # nothing remembered yet
        with yubikey():
            self.unlock()
        self.app.lock()
        self.app.root.update()
        self.assertEqual(self.find(self.gui.YubiKeyField)[0].get(), SLOT2)
        self.start()  # a restart
        self.assertEqual(self.find(self.gui.YubiKeyField)[0].get(), SLOT2)
        other = self.tmp / "other.kdbx"
        shutil.copyfile(self.path, other)
        self.start(other)
        self.assertIsNone(self.find(self.gui.YubiKeyField)[0].get())

    def test_create_a_vault_with_a_yubikey(self):
        new = self.tmp / "new.kdbx"
        self.start(new)
        first, confirm = self.find(self.gui.PasswordField)[:2]
        first.var.set("short")  # allowed with a YubiKey
        confirm.var.set("short")
        self.find(self.gui.YubiKeyField)[0].set(SLOT2)
        with yubikey():
            self.button("Create vault").invoke()
            self.app.root.update()
            self.assertIsNotNone(self.app.vault, self.error_text())
            Vault.open(new, "short", yubikey=SLOT2)
        with self.assertRaises(VaultError):
            Vault.open(new, "short")

    def test_change_master_key_adds_and_removes_the_yubikey(self):
        self.start()
        current = PW
        with yubikey():
            self.unlock()
            for new_pw, slot in ((OTHER_PW, None), (PW, YubiKeySlot(1))):
                d = self.gui.ChangeMasterDialog(self.app)
                d.cur.set(current)
                d.new.set(new_pw)
                d.confirm.set(new_pw)
                self.assertEqual(d.yubikey.get(), self.app.vault.yubikey)  # defaults to the current one
                d.yubikey.set(slot)
                d.apply()
                self.app.root.update()
                self.assertFalse(d.winfo_exists())
                current = new_pw
                Vault.open(self.path, current, yubikey=slot)
                self.assertEqual(self.gui.remembered_yubikey(self.path), slot)
        with self.assertRaises(VaultError):
            Vault.open(self.path, current)  # slot 1 is required again

    def test_change_master_key_with_an_absent_yubikey_writes_nothing(self):
        from test_yubikey import SECRET, emulated_key
        self.start()
        with yubikey():
            self.unlock()
        before = self.path.read_bytes()
        d = self.gui.ChangeMasterDialog(self.app)
        d.cur.set(PW)
        d.new.set(PW)
        d.confirm.set(PW)
        d.yubikey.set(YubiKeySlot(1))  # a key that isn't plugged in
        current_key = emulated_key(SECRET)

        def challenge(slot, chal):
            if slot == SLOT2:
                return current_key(slot, chal)
            raise VaultError("no YubiKey found; plug it in and try again")
        with patch.object(pwvault, "challenge_response", side_effect=challenge), \
                patch.object(self.gui.messagebox, "showerror") as shown:
            d.apply()
            self.app.root.update()
        self.assertEqual(self.path.read_bytes(), before)
        self.assertIn("No YubiKey found", shown.call_args.args[1])
        self.assertIsNone(self.app.vault)  # dropped; the next unlock reads the unchanged file

    def test_merge_other_copy_with_its_own_yubikey(self):
        plain = self.tmp / "plain.kdbx"
        v = Vault.create(plain, PW)
        v.save()
        other = self.tmp / "other.kdbx"
        shutil.copyfile(plain, other)
        with yubikey():
            o = Vault.open(other, PW)
            o.add_entry(o.root, "From other", "me", "y")
            o.rekey(OTHER_PW, None, SLOT2)
            o.save()
        self.start(plain)
        self.unlock(slot=None)
        d = self.gui.MergeDialog(self.app)
        d.other.set(str(other))
        self.assertEqual(str(d.yubikey.box.cget("state")), "disabled")  # same credentials ticked
        d.same.set(False)
        d.toggle_credentials()
        self.assertEqual(str(d.yubikey.box.cget("state")), "readonly")
        d.password.set(OTHER_PW)
        d.yubikey.set(SLOT2)
        with yubikey():
            d.merge()
        self.assertIn(("Added", "Root", "From other"), [tuple(d.tree.item(i, "values"))
                                                        for i in d.tree.get_children()])
        d.close()

    def test_touch_prompt_is_drawn_while_waiting(self):
        self.start()
        seen = []
        real = __import__("test_yubikey").emulated_key(__import__("test_yubikey").SECRET)

        def slow_key(slot, challenge):
            pwvault.yubikey_touch_prompt()  # what the driver does when the key asks for a touch
            seen.append([w.cget("text") for w in self.find(tk.ttk.Label)])
            return real(slot, challenge)
        with patch.object(pwvault, "challenge_response", side_effect=slow_key):
            self.unlock()
        self.assertTrue(any("Touch your YubiKey" in t for t in seen[0]))
        self.assertIsNotNone(self.app.vault)

    def test_errors_after_a_touch_prompt_use_the_error_style(self):
        # Regression (CodeRabbit, PR #6): touch_prompt() greys the message line; an error shown
        # on it afterwards must switch back to the error style.
        def touched_then_absent(_slot, _challenge):
            pwvault.yubikey_touch_prompt()
            raise VaultError("timed out waiting for a touch on the YubiKey")
        plain = self.tmp / "plain.kdbx"
        Vault.create(plain, PW).save()
        other = self.tmp / "other.kdbx"
        shutil.copyfile(self.path, other)
        self.start(plain)
        self.unlock(slot=None)
        # Merge: the other copy needs a YubiKey that asks for a touch, then times out.
        d = self.gui.MergeDialog(self.app)
        d.other.set(str(other))
        d.same.set(False)
        d.toggle_credentials()
        d.password.set(PW)
        d.yubikey.set(SLOT2)
        with patch.object(pwvault, "challenge_response", side_effect=touched_then_absent):
            d.merge()
        self.assertIn("other.kdbx: timed out waiting for a touch", d.error.cget("text"))
        self.assertEqual(str(d.error.cget("style")), "Error.TLabel")
        d.other.set("")
        d.merge()
        self.assertEqual(str(d.error.cget("style")), "Error.TLabel")  # "Choose the other copy first."
        d.destroy()
        # Change master key: a touch prompt, then a mismatch on the next attempt.
        c = self.gui.ChangeMasterDialog(self.app)
        c.err.configure(text="", style="Muted.TLabel")  # as touch_prompt leaves it
        c.new.set(PW)
        c.confirm.set(PW + "x")
        c.apply()
        self.assertEqual(str(c.err.cget("style")), "Error.TLabel")
        c.confirm.set(PW)
        c.new.set("short")
        c.confirm.set("short")
        c.err.configure(style="Muted.TLabel")
        c.apply()  # too short without a key file or YubiKey
        self.assertEqual(str(c.err.cget("style")), "Error.TLabel")
        c.destroy()

    def test_driver_errors_are_shown_inline(self):
        before = self.path.read_bytes()
        for message in ("no YubiKey found; plug it in and try again",
                        "YubiKey support needs the yubikey extra: pip install 'pwvault-manager[yubikey]'",
                        "timed out waiting for a touch on the YubiKey"):
            self.start()
            with patch.object(pwvault, "challenge_response", side_effect=VaultError(message)):
                self.unlock()
            self.assertIsNone(self.app.vault)
            self.assertIn(message[0].upper() + message[1:], self.error_text())
            self.assertEqual(self.find(self.gui.PasswordField)[0].var.get(), "")
        self.assertEqual(self.path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
