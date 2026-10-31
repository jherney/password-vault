"""Tests for TOTP (2FA) codes. Run: python3 -m unittest discover -s tests"""

import shutil
import subprocess
import unittest
from unittest.mock import patch

from test_backups import BackupCliTests
from test_pwvault import PW, Base, display_available, pwvault
from pwvault import Totp, VaultError

SECRET = "JBSWY3DPEHPK3PXP"  # base32 of b"Hello!\xde\xad\xbe\xef", a common example secret
URI = f"otpauth://totp/Example:me?secret={SECRET}&period=30&digits=6&issuer=Example"
# RFC 6238 Appendix B: the seed is "12345678901234567890" repeated to the hash's block size.
RFC_SEEDS = {"SHA1": b"12345678901234567890",
             "SHA256": b"12345678901234567890123456789012",
             "SHA512": b"1234567890" * 6 + b"1234"}
RFC_VECTORS = [  # time, SHA1, SHA256, SHA512 (8 digits, 30 s)
    (59, "94287082", "46119246", "90693936"),
    (1111111109, "07081804", "68084774", "25091201"),
    (1111111111, "14050471", "67062674", "99943326"),
    (1234567890, "89005924", "91819424", "93441116"),
    (2000000000, "69279037", "90698825", "38618901"),
    (20000000000, "65353130", "77737706", "47863826"),
]


def string_field(entry, key):
    """The entry's <String> element for key, or None."""
    return next((s for s in entry._element.findall("String") if s.findtext("Key") == key), None)


class GeneratorTests(unittest.TestCase):
    def test_rfc_6238_vectors(self):
        for now, *codes in RFC_VECTORS:
            for algo, code in zip(("SHA1", "SHA256", "SHA512"), codes):
                with self.subTest(now=now, algo=algo):
                    self.assertEqual(pwvault.totp_code(Totp(RFC_SEEDS[algo], 8, 30, algo), now)[0], code)
                    self.assertEqual(pwvault.totp_code(Totp(RFC_SEEDS[algo], 6, 30, algo), now)[0], code[2:])

    def test_seconds_left(self):
        t = Totp(RFC_SEEDS["SHA1"])
        self.assertEqual(pwvault.totp_code(t, 59)[1], 1)
        self.assertEqual(pwvault.totp_code(t, 60)[1], 30)
        self.assertEqual(pwvault.totp_code(Totp(RFC_SEEDS["SHA1"], period=60), 59.9)[1], 1)

    def test_steam_code(self):
        # RFC 4226 Appendix D: counter 0 truncates to 1284755224; Steam spells that in base 26.
        n, expected = 1284755224, ""
        for _ in range(5):
            n, i = divmod(n, 26)
            expected += pwvault.STEAM_ALPHABET[i]
        self.assertEqual(pwvault.totp_code(Totp(RFC_SEEDS["SHA1"], 5, 30, steam=True), 0)[0], expected)

    def test_display_grouping(self):
        self.assertEqual(pwvault.fmt_totp_code("123456"), "123 456")
        self.assertEqual(pwvault.fmt_totp_code("12345678"), "1234 5678")
        self.assertEqual(pwvault.fmt_totp_code("1234567"), "1234 567")
        self.assertEqual(pwvault.fmt_totp_code("99X58"), "99X58")


class ParseTests(unittest.TestCase):
    def test_otpauth_uri_variants(self):
        secret = pwvault._totp_secret(SECRET)
        cases = {
            URI: Totp(secret),
            f"otpauth://totp/x?secret={SECRET.lower()}&digits=8&period=60&algorithm=SHA256":
                Totp(secret, 8, 60, "SHA256"),
            f"OTPAUTH://TOTP/x?Secret={SECRET}&Algorithm=sha512": Totp(secret, 6, 30, "SHA512"),
            f"otpauth://totp/Steam:me?secret={SECRET}&encoder=steam": Totp(secret, 5, 30, steam=True),
            f"otpauth://totp/Steam:me?secret={SECRET}&digits=5&encoder=Steam": Totp(secret, 5, 30, steam=True),
            f"otpauth://totp/Steam:me?secret={SECRET}&digits=6&encoder=steam": Totp(secret, 6, 30, steam=True),
            f"  otpauth://totp/x?secret={SECRET}%3D%3D%3D%3D  ": Totp(secret),
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(pwvault.parse_totp(text), expected)

    def test_keeotp_format(self):
        secret = pwvault._totp_secret(SECRET)
        self.assertEqual(pwvault.parse_totp(f"key={SECRET}"), Totp(secret))
        self.assertEqual(pwvault.parse_totp(f"key={SECRET}&step=45&size=8&otpHashMode=Sha256"),
                         Totp(secret, 8, 45, "SHA256"))

    def test_base32_as_sites_show_it(self):
        self.assertEqual(pwvault._totp_secret("jbsw y3dp-ehpk 3pxp"), pwvault._totp_secret(SECRET))

    def test_errors_name_the_problem(self):
        cases = {
            "otpauth://totp/x?secret=not*base32": "isn't valid base32",
            "otpauth://totp/x?secret=ÄÖ": "isn't valid base32",
            "otpauth://totp/x?issuer=x": "is empty",
            f"otpauth://hotp/x?secret={SECRET}&counter=0": "HOTP (counter-based) codes aren't supported",
            f"otpauth://totp/x?secret={SECRET}&digits=5": "digits must be 6–10",
            f"otpauth://totp/x?secret={SECRET}&digits=11": "digits must be 6–10",
            f"otpauth://totp/x?secret={SECRET}&digits=six": "digits must be 6–10",
            f"otpauth://totp/x?secret={SECRET}&encoder=steam&digits=4": "digits must be 5–10",
            f"otpauth://totp/x?secret={SECRET}&period=0": "period must be a positive number",
            f"otpauth://totp/x?secret={SECRET}&period=-30": "period must be a positive number",
            f"otpauth://totp/x?secret={SECRET}&algorithm=MD5": "unknown TOTP algorithm MD5",
            f"otpauth://other/x?secret={SECRET}": "isn't an otpauth://totp URI",
            "just some text": "isn't an otpauth:// URI or a KeeOtp",
            "": "isn't an otpauth:// URI or a KeeOtp",
        }
        for text, message in cases.items():
            with self.subTest(text=text), self.assertRaises(VaultError) as cm:
                pwvault.parse_totp(text)
            self.assertIn(message, str(cm.exception))


class NormalizeTests(unittest.TestCase):
    def test_bare_secret_becomes_keepassxc_uri(self):
        self.assertEqual(pwvault.normalize_totp(" jbsw y3dp ehpk 3pxp ", "GitHub", "me"),
                         f"otpauth://totp/GitHub:me?secret={SECRET}&period=30&digits=6&issuer=GitHub")

    def test_label_is_url_encoded(self):
        uri = pwvault.normalize_totp(SECRET, "Git:Hub & Co ü", "me@x.org")
        self.assertEqual(uri, f"otpauth://totp/Git%3AHub%20%26%20Co%20%C3%BC:me%40x.org?secret={SECRET}"
                              "&period=30&digits=6&issuer=Git%3AHub%20%26%20Co%20%C3%BC")
        self.assertEqual(pwvault.parse_totp(uri), Totp(pwvault._totp_secret(SECRET)))

    def test_untitled_entry(self):
        self.assertTrue(pwvault.normalize_totp(SECRET).startswith("otpauth://totp/pwvault:?secret="))

    def test_uri_kept_as_is(self):
        uri = URI + "&image=https%3A%2F%2Fexample.com%2Flogo.png"
        self.assertEqual(pwvault.normalize_totp(f"  {uri}\n", "Other", "name"), uri)

    def test_invalid_refused(self):
        for text in ("not base32!", "", "otpauth://totp/x?secret=1", "otpauth://hotp/x?secret=" + SECRET):
            with self.subTest(text=text), self.assertRaises(VaultError):
                pwvault.normalize_totp(text, "t", "u")

    def test_uri_for_other_settings(self):
        t = Totp(pwvault._totp_secret(SECRET), 5, 30, "SHA256", steam=True)
        uri = pwvault.totp_uri(t, "Steam", "me")
        self.assertEqual(uri, f"otpauth://totp/Steam:me?secret={SECRET}&period=30&digits=5&issuer=Steam"
                              "&encoder=steam&algorithm=SHA256")
        self.assertEqual(pwvault.parse_totp(uri), t)


class EntryStorageTests(Base):
    def entry(self, v=None):
        return (v or self.reopen()).kp.find_entries(title="GitHub", first=True)

    def legacy_entry(self, v, settings="30;6"):
        e = self.entry(v)
        e.set_custom_property("TOTP Seed", SECRET, protect=True)
        if settings is not None:
            e.set_custom_property("TOTP Settings", settings)
        v.save()
        return e

    def test_entry_without_totp(self):
        self.assertIsNone(pwvault.entry_totp(self.entry(self.new_vault())))

    def test_set_saves_protected_and_round_trips(self):
        v = self.new_vault()
        v.update_entry(self.entry(v), {"otp": URI})
        v.save()
        e = self.entry()
        self.assertEqual(e.otp, URI)
        self.assertEqual(string_field(e, "otp").find("Value").get("Protected"), "True")
        self.assertEqual(pwvault.entry_totp(e), Totp(pwvault._totp_secret(SECRET)))

    def test_add_entry_with_otp(self):
        v = self.new_vault()
        v.add_entry(v.root, "New", "me", "pw", otp=URI)
        v.add_entry(v.root, "Plain", "me", "pw")
        v.save()
        kp = self.reopen().kp
        self.assertEqual(kp.find_entries(title="New", first=True).otp, URI)
        self.assertIsNone(string_field(kp.find_entries(title="Plain", first=True), "otp"))

    def test_clear_removes_the_field(self):
        v = self.new_vault()
        v.update_entry(self.entry(v), {"otp": URI})
        v.save()
        v.update_entry(self.entry(v), {"otp": ""})
        v.save()
        e = self.entry()
        self.assertIsNone(string_field(e, "otp"))
        self.assertIsNone(pwvault.entry_totp(e))

    def test_changes_are_history_versions(self):
        v = self.new_vault()
        e = self.entry(v)
        v.update_entry(e, {"otp": URI})
        v.update_entry(e, {"otp": URI})  # unchanged: no new version
        other = pwvault.normalize_totp("GEZDGNBVGY3TQOJQ", "GitHub", "me")
        v.update_entry(e, {"otp": other})
        self.assertEqual([h.otp for h in e.history], [None, URI])
        v.restore_history(e, e.history[1])
        self.assertEqual(e.otp, URI)
        v.restore_history(e, e.history[0])  # the version from before any TOTP
        self.assertIsNone(string_field(e, "otp"))

    def test_legacy_fields(self):
        v = self.new_vault()
        secret = pwvault._totp_secret(SECRET)
        for settings, expected in (("30;6", Totp(secret)), ("45;8", Totp(secret, 8, 45)),
                                   ("30;S", Totp(secret, 5, 30, steam=True)), (None, Totp(secret)),
                                   ("60;8;https://example.com", Totp(secret, 8, 60))):
            with self.subTest(settings=settings):
                e = self.legacy_entry(v, settings)
                self.assertEqual(pwvault.entry_totp(e), expected)
                if settings is None:
                    continue
                pwvault.remove_string_field(e, "TOTP Settings")

    def test_unreadable_legacy_settings(self):
        v = self.new_vault()
        for settings in ("0;6", "30;3", "abc"):
            with self.subTest(settings=settings), self.assertRaises(VaultError):
                pwvault.entry_totp(self.legacy_entry(v, settings))

    def test_otp_wins_over_legacy(self):
        v = self.new_vault()
        e = self.legacy_entry(v, "30;S")
        e.otp = f"otpauth://totp/x?secret={SECRET}&digits=8"  # as another app might leave it
        self.assertEqual(pwvault.entry_totp(e), Totp(pwvault._totp_secret(SECRET), 8))

    def test_setting_or_clearing_drops_legacy_fields(self):
        for value in (URI, ""):
            with self.subTest(value=value):
                self.path = self.tmp / f"vault{len(value)}.kdbx"
                v = self.new_vault()
                e = self.legacy_entry(v)
                v.update_entry(e, {"otp": value})
                v.save()
                e = self.entry()
                self.assertIsNone(e.get_custom_property("TOTP Seed"))
                self.assertIsNone(e.get_custom_property("TOTP Settings"))
                self.assertEqual(e.otp, value or None)

    def test_other_edits_leave_legacy_fields_alone(self):
        v = self.new_vault()
        e = self.legacy_entry(v, "45;8")
        v.update_entry(e, {"title": "GitHub", "username": "someone else"})
        v.save()
        e = self.entry()
        self.assertEqual((e.get_custom_property("TOTP Seed"), e.get_custom_property("TOTP Settings")),
                         (SECRET, "45;8"))
        self.assertIsNone(string_field(e, "otp"))

    def test_clearing_a_legacy_only_entry_is_a_change(self):
        v = self.new_vault()
        e = self.legacy_entry(v)
        v.update_entry(e, {"otp": ""})
        self.assertEqual(len(e.history), 1)
        self.assertIsNone(pwvault.entry_totp(e))

    def test_restoring_a_version_without_totp_over_legacy(self):
        v = self.new_vault()
        e = self.entry(v)
        v.update_entry(e, {"password": "changed"})  # history[0]: no TOTP at all
        e.set_custom_property("TOTP Seed", SECRET, protect=True)  # added later, e.g. by KeePassXC
        v.restore_history(e, e.history[0])
        self.assertIsNone(pwvault.entry_totp(e))

    def test_restoring_a_legacy_version(self):
        v = self.new_vault()
        e = self.legacy_entry(v, "45;8")
        v.update_entry(e, {"password": "changed"})  # history[0] holds the legacy fields
        v.restore_history(e, e.history[0])  # entry still legacy: fields stay as they are
        self.assertEqual(e.get_custom_property("TOTP Settings"), "45;8")
        self.assertIsNone(e.otp)
        v.update_entry(e, {"otp": pwvault.normalize_totp("GEZDGNBVGY3TQOJQ", "GitHub", "me")})
        v.restore_history(e, e.history[0])  # entry moved to "otp": the old secret comes back there
        self.assertEqual(pwvault.entry_totp(e), Totp(pwvault._totp_secret(SECRET), 8, 45))
        self.assertIsNone(e.get_custom_property("TOTP Seed"))


class TotpCliTests(Base):
    run_cli = BackupCliTests.run_cli
    NOW = 999_999_997  # 7 s into its 30 s window: 23 s left

    def setUp(self):
        super().setUp()
        clock = patch.object(pwvault.time, "time", return_value=self.NOW)
        clock.start()
        self.addCleanup(clock.stop)
        self.code = pwvault.totp_code(pwvault.parse_totp(URI), self.NOW)[0]

    def with_totp(self, otp=URI):
        v = self.new_vault()
        v.update_entry(v.kp.entries[0], {"otp": otp})
        v.save()
        return v

    def entry(self):
        return self.reopen().kp.entries[0]

    def test_copies_the_code(self):
        self.with_totp()
        with patch.object(pwvault, "copy_to_clipboard", return_value=True) as copy:
            code, out = self.run_cli("totp", "github", prompts=[PW])
        self.assertIsNone(code)
        copy.assert_called_once_with(self.code)
        self.assertEqual(out, "Code copied to clipboard (valid 23s more; clipboard clears in "
                              f"{pwvault.CLIPBOARD_CLEAR_SECONDS}s).\n")

    def test_show_prints_grouped_code_never_the_secret(self):
        self.with_totp()
        code, out = self.run_cli("totp", "github", "--show", prompts=[PW])
        self.assertEqual(out, f"{self.code[:3]} {self.code[3:]}  (23s left)\n")
        self.assertNotIn(SECRET, out)

    def test_reading_a_code_does_not_save(self):
        self.with_totp()
        before = self.path.read_bytes()
        self.run_cli("totp", "github", "--show", prompts=[PW])
        self.assertEqual(self.path.read_bytes(), before)

    def test_set_bare_secret(self):
        self.new_vault()
        code, out = self.run_cli("totp", "github", "--set", prompts=[PW, "jbsw y3dp ehpk 3pxp"])
        self.assertIsNone(code)
        self.assertEqual(self.entry().otp,
                         f"otpauth://totp/GitHub:me?secret={SECRET}&period=30&digits=6&issuer=GitHub")
        self.assertEqual(out, f"TOTP set for 'GitHub'. Current code: {self.code[:3]} {self.code[3:]} (23s left).\n")
        self.assertNotIn(SECRET, out)

    def test_set_invalid_secret_changes_nothing(self):
        self.new_vault()
        before = self.path.read_bytes()
        code, _ = self.run_cli("totp", "github", "--set", prompts=[PW, "not a secret!"])
        self.assertEqual(code, "error: TOTP secret isn't valid base32")
        self.assertEqual(self.path.read_bytes(), before)

    def test_clear_confirm_and_cancel(self):
        self.with_totp()
        before = self.path.read_bytes()
        with patch("builtins.input", return_value="n"):
            self.assertEqual(self.run_cli("totp", "github", "--clear", prompts=[PW]), (None, "Cancelled.\n"))
        self.assertEqual(self.path.read_bytes(), before)
        with patch("builtins.input", return_value="y"):
            self.assertEqual(self.run_cli("totp", "github", "--clear", prompts=[PW]), (None, "TOTP removed.\n"))
        self.assertIsNone(pwvault.entry_totp(self.entry()))
        code, _ = self.run_cli("totp", "github", "--clear", prompts=[PW])
        self.assertEqual(code, "error: 'GitHub' has no TOTP secret")

    def test_set_and_clear_are_exclusive(self):
        self.new_vault()
        with patch("sys.stderr"):
            self.assertEqual(self.run_cli("totp", "github", "--set", "--clear")[0], 2)  # argparse usage error

    def test_entry_without_totp(self):
        self.new_vault()
        code, _ = self.run_cli("totp", "github", prompts=[PW])
        self.assertEqual(code, "error: 'GitHub' has no TOTP secret — add one with `pwvault totp github --set`")

    def test_get_mentions_totp_only_when_set(self):
        self.new_vault()
        _, plain = self.run_cli("get", "github", "--show", prompts=[PW])
        self.assertNotIn("TOTP", plain)
        self.path.unlink()
        self.with_totp()
        _, out = self.run_cli("get", "github", "--show", prompts=[PW])
        self.assertEqual(out.replace("TOTP:     set — `pwvault totp github`\n", ""), plain)
        self.assertNotIn(SECRET, out)
        self.assertNotIn(self.code, out)

    def test_get_with_unreadable_totp(self):
        self.with_totp("otpauth://hotp/x?secret=" + SECRET)
        _, out = self.run_cli("get", "github", "--show", prompts=[PW])
        self.assertIn("TOTP:     unreadable (HOTP (counter-based) codes aren't supported)", out)


@unittest.skipUnless(display_available(), "needs a display; run under xvfb-run")
class GuiTests(Base):
    NOW = 999_999_997

    def setUp(self):
        super().setUp()
        import pwvault_gui
        self.gui = pwvault_gui
        self.clock = [self.NOW]
        clock = patch.object(pwvault.time, "time", side_effect=lambda: self.clock[0])
        clock.start()
        self.addCleanup(clock.stop)
        v = self.new_vault()
        v.add_entry(v.root, "Plain", "u", "p")
        v.update_entry(v.entries(query="GitHub")[0], {"otp": URI})
        v.save()
        self.app = pwvault_gui.App(self.path)
        self.app.vault = self.reopen()
        self.app.show_main()
        self.app.root.update()

    def tearDown(self):
        self.app.quit()
        super().tearDown()

    def select(self, title):
        self.app.show_group(self.app.vault.root, select=self.app.vault.entries(query=title)[0])
        self.app.root.update()

    def code_at(self, now):
        return pwvault.fmt_totp_code(pwvault.totp_code(pwvault.parse_totp(URI), now)[0])

    def pending(self, job):
        return job in self.app.root.tk.splitlist(self.app.root.tk.call("after", "info"))

    def panel_text(self):
        out = []
        def walk(w):
            for c in w.winfo_children():
                if isinstance(c, self.gui.ttk.Label):
                    out.append(c.cget("text"))
                walk(c)
        walk(self.app.detail)
        return out

    def test_live_code_and_countdown(self):
        self.select("GitHub")
        self.assertEqual(self.app.totp_code.cget("text"), self.code_at(self.NOW))
        self.assertEqual(self.app.totp_left.cget("text"), "23s")
        self.clock[0] = self.NOW + 23  # the next window
        self.app.root.after(1100)  # let the pending tick run
        self.app.root.update()
        self.assertEqual(self.app.totp_code.cget("text"), self.code_at(self.NOW + 23))
        self.assertEqual(self.app.totp_left.cget("text"), "30s")
        self.assertNotEqual(self.code_at(self.NOW), self.code_at(self.NOW + 23))

    def test_timer_stops_on_reselect_and_lock(self):
        self.select("GitHub")
        first = self.app.totp_job
        self.assertTrue(self.pending(first))
        self.select("Plain")
        self.assertFalse(self.pending(first))
        self.assertIsNone(self.app.totp_job)
        self.assertNotIn("ONE-TIME CODE", self.panel_text())
        self.select("GitHub")
        job = self.app.totp_job
        self.app.lock()
        self.app.root.update()
        self.assertFalse(self.pending(job))
        self.assertIsNone(self.app.totp_job)

    def test_ctrl_t_and_copy_button_copy_the_current_code(self):
        self.select("GitHub")
        with patch.object(self.app, "copy") as copy:
            self.app.tree.focus_set()
            self.app.root.update()
            self.app.tree.event_generate("<Control-t>")
            self.app.root.update()
            self.clock[0] = self.NOW + 30
            self.app.copy_totp()  # computed at click time, not read off the label
        self.assertEqual([c.args for c in copy.call_args_list],
                         [(self.code_at(self.NOW).replace(" ", ""), "One-time code"),
                          (self.code_at(self.NOW + 30).replace(" ", ""), "One-time code")])

    def test_ctrl_t_without_totp_does_nothing(self):
        self.select("Plain")
        with patch.object(self.app, "copy") as copy:
            self.app.copy_totp()
        copy.assert_not_called()

    def test_unreadable_totp_is_shown_as_such(self):
        e = self.app.vault.entries(query="Plain")[0]
        e.otp = "otpauth://hotp/x?secret=" + SECRET
        self.select("Plain")
        self.assertIn("unreadable TOTP settings", self.panel_text())
        self.assertIsNone(self.app.totp_job)

    def dialog(self, title=None):
        e = self.app.vault.entries(query=title)[0] if title else None
        d = self.gui.EntryDialog(self.app, e)
        self.app.root.update()
        return d

    def test_dialog_adds_entry_with_secret(self):
        d = self.dialog()
        d.vars["title"].set("New")
        d.vars["password"].set("pw")
        d.otp.set("jbsw y3dp ehpk 3pxp")
        d.save()
        self.assertEqual(self.reopen().kp.find_entries(title="New", first=True).otp,
                         f"otpauth://totp/New:?secret={SECRET}&period=30&digits=6&issuer=New")

    def test_dialog_shows_and_clears_secret(self):
        d = self.dialog("GitHub")
        self.assertEqual(d.otp.get(), URI)
        d.otp.set("")
        d.save()
        self.assertIsNone(string_field(self.reopen().kp.find_entries(title="GitHub", first=True), "otp"))

    def test_dialog_refuses_invalid_secret(self):
        before = self.path.read_bytes()
        d = self.dialog("GitHub")
        d.otp.set("not a secret!")
        d.save()
        self.assertEqual(d.err.cget("text"), "TOTP secret isn't valid base32.")
        self.assertTrue(d.winfo_exists())
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(self.app.vault.entries(query="GitHub")[0].otp, URI)

    def test_dialog_keeps_legacy_storage_unless_totp_changes(self):
        e = self.app.vault.entries(query="Plain")[0]
        e.set_custom_property("TOTP Seed", SECRET, protect=True)
        e.set_custom_property("TOTP Settings", "45;8")
        self.app.save()
        d = self.dialog("Plain")
        self.assertEqual(pwvault.parse_totp(d.otp.get()), Totp(pwvault._totp_secret(SECRET), 8, 45))
        d.vars["title"].set("Plain renamed")
        d.save()
        e = self.reopen().kp.find_entries(title="Plain renamed", first=True)
        self.assertEqual((e.get_custom_property("TOTP Seed"), e.get_custom_property("TOTP Settings")),
                         (SECRET, "45;8"))
        self.assertIsNone(e.otp)


@unittest.skipUnless(shutil.which("keepassxc-cli"), "needs keepassxc-cli")
class KeePassXCInteropTests(Base):
    """KeePassXC reads what pwvault writes, and shows the same codes."""

    def keepassxc_code(self, title):
        out = subprocess.run(["keepassxc-cli", "show", "-q", "-t", str(self.path), title],
                             input=PW + "\n", capture_output=True, text=True, timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr)
        return out.stdout.strip().splitlines()[-1]

    def test_same_codes_as_keepassxc(self):
        v = self.new_vault()
        v.add_entry(v.root, "bare", "me & you", "pw", otp=pwvault.normalize_totp(SECRET, "bare", "me & you"))
        v.add_entry(v.root, "sha512", "me", "pw",
                    otp=f"otpauth://totp/x?secret={SECRET}&digits=8&period=60&algorithm=SHA512")
        v.add_entry(v.root, "keeotp", "me", "pw", otp=f"key={SECRET}&step=30&size=7&otpHashMode=Sha256")
        steam = v.add_entry(v.root, "steam", "me", "pw")
        steam.set_custom_property("TOTP Seed", SECRET, protect=True)
        steam.set_custom_property("TOTP Settings", "30;S")
        v.save()
        for title in ("bare", "sha512", "keeotp", "steam"):
            with self.subTest(title=title):
                t = pwvault.entry_totp(v.kp.find_entries(title=title, first=True))
                for _ in range(2):  # again if the code changed while keepassxc-cli ran
                    before, theirs, after = pwvault.totp_code(t)[0], self.keepassxc_code(title), pwvault.totp_code(t)[0]
                    if before == after:
                        break
                self.assertEqual(theirs, after)

if __name__ == "__main__":
    unittest.main()
