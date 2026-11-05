"""Tests for YubiKey HMAC-SHA1 challenge-response unlock. Run: python3 -m unittest discover -s tests

No hardware is needed: pwvault.challenge_response is replaced by an emulator that does what a
YubiKey slot in variable-length mode does with KeePassXC's 64-byte challenge block.
"""

import base64
import hashlib
import hmac
import shutil
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from pykeepass.kdbx_parsing.common import compute_key_composite

from test_pwvault import PW, Base, pwvault
from pwvault import Vault, VaultError, YubiKeySlot

DATA = Path(__file__).resolve().parent / "data"
KEEPASSXC_VAULT = DATA / "keepassxc-YubiKeyProtectedPasswords.kdbx"
SECRET = bytes.fromhex("1ce30fd78d20dcfa40b50c18779afb0f02288db7")  # KeePassXC's test secret
OTHER_SECRET = bytes(range(20))
SLOT2 = YubiKeySlot(2)


def emulated_key(secret):
    """A YubiKey HMAC-SHA1 slot: it strips the padding (every trailing byte equal to the last one)
    from the 64-byte block and answers with HMAC-SHA1 of what is left."""
    def respond(_slot, challenge):
        block = pwvault.yubikey_challenge_block(challenge)
        assert len(block) == 64
        return hmac.new(secret, block.rstrip(block[-1:]), hashlib.sha1).digest()
    return respond


@contextmanager
def yubikey(secret=SECRET):
    with patch.object(pwvault, "challenge_response", side_effect=emulated_key(secret)) as m:
        yield m


class KeePassXCCompatibilityTests(Base):
    def test_known_answer_from_keepassxc(self):
        # KeePassXC's TestCli.cpp: this secret answers "CLITest" with this response.
        self.assertEqual(emulated_key(SECRET)(SLOT2, b"CLITest").hex(),
                         "a23b9400be479a30a9eb509b85565b6b3025b48e")

    def test_opens_keepassxcs_yubikey_vault(self):
        vault_file = self.tmp / "kpxc.kdbx"
        shutil.copyfile(KEEPASSXC_VAULT, vault_file)
        with yubikey() as key:
            v = Vault.open(vault_file, "a", yubikey=SLOT2)
        self.assertEqual(sorted(e.title for e in v.kp.entries), ["entry1", "entry2"])
        salt = pwvault.read_kdf_params(KEEPASSXC_VAULT.read_bytes())[1]["S"]
        key.assert_called_once_with(SLOT2, salt)  # challenged with the KDF salt
        with self.assertRaisesRegex(VaultError, "wrong master password or key file"):
            Vault.open(vault_file, "a")  # the YubiKey is required
        with yubikey(OTHER_SECRET), self.assertRaisesRegex(VaultError, "wrong master password"):
            Vault.open(vault_file, "a", yubikey=SLOT2)  # and it must be the right one

    def test_challenge_block_is_keepassxcs(self):
        salt = bytes(range(32))
        self.assertEqual(pwvault.yubikey_challenge_block(salt), salt + bytes([32]) * 32)


class KeyFileKeyTests(Base):
    """keyfile_key must give what pykeepass (and KeePass) derive, or YubiKey vaults with a key
    file would open nowhere else."""

    def check(self, content: bytes):
        f = self.tmp / "key"
        f.write_bytes(content)
        ours = hashlib.sha256(hashlib.sha256(b"pw").digest() + pwvault.keyfile_key(f)).digest()
        self.assertEqual(ours, compute_key_composite(password="pw", keyfile=str(f)), content[:40])

    def test_every_key_file_format(self):
        key = bytes(range(32))
        self.check(key)                                   # 32 raw bytes
        self.check(key.hex().encode())                    # 64 hex characters
        self.check(b"any other file, hashed" * 7)         # anything else: SHA-256 of it
        self.check(b"<KeyFile><Meta><Version>1.00</Version></Meta><Key><Data>"
                   + base64.b64encode(key) + b"</Data></Key></KeyFile>")
        digest = hashlib.sha256(key).digest()[:4].hex().upper()
        self.check(f'<?xml version="1.0" encoding="utf-8"?><KeyFile><Meta><Version>2.0</Version></Meta>'
                   f'<Key><Data Hash="{digest}">{key.hex().upper()}</Data></Key></KeyFile>'.encode())
        pwvault.generate_keyfile(self.tmp / "gen.keyx")   # what pwvault itself creates
        self.check((self.tmp / "gen.keyx").read_bytes())


class YubiKeyVaultTests(Base):
    def make(self, password=PW, keyfile=None):
        with yubikey():
            v = Vault.create(self.path, password, keyfile, yubikey=SLOT2)
            v.add_entry(v.root, "GitHub", "me", "s3cret")
            v.save()
        return v

    def test_create_save_reopen(self):
        v = self.make()
        with yubikey():
            v.add_entry(v.root, "Two", "me", "pw2")
            v.save()
            v.save()
            again = Vault.open(self.path, PW, yubikey=SLOT2)
        self.assertEqual(sorted(e.title for e in again.kp.entries), ["GitHub", "Two"])
        with self.assertRaisesRegex(VaultError, "wrong master password"):
            Vault.open(self.path, PW)
        with yubikey(OTHER_SECRET), self.assertRaisesRegex(VaultError, "wrong master password"):
            Vault.open(self.path, PW, yubikey=SLOT2)

    def test_routine_saves_do_not_ask_the_key_again(self):
        v = self.make()
        with yubikey() as key:
            v.add_entry(v.root, "Two", "me", "pw2")
            v.save()
        key.assert_not_called()  # same salt, cached transformed key

    def test_key_file_and_yubikey_without_a_password(self):
        keyfile = self.tmp / "k.keyx"
        pwvault.generate_keyfile(keyfile)
        self.make(password="", keyfile=keyfile)
        with yubikey():
            v = Vault.open(self.path, "", keyfile, SLOT2)
        self.assertEqual([e.title for e in v.kp.entries], ["GitHub"])
        with self.assertRaisesRegex(VaultError, "wrong master password"):
            Vault.open(self.path, "", keyfile)

    def test_rekey_adds_changes_and_removes_the_yubikey(self):
        # Start without one.
        v = Vault.create(self.path, PW)
        v.add_entry(v.root, "GitHub", "me", "s3cret")
        v.save()
        v.save()  # a backup made with the old key
        self.assertTrue(pwvault.list_backups(self.path))
        with yubikey():
            v.rekey(PW, None, SLOT2)
            v.save()
            Vault.open(self.path, PW, yubikey=SLOT2)
        self.assertEqual(pwvault.list_backups(self.path), [])  # old-key backups purged
        with self.assertRaisesRegex(VaultError, "wrong master password"):
            Vault.open(self.path, PW)
        # Change to another YubiKey slot secret (e.g. a replacement key).
        with yubikey(OTHER_SECRET):
            v.rekey(PW, None, YubiKeySlot(1))
            v.save()
            Vault.open(self.path, PW, yubikey=YubiKeySlot(1))
        with yubikey(), self.assertRaisesRegex(VaultError, "wrong master password"):
            Vault.open(self.path, PW, yubikey=SLOT2)
        # Remove it again.
        v.rekey(PW, None, None)
        v.save()
        self.assertEqual([e.title for e in Vault.open(self.path, PW).kp.entries], ["GitHub"])

    def test_each_rekey_challenges_a_fresh_salt(self):
        v = self.make()
        first = pwvault.read_kdf_params(self.path.read_bytes())[1]["S"]
        with yubikey() as key:
            v.rekey(PW, None, SLOT2)
            v.save()
        second = pwvault.read_kdf_params(self.path.read_bytes())[1]["S"]
        self.assertNotEqual(first, second)
        key.assert_called_once_with(SLOT2, second)

    def test_restore_a_backup(self):
        v = self.make()
        with yubikey():
            v.add_entry(v.root, "Later", "me", "x")
            v.save()
            (_, backup), *_ = pwvault.list_backups(self.path)
            v.restore(backup)
            self.assertEqual([e.title for e in Vault.open(self.path, PW, yubikey=SLOT2).kp.entries],
                             ["GitHub"])

    def test_merge_with_the_same_credentials(self):
        v = self.make()
        other = self.tmp / "other.kdbx"
        shutil.copyfile(self.path, other)
        with yubikey():
            o = Vault.open(other, PW, yubikey=SLOT2)
            o.add_entry(o.root, "From other", "me", "y")
            o.save()
            kp = pwvault.open_other_copy(self.path, other, PW, None, SLOT2)
        report = pwvault.merge_vaults(v, kp)
        self.assertIn(("Root", "From other"), report.added)

    def test_no_key_never_writes(self):
        v = self.make()
        before = self.path.read_bytes()
        with patch.object(pwvault, "challenge_response",
                          side_effect=VaultError("no YubiKey found; plug it in and try again")):
            v.rekey(PW, None, SLOT2)
            with self.assertRaisesRegex(VaultError, "no YubiKey found"):
                v.save()
            with self.assertRaisesRegex(VaultError, "no YubiKey found"):
                Vault.open(self.path, PW, yubikey=SLOT2)
        self.assertEqual(self.path.read_bytes(), before)

    def test_only_kdbx4_argon2(self):
        kdbx3 = pwvault.KDBX_SIGNATURE + (1).to_bytes(2, "little") + (3).to_bytes(2, "little") + b"\x00\x00\x00"
        with self.assertRaisesRegex(VaultError, "needs a KDBX 4 vault with Argon2"):
            pwvault.load_kdbx(kdbx3, PW, None, SLOT2)
        aes = {"$UUID": bytes.fromhex("7c02bb8279a74ac0927d114a00648238"), "S": bytes(32)}
        with self.assertRaisesRegex(VaultError, "needs a KDBX 4 vault with Argon2"):
            pwvault.yubikey_transformed_key(aes, PW, None, SLOT2)

    def test_crafted_kdf_settings_give_a_clean_error(self):
        # CSO hardening (Phase 7): header values come from the file being opened.
        good = {"$UUID": bytes.fromhex("ef636ddf8c29444b91f7a9a403e30a0c"), "S": bytes(32),
                "I": 2, "M": 1 << 20, "P": 1, "V": 19}
        for bad in ({k: v for k, v in good.items() if k != "M"}, {**good, "P": 0},
                    {**good, "S": bytes(64)}, {**good, "I": b"x"},
                    {**good, "M": 8191}, {**good, "M": 16383, "P": 2},
                    {**good, "S": bytes(7)}, {**good, "S": "12345678"},
                    {**good, "S": 8}, {**good, "S": bytearray(8)},
                    {**good, "V": 0x100000000}, {**good, "V": 0},
                    {**good, "M": 0}, {**good, "I": 0}):
            with yubikey() as key, self.assertRaisesRegex(VaultError, "invalid key-derivation settings"):
                pwvault.yubikey_transformed_key(bad, PW, None, SLOT2)
            key.assert_not_called()  # rejected before the YubiKey is asked

    def test_argon2_boundary_settings_are_accepted(self):
        for version in (0x10, 0x13):
            for salt_length in (8, 63):
                with self.subTest(version=version, salt_length=salt_length):
                    params = {"$UUID": bytes.fromhex("ef636ddf8c29444b91f7a9a403e30a0c"),
                              "S": bytes(salt_length), "I": 1, "M": 16 * 1024,
                              "P": 2, "V": version}
                    with yubikey() as key:
                        result = pwvault.yubikey_transformed_key(params, PW, None, SLOT2)
                    self.assertEqual(len(result), 32)
                    key.assert_called_once_with(SLOT2, params["S"])

    def test_vaults_without_a_yubikey_never_ask(self):
        with patch.object(pwvault, "challenge_response") as key:
            v = Vault.create(self.path, PW)
            v.save()
            Vault.open(self.path, PW)
        key.assert_not_called()


class FakeYkman:
    """Stand-in for the yubikey-manager modules the driver imports, recording what it is asked."""

    def __init__(self, devices=1, configured=True, answer=b"\x01" * 20, error=None, touch=False):
        import types
        self.calls = []
        fake = self

        class Info:
            def __init__(self, serial):
                self.serial = serial

        class Conn:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        class Device:
            def open_connection(self, _kind):
                return Conn()

        class State:
            def is_configured(self, slot):
                return configured

        class Session:
            def __init__(self, conn):
                pass

            def get_config_state(self):
                return State()

            def calculate_hmac_sha1(self, slot, challenge, event=None, on_keepalive=None):
                fake.calls.append((slot, challenge))
                if touch and on_keepalive:
                    on_keepalive(2)
                if error == "timeout":
                    event.set()
                    raise RuntimeError("cancelled")
                if error:
                    raise RuntimeError(error)
                return answer

        devs = [(Device(), Info(1000 + i)) for i in range(devices)]
        self.modules = {
            "ykman": types.ModuleType("ykman"),
            "ykman.device": types.SimpleNamespace(list_all_devices=lambda: devs),
            "yubikit": types.ModuleType("yubikit"),
            "yubikit.core": types.ModuleType("yubikit.core"),
            "yubikit.core.otp": types.SimpleNamespace(OtpConnection=object),
            "yubikit.yubiotp": types.SimpleNamespace(SLOT=types.SimpleNamespace(ONE=1, TWO=2),
                                                     YubiOtpSession=Session),
        }

    def __enter__(self):
        self.patch = patch.dict("sys.modules", self.modules)
        self.patch.start()
        return self

    def __exit__(self, *a):
        self.patch.stop()


class DriverTests(unittest.TestCase):
    """challenge_response() against a stand-in for yubikey-manager (no hardware here)."""

    def test_sends_keepassxcs_block_and_returns_the_answer(self):
        with FakeYkman() as yk:
            self.assertEqual(pwvault.challenge_response(SLOT2, bytes(32)), b"\x01" * 20)
        self.assertEqual(yk.calls, [(2, bytes(32) + bytes([32]) * 32)])

    def test_serial_picks_one_of_several_keys(self):
        with FakeYkman(devices=2) as yk:
            with self.assertRaisesRegex(VaultError, r"more than one YubiKey.*--yubikey 2:1000"):
                pwvault.challenge_response(SLOT2, b"c")
            pwvault.challenge_response(YubiKeySlot(1, 1001), b"c")
        self.assertEqual(yk.calls[0][0], 1)

    def test_errors(self):
        cases = [(dict(devices=0), "no YubiKey found; plug it in"),
                 (dict(configured=False), r"slot 2 is not set up .*ykman otp chalresp --generate 2"),
                 (dict(error="timeout"), "timed out waiting for a touch"),
                 (dict(error="boom"), r"didn't answer the challenge \(boom\)")]
        for kwargs, message in cases:
            with FakeYkman(**kwargs), self.assertRaisesRegex(VaultError, message):
                pwvault.challenge_response(SLOT2, b"c")
        with FakeYkman(devices=1), self.assertRaisesRegex(VaultError, "with serial 42 found"):
            pwvault.challenge_response(YubiKeySlot(2, 42), b"c")

    def test_touch_prompt(self):
        with FakeYkman(touch=True), patch("sys.stderr") as err:
            pwvault.challenge_response(SLOT2, b"c")
        self.assertIn("Touch your YubiKey", "".join(c.args[0] for c in err.write.call_args_list))

    def test_without_yubikey_manager(self):
        with patch.dict("sys.modules", {"ykman": None, "ykman.device": None}), \
                self.assertRaisesRegex(VaultError, r"pip install 'pwvault-manager\[yubikey\]'"):
            pwvault.challenge_response(SLOT2, b"c")


class YubiKeyCliTests(Base):
    def run_cli(self, *argv, prompts=()):
        import io
        import sys
        from contextlib import redirect_stdout
        answers = iter(prompts)
        out = io.StringIO()
        with patch.object(sys, "argv", ["pwvault", "--vault", str(self.path), *argv]), \
                patch("getpass.getpass", side_effect=lambda *a, **k: next(answers)), \
                patch.object(pwvault, "copy_to_clipboard", return_value=False), \
                patch("sys.stderr"), redirect_stdout(out), yubikey():
            try:
                pwvault.main()
                code = 0
            except SystemExit as e:
                code = e.code
        return code, out.getvalue()

    def test_init_list_passwd(self):
        code, out = self.run_cli("--yubikey", "2", "init", prompts=("short", "short"))
        self.assertEqual(code, 0, out)  # a YubiKey allows a short password, like a key file
        self.assertIn("also needs YubiKey slot 2", out)
        code, out = self.run_cli("--yubikey", "2", "list", prompts=("short",))
        self.assertEqual(code, 0, out)
        code, _ = self.run_cli("list", prompts=("short",))
        self.assertRegex(str(code), "wrong master password")
        # passwd keeps the YubiKey by default, can move it to another slot, and can drop it.
        code, out = self.run_cli("--yubikey", "2", "passwd", prompts=("short", "short", "short"))
        self.assertEqual(code, 0, out)
        self.assertEqual(self.run_cli("--yubikey", "2", "list", prompts=("short",))[0], 0)
        code, out = self.run_cli("--yubikey", "2", "passwd", "--new-yubikey", "1",
                                 prompts=("short", PW, PW))
        self.assertIn("needs YubiKey slot 1", out)
        self.assertEqual(self.run_cli("--yubikey", "1", "list", prompts=(PW,))[0], 0)
        code, out = self.run_cli("--yubikey", "1", "passwd", "--no-yubikey", prompts=(PW, PW, PW))
        self.assertEqual(code, 0, out)
        self.assertEqual(self.run_cli("list", prompts=(PW,))[0], 0)

    def test_merge_same_credentials_includes_the_yubikey(self):
        self.run_cli("--yubikey", "2", "init", prompts=(PW, PW))
        other = self.tmp / "other.kdbx"
        shutil.copyfile(self.path, other)
        with yubikey():
            o = Vault.open(other, PW, yubikey=SLOT2)
            o.add_entry(o.root, "From other", "me", "y")
            o.save()
        code, out = self.run_cli("--yubikey", "2", "merge", str(other), "--same-credentials", prompts=(PW,))
        self.assertEqual(code, 0, out)
        self.assertIn("+ Root/From other", out)
        code, _ = self.run_cli("--yubikey", "2", "merge", str(other), "--same-credentials",
                               "--other-yubikey", "1", prompts=(PW,))
        self.assertRegex(str(code), "not both")

    def test_bad_slot_argument(self):
        code, _ = self.run_cli("--yubikey", "3", "list")
        self.assertEqual(code, 2)  # argparse usage error


class SlotParsingTests(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(YubiKeySlot.parse("2"), YubiKeySlot(2))
        self.assertEqual(YubiKeySlot.parse("1:12345678"), YubiKeySlot(1, 12345678))
        self.assertEqual(str(YubiKeySlot(1, 12345678)), "1:12345678")
        for bad in ("3", "0", "two", "2:abc", ""):
            with self.assertRaises(VaultError, msg=bad):
                YubiKeySlot.parse(bad)


if __name__ == "__main__":
    unittest.main()
