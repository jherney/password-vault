"""Offline breach check (Phase 8): the local HIBP store, its download and import, and `pwvault check`.

No test touches the network: downloads use a fake fetcher, and the check runs with sockets disabled.
Run: python3 -m unittest discover -s tests -p test_breach.py
"""

import gzip
import hashlib
import io
import os
import random
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import pwvault  # noqa: E402
from pwvault import BreachStore, Vault, VaultError  # noqa: E402

PW = "correct horse battery staple"
BREACHED = "Tr0ub4dor&3-but-it-leaked"  # strong by strength(), so only "breached" applies
SHARED = "Sh4red-by-two-entries!Q9"
WEAK = "abc123"


def sha1(password: str) -> str:
    return hashlib.sha1(password.encode()).hexdigest().upper()


def http_503():
    raise urllib.error.HTTPError(pwvault.PWNED_API + "0000A", 503, "busy", None, None)


def same_prefix_other(password: str) -> str:
    """A hash in the same range as `password`'s that differs in the stored bytes."""
    h = sha1(password)
    return h[:5] + ("0" if h[5] != "0" else "1") + h[6:]


class BreachBase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.dir.name)
        for p in (patch.dict(os.environ, {"XDG_CACHE_HOME": str(self.tmp / "cache")}),
                  patch.object(pwvault, "PWNED_MIN_FREE", 0),
                  patch.object(pwvault.time, "sleep")):  # retry backoff
            p.start()
            self.addCleanup(p.stop)

    def tearDown(self):
        self.dir.cleanup()

    def import_hashes(self, hashes, counts=None) -> int:
        f = self.tmp / "list.txt"
        f.write_text("".join(f"{h}:{(counts or {}).get(h, 7)}\r\n" for h in sorted(hashes)))
        return pwvault.import_breach_list(f)

    def store_files(self) -> dict:
        live = Path(os.path.realpath(pwvault.breach_dir() / "current"))
        return {n: (live / n).read_bytes() for n in ("hashes.bin", "index.bin")}


class SmallRanges(BreachBase):
    """64 ranges in batches of 8, with made-up hashes, so a whole download takes milliseconds."""

    RANGES, BATCH = 64, 8

    def setUp(self):
        super().setUp()
        for p in (patch.object(pwvault, "PWNED_RANGES", self.RANGES),
                  patch.object(pwvault, "PWNED_BATCH", self.BATCH)):
            p.start()
            self.addCleanup(p.stop)
        rng = random.Random(8)
        self.api = {}
        for r in range(self.RANGES):
            suffixes = sorted({"".join(rng.choice("0123456789ABCDEF") for _ in range(35))
                               for _ in range(rng.randrange(1, 6))})
            self.api[f"{r:05X}"] = "".join(f"{s}:{rng.randrange(1, 99)}\r\n" for s in suffixes)
        self.fetched = []

    def fetch(self, prefix):
        self.fetched.append(prefix)
        return self.api[prefix].encode()

    def all_hashes(self):
        return [p + line.split(":")[0] for p, body in self.api.items() for line in body.split()]


class StoreTests(BreachBase):
    def test_import_then_lookup(self):
        n = self.import_hashes([sha1("password1"), sha1("123456"), same_prefix_other("hunter2")])
        self.assertEqual(n, 3)
        with BreachStore() as store:
            self.assertTrue(store.contains("password1"))
            self.assertTrue(store.contains("123456"))
            self.assertFalse(store.contains("not in the list"))
            self.assertFalse(store.contains("hunter2"))  # same range, different hash
        live = Path(os.path.realpath(pwvault.breach_dir() / "current"))
        self.assertTrue(live.is_relative_to(self.tmp / "cache" / "pwvault" / "pwned"))

    def test_store_defaults_to_the_cache_dir(self):
        with patch.dict(os.environ, {"XDG_CACHE_HOME": ""}), patch.object(Path, "home", return_value=Path("/h")):
            self.assertEqual(pwvault.breach_dir(), Path("/h/.cache/pwvault/pwned"))

    def test_zero_count_lines_are_not_stored(self):
        self.import_hashes([sha1("password1"), sha1("pad")], counts={sha1("pad"): 0})
        with BreachStore() as store:
            self.assertTrue(store.contains("password1"))
            self.assertFalse(store.contains("pad"))

    def test_lookup_reads_one_range_only(self):
        self.import_hashes([sha1("password1"), same_prefix_other("password1"), sha1("123456")])
        reads = []
        real = os.pread

        def pread(fd, n, offset):
            reads.append(n)
            return real(fd, n, offset)
        with BreachStore() as store, patch.object(pwvault.os, "pread", pread):
            self.assertTrue(store.contains("password1"))
        self.assertEqual(reads, [16, 2 * pwvault.PWNED_RECORD])  # two offsets, then this range's 2 records

    def test_import_rejects_bad_or_unsorted_lines(self):
        low, high = sorted((sha1("a"), sha1("b")))
        for text in (f"{high}:1\n{low}:1\n", f"{low}:1\nnot a hash\n"):
            f = self.tmp / "bad.txt"
            f.write_text(text)
            with self.assertRaisesRegex(VaultError, "line 2 is not a HASH:COUNT line in hash order"):
                pwvault.import_breach_list(f)
        self.assertFalse((pwvault.breach_dir() / "current").exists())

    def test_missing_and_damaged_store(self):
        with self.assertRaisesRegex(VaultError, "no breach list yet"):
            BreachStore()
        self.import_hashes([sha1("password1")])
        live = Path(os.path.realpath(pwvault.breach_dir() / "current"))
        with open(live / "hashes.bin", "ab") as f:
            f.write(b"x")
        with self.assertRaisesRegex(VaultError, "damaged"):
            BreachStore()

    def test_old_store_answers_until_a_rebuild_finishes(self):
        self.import_hashes([sha1("password1")])

        def stop(prefix):
            raise KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            pwvault.update_breach_list(stop)
        self.assertTrue((pwvault.breach_dir() / "partial").exists())
        with BreachStore() as store:
            self.assertTrue(store.contains("password1"))
            self.import_hashes([sha1("123456")])  # swaps stores under the open one
            self.assertTrue(store.contains("password1"))  # the open store still reads its own files
        with BreachStore() as store:
            self.assertFalse(store.contains("password1"))
            self.assertTrue(store.contains("123456"))
        self.assertEqual(len(list(pwvault.breach_dir().glob("store-*"))), 1)  # the old one removed

    def test_too_little_disk_space(self):
        free = type("Usage", (), {"free": 1 << 30})()
        with patch.object(pwvault, "PWNED_MIN_FREE", 16 << 30), \
                patch.object(pwvault.shutil, "disk_usage", return_value=free), \
                self.assertRaisesRegex(VaultError, r"needs about 16 GB free .*\(1\.0 GB free\)"):
            pwvault.update_breach_list(lambda p: self.fail("fetched despite no space"))


class FetchTests(unittest.TestCase):
    """fetch_range() against a stand-in for urlopen: what it asks for and how it reads the reply."""

    def reply(self, body, encoding=""):
        class Reply(io.BytesIO):
            headers = {"Content-Encoding": encoding} if encoding else {}

            def __exit__(self, *exc):
                self.close()
        return Reply(body)

    def test_asks_for_gzip_and_unpacks_it(self):
        body = b"0" * 35 + b":3\r\n"
        for reply, encoding in ((gzip.compress(body), "gzip"), (body, "")):
            with self.subTest(encoding=encoding or "none"), \
                    patch.object(pwvault.urllib.request, "urlopen", return_value=self.reply(reply, encoding)) as op:
                self.assertEqual(pwvault.fetch_range("0A1B2"), body)
                req = op.call_args.args[0]
                self.assertEqual(req.full_url, "https://api.pwnedpasswords.com/range/0A1B2")
                self.assertEqual(req.get_header("Accept-encoding"), "gzip")
                self.assertTrue(req.get_header("User-agent").startswith("pwvault-manager/"))

    def test_damaged_gzip_is_an_error(self):
        with patch.object(pwvault.urllib.request, "urlopen", return_value=self.reply(b"not gzip", "gzip")), \
                self.assertRaisesRegex(VaultError, "range 0A1B2 arrived damaged"):
            pwvault.fetch_range("0A1B2")


class DownloadTests(SmallRanges):
    def test_download_matches_import_byte_for_byte(self):
        n = pwvault.update_breach_list(self.fetch)
        downloaded = self.store_files()
        self.assertEqual(n, len(self.all_hashes()))
        self.assertEqual(sorted(self.fetched), sorted(self.api))
        self.assertEqual(self.import_hashes(self.all_hashes(), {h: 1 for h in self.all_hashes()}), n)
        self.assertEqual(self.store_files(), downloaded)

    def test_ranges_in_any_order_are_stored_sorted(self):
        api = dict(self.api)
        self.api = {p: "".join(reversed(body.splitlines(keepends=True))) for p, body in api.items()}
        pwvault.update_breach_list(self.fetch)
        reversed_order = self.store_files()
        self.api = api
        pwvault.update_breach_list(self.fetch)
        self.assertEqual(self.store_files(), reversed_order)

    def test_bad_ranges_are_retried(self):
        broken = iter([b"garbage\r\n", OSError("connection reset")])

        def flaky(prefix):
            if prefix == "00005":
                try:
                    item = next(broken)
                except StopIteration:
                    return self.fetch(prefix)
                if isinstance(item, Exception):
                    raise item
                return item
            return self.fetch(prefix)
        self.assertEqual(pwvault.update_breach_list(flaky), len(self.all_hashes()))

    def test_ranges_that_stay_bad_fail_the_update(self):
        cases = {
            "malformed": lambda: b"XYZ:1\r\n",
            "duplicate": lambda: b"F" * 35 + b":1\r\n" + b"F" * 35 + b":2\r\n",
            "empty": lambda: b"",
            "only padding": lambda: b"F" * 35 + b":0\r\n",
            "http error": http_503,
        }
        for name, bad in cases.items():
            with self.subTest(name):
                tries = []

                def fetch(prefix):
                    if prefix == "0000A":
                        tries.append(prefix)
                        return bad()
                    return self.fetch(prefix)
                with self.assertRaisesRegex(VaultError, "range 0000A"):
                    pwvault.update_breach_list(fetch)
                self.assertEqual(len(tries), pwvault.PWNED_TRIES)
                self.assertFalse((pwvault.breach_dir() / "current").exists())

    def test_interrupted_download_resumes_after_the_last_finished_batch(self):
        def interrupt_in_third_batch(prefix):
            if prefix == "00013":  # range 19, in the batch of ranges 16-23
                raise KeyboardInterrupt
            return self.fetch(prefix)
        with self.assertRaises(KeyboardInterrupt):
            pwvault.update_breach_list(interrupt_in_third_batch)
        self.assertFalse((pwvault.breach_dir() / "current").exists())
        self.fetched.clear()
        n = pwvault.update_breach_list(self.fetch)
        self.assertEqual(min(int(p, 16) for p in self.fetched), 16)  # batches 0-15 not fetched again
        resumed = self.store_files()
        self.import_hashes(self.all_hashes())
        self.assertEqual(self.store_files(), resumed)
        self.assertEqual(n, len(self.all_hashes()))

    def test_a_crash_mid_batch_is_cut_back_on_resume(self):
        pwvault.update_breach_list(self.fetch)
        expected = self.store_files()
        partial = pwvault.breach_dir() / "partial"
        build = pwvault._BreachBuild(pwvault.breach_dir(), fresh=True)
        build.append(pwvault.parse_range(self.api[f"{r:05X}"].encode(), f"{r:05X}") for r in range(self.BATCH))
        build.close()
        with open(partial / "hashes.bin", "ab") as f:  # records written, index not: a crash here
            f.write(b"\xff" * pwvault.PWNED_RECORD * 3)
        with open(partial / "index.bin", "ab") as f:
            f.write(b"\x01\x02\x03")  # half an offset
        pwvault.update_breach_list(self.fetch)
        self.assertEqual(self.store_files(), expected)


class CheckTests(BreachBase):
    def make_vault(self):
        path = self.tmp / "vault.kdbx"
        v = Vault.create(path, PW)
        work = v.add_group(v.root, "Work")
        v.add_entry(v.root, "Leaked site", "me", BREACHED, "https://leaked.example")
        v.add_entry(work, "Mail", "me@work", SHARED)
        v.add_entry(v.root, "Forum", "me", SHARED)
        v.add_entry(v.root, "Router", "admin", WEAK)
        v.add_entry(v.root, "Bank", "me", pwvault.generate_password(24))
        v.add_entry(v.root, "Bookmark", "", "")
        old = v.add_entry(v.root, "Old leaked", "me", BREACHED + "-old")
        v.delete_entry(old)
        v.save()
        return path

    def test_check_vault_findings(self):
        path = self.make_vault()
        self.import_hashes([sha1(BREACHED), sha1(BREACHED + "-old")])
        v = Vault.open(path, PW)
        with BreachStore() as store:
            found = {f.entry.title: (f.issues, sorted(o.title for o in f.reused_with))
                     for f in pwvault.check_vault(v, store)}
        self.assertEqual(found, {
            "Leaked site": (["breached"], []),
            "Mail": (["reused"], ["Forum"]),
            "Forum": (["reused"], ["Mail"]),
            "Router": (["weak"], []),
        })
        self.assertEqual(len(pwvault.checked_entries(v)), 5)

    def run_check(self, path) -> str:
        out = io.StringIO()
        with patch.object(sys, "argv", ["pwvault", "--vault", str(path), "check"]), \
                patch("getpass.getpass", return_value=PW), patch("sys.stdout", out):
            pwvault.main()
        return out.getvalue()

    def test_cli_check_with_store_and_no_network(self):
        path = self.make_vault()
        self.import_hashes([sha1(BREACHED)])
        with patch("socket.socket", side_effect=OSError("network used during check")):
            out = self.run_check(path)
        self.assertIn("Leaked site  (me)  in Root\n  breached\n", out)
        self.assertIn("Mail  (me@work)  in Root/Work\n  reused; same password as: Forum\n", out)
        self.assertIn("Router  (admin)  in Root\n  weak\n", out)
        self.assertIn("4 of 5 entries flagged (1 breached, 2 reused, 1 weak)", out)
        for absent in ("Bank", "Bookmark", "Old leaked", "not checked"):
            self.assertNotIn(absent, out)
        for secret in (BREACHED, SHARED, WEAK, PW):
            self.assertNotIn(secret, out)

    def test_cli_check_without_store(self):
        path = self.make_vault()
        with patch("socket.socket", side_effect=OSError("network used during check")):
            out = self.run_check(path)
        self.assertNotIn("Leaked site", out)
        self.assertIn("3 of 5 entries flagged (0 breached, 2 reused, 1 weak)", out)
        self.assertIn("Breached passwords not checked: no breach list yet — run `pwvault breach update`", out)

    def run_breach(self, *argv) -> str:
        out = io.StringIO()
        with patch.object(sys, "argv", ["pwvault", "breach", *argv]), patch("sys.stdout", out), \
                patch("sys.stderr", io.StringIO()):
            try:
                pwvault.main()
            except SystemExit as e:
                out.write(str(e.code))
        return out.getvalue()

    def test_breach_import_and_status_commands(self):
        self.assertIn("no breach list yet", self.run_breach("status"))
        f = self.tmp / "list.txt"
        f.write_text(f"{sha1('password1')}:9\n")
        self.assertIn("Breach list ready: 1 password hashes.", self.run_breach("import", str(f)))
        status = self.run_breach("status")
        self.assertIn("Breach list: 1 password hashes, completed ", status)
        self.assertIn(str(pwvault.breach_dir()), status)
        self.assertIn("needs the hash list file", self.run_breach("import"))
        self.assertIn("takes no file", self.run_breach("update", str(f)))


if __name__ == "__main__":
    unittest.main()
