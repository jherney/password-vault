# Regression: ISSUE-001 — export overwrote the vault file or its key file with plaintext
# Found by /qa on 2026-10-28
# Report: .gstack/qa-reports/qa-report-pwvault-cli-2026-10-28.md
"""Run: python3 -m unittest discover -s tests"""

import unittest

from test_pwvault import PW, Base, pwvault
from pwvault import VaultError


class ExportTargetTests(Base):
    def test_export_refuses_the_vault_file(self):
        v = self.new_vault()
        link = self.tmp / "link.csv"
        link.symlink_to(self.path)
        for target in (self.path, link, self.tmp / "." / "vault.kdbx"):
            with self.subTest(target=target), self.assertRaises(VaultError):
                pwvault.export(v, target, "csv")
        self.assertEqual(self.reopen().entries(query="github")[0].password, "s3cret")

    def test_export_refuses_the_key_file(self):
        keyfile = self.tmp / "vault.key"
        pwvault.generate_keyfile(keyfile)
        key = keyfile.read_bytes()
        v = self.new_vault(keyfile=keyfile)
        with self.assertRaises(VaultError):
            pwvault.export(v, keyfile, "txt")
        self.assertEqual(keyfile.read_bytes(), key)
        self.reopen(keyfile=keyfile)  # still unlocks


if __name__ == "__main__":
    unittest.main()
