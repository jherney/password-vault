# Regression: ISSUE-002 — aborting at the password prompt left a new key file behind
# Found by /qa on 2026-10-28
# Report: .gstack/qa-reports/qa-report-pwvault-cli-2026-10-28.md
"""Run: python3 -m unittest discover -s tests"""

import sys
import unittest
from unittest.mock import patch

from test_pwvault import PW, Base, pwvault


class NewKeyfileAbortTests(Base):
    def run_cli(self, *argv, prompts):
        with patch.object(sys, "argv", ["pwvault", "--vault", str(self.path), *argv]), \
                patch("getpass.getpass", side_effect=prompts), self.assertRaises(SystemExit) as cm:
            pwvault.main()
        return cm.exception.code

    def test_aborted_init_leaves_no_key_file(self):
        keyfile = self.tmp / "new.key"
        self.assertEqual(self.run_cli("init", "--new-keyfile", str(keyfile), prompts=EOFError), "\nAborted.")
        self.assertFalse(keyfile.exists())
        self.assertFalse(self.path.exists())

    def test_aborted_passwd_leaves_no_key_file(self):
        self.new_vault()
        keyfile = self.tmp / "new.key"
        self.assertEqual(self.run_cli("passwd", "--new-keyfile", str(keyfile), prompts=[PW, EOFError]),
                         "\nAborted.")
        self.assertFalse(keyfile.exists())
        self.reopen()  # old master key still works


if __name__ == "__main__":
    unittest.main()
