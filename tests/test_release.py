"""Keeps the version the app reports and the top CHANGELOG.md entry in step.
Run: python3 -m unittest discover -s tests
"""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import pwvault  # noqa: E402

CHANGELOG = Path(__file__).resolve().parent.parent / "CHANGELOG.md"


class ReleaseTests(unittest.TestCase):
    def test_top_changelog_entry_is_the_app_version(self):
        headings = re.findall(r"^## \[(\d+\.\d+\.\d+)\]", CHANGELOG.read_text(), re.MULTILINE)
        self.assertTrue(headings, "CHANGELOG.md has no version entries")
        self.assertEqual(headings[0], pwvault.__version__)


if __name__ == "__main__":
    unittest.main()
