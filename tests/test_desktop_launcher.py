"""Tests for the per-user desktop launcher. Run: python3 -m unittest discover -s tests"""

import configparser
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import pwvault_gui  # noqa: E402


class DesktopLauncherTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.home = Path(self.dir.name)
        # XDG_DATA_HOME would override the temp home, so clear it for these tests.
        env = patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("XDG_DATA_HOME", None)

    def tearDown(self):
        self.dir.cleanup()

    def entry(self, path):
        cp = configparser.ConfigParser(interpolation=None)
        cp.read(path, encoding="utf-8")
        return cp["Desktop Entry"]

    def test_install_writes_a_valid_desktop_entry_and_icon(self):
        with patch("shutil.which", return_value="/opt/bin/pwvault-gui"):
            desktop, icon = pwvault_gui.install_launcher(self.home)
        self.assertTrue(desktop.is_file() and icon.is_file())
        self.assertEqual(desktop, self.home / ".local/share/applications/pwvault.desktop")
        self.assertEqual(icon, self.home / ".local/share/icons/hicolor/scalable/apps/pwvault.svg")
        e = self.entry(desktop)
        self.assertEqual(e["Type"], "Application")
        self.assertEqual(e["Name"], "pwvault")
        self.assertEqual(e["Icon"], "pwvault")
        self.assertIn("Utility", e["Categories"].split(";"))
        self.assertIn("Security", e["Categories"].split(";"))
        self.assertIn("<svg", icon.read_text())

    def test_exec_is_the_absolute_path_when_found(self):
        with patch("shutil.which", return_value="/opt/bin/pwvault-gui"):
            desktop, _ = pwvault_gui.install_launcher(self.home)
        self.assertEqual(self.entry(desktop)["Exec"], "/opt/bin/pwvault-gui")

    def test_exec_falls_back_to_the_bare_name_and_quotes_spaces(self):
        with patch("shutil.which", return_value=None):
            desktop, _ = pwvault_gui.install_launcher(self.home)
        self.assertEqual(self.entry(desktop)["Exec"], "pwvault-gui")
        with patch("shutil.which", return_value="/opt/my apps/pwvault-gui"):
            desktop, _ = pwvault_gui.install_launcher(self.home)
        self.assertEqual(self.entry(desktop)["Exec"], '"/opt/my apps/pwvault-gui"')

    def test_reinstall_is_identical_and_leaves_other_files_alone(self):
        apps = self.home / ".local/share/applications"
        apps.mkdir(parents=True)
        other = apps / "other.desktop"
        other.write_text("keep me")
        desktop, icon = pwvault_gui.install_launcher(self.home)
        first = (desktop.read_bytes(), icon.read_bytes())
        pwvault_gui.install_launcher(self.home)
        self.assertEqual((desktop.read_bytes(), icon.read_bytes()), first)
        self.assertEqual(other.read_text(), "keep me")
        self.assertEqual(sorted(p.name for p in apps.iterdir()), ["other.desktop", "pwvault.desktop"])

    def test_uninstall_removes_only_pwvault_files(self):
        apps = self.home / ".local/share/applications"
        apps.mkdir(parents=True)
        (apps / "other.desktop").write_text("keep me")
        pwvault_gui.install_launcher(self.home)
        removed = pwvault_gui.uninstall_launcher(self.home)
        self.assertEqual(len(removed), 2)
        self.assertFalse(any(p.exists() for p in removed))
        self.assertEqual((apps / "other.desktop").read_text(), "keep me")

    def test_uninstall_when_absent_removes_nothing(self):
        self.assertEqual(pwvault_gui.uninstall_launcher(self.home), [])

    def test_xdg_data_home_is_honoured(self):
        with patch.dict(os.environ, {"XDG_DATA_HOME": str(self.home / "xdg")}):
            desktop, _ = pwvault_gui.install_launcher(self.home)
        self.assertEqual(desktop, self.home / "xdg/applications/pwvault.desktop")


if __name__ == "__main__":
    unittest.main()
