"""Regression tests from the 04-03 GUI QA pass. Run under xvfb:
xvfb-run -a python3 -m unittest discover -s tests -v
"""

import unittest
from unittest.mock import patch

from test_pwvault import Base, display_available


@unittest.skipUnless(display_available(), "needs a display; run under xvfb-run")
class QuitTimerTests(Base):
    def setUp(self):
        super().setUp()
        import pwvault_gui
        self.gui = pwvault_gui
        self.new_vault()
        self.app = pwvault_gui.App(self.path)
        self.app.vault = self.reopen()
        self.app.show_main()
        self.app.root.update()

    def pending_jobs(self):
        return self.app.root.tk.splitlist(self.app.root.tk.call("after", "info"))

    # Regression: closing the window while the idle-lock or clipboard-clear timer was pending left
    # the timer scheduled, so it fired into the destroyed interpreter ("invalid command name
    # auto_lock" in the test output). quit() must cancel both timers before destroying the window.
    def test_quit_cancels_pending_lock_and_clipboard_timers(self):
        self.app.touch()                 # arms the idle-lock timer
        self.app.clip_job = self.app.root.after(60_000, self.app.clear_clipboard)
        self.assertTrue(self.app.lock_job)
        with patch.object(self.app.root, "destroy"):
            self.app.quit()
        self.assertEqual(self.pending_jobs(), ())

    def tearDown(self):
        if self.app.root.winfo_exists():
            self.app.root.destroy()
        super().tearDown()


if __name__ == "__main__":
    unittest.main()
