---
name: run-password-vault
description: Build, run, and drive pwvault (the password-vault CLI and Tk GUI). Use when asked to start or run pwvault, launch its GUI, take a screenshot of it, click through it, exercise the CLI, or run its tests.
---

pwvault is a KeePass-file password manager with a CLI (`pwvault.py`) and a Tkinter GUI
(`pwvault_gui.py`). Drive both with `.claude/skills/run-password-vault/driver.sh`: the GUI
runs on Xvfb + openbox and is driven with xdotool and screenshotted with ImageMagick; the CLI
gets its password prompts on stdin. All paths are relative to the repo root.

## Prerequisites

Ubuntu (24.04 container). `python3-tk` from apt only provides tkinter for the distro Python
(3.12); if the default `python3` is a different version (3.13 here) it has no tkinter, so
install the deps into 3.12 as well:

```bash
apt-get update
apt-get install -y python3-tk xvfb openbox xdotool imagemagick tmux fonts-dejavu-core fonts-noto-color-emoji
python3.12 -m pip install --break-system-packages -r requirements.txt
pip install -r requirements.txt   # for the default python3, used by the CLI path
```

No build step.

## Run (agent path): GUI

```bash
D=.claude/skills/run-password-vault/driver.sh
printf 'correct horse battery\ncorrect horse battery\n' | $D cli --vault /tmp/pwv-demo/vault.kdbx init
$D start /tmp/pwv-demo/vault.kdbx          # Xvfb :99 + openbox + GUI, focused at 0,0
$D ss unlock                               # -> /tmp/pwvault-shots/unlock.png
$D type 'correct horse battery'; $D key Return; sleep 4   # Argon2 unlock takes a moment
$D key ctrl+n; $D focus "Add entry"        # new-entry dialog; cursor starts in Title
$D type 'Typed via driver'; $D key Tab; $D type 'drv'; $D key Tab; $D type 'pw-123456789'
$D key Return; sleep 3                     # Return saves the dialog
$D ss saved
$D click 983 46; $D key Down Down Right; $D ss export-menu   # Database menu > Export submenu
$D key Escape Escape
$D log                                     # GUI stderr: tracebacks show up here
$D stop
```

Read the screenshots (`/tmp/pwvault-shots/*.png`) to check the result. A blank or black frame
means the GUI didn't come up; check `$D log`.

| command | what it does |
|---|---|
| `start [VAULT]` | start Xvfb, openbox and the GUI on VAULT (default `$PWVAULT_PATH` or `~/.local/share/pwvault/vault.kdbx`); a missing file opens the create-vault screen |
| `focus NAME` | raise and focus the window titled NAME (`pwvault`, `Add entry`, `Edit entry`, `Export`, ...) and print its geometry |
| `type TEXT` / `key KEYS...` | type into / send keys (`Return`, `Tab`, `ctrl+n`, `ctrl+l`, `Escape`) to the focused widget |
| `click X Y` | left-click at screen coordinates (same coordinates as the screenshots) |
| `ss NAME` | screenshot the whole screen to `/tmp/pwvault-shots/NAME.png` |
| `windows` | list visible windows: id, position, size, title |
| `log` / `stop` | show GUI output / tear everything down |

Useful screen coordinates with the main window at 0,0 (1280x720 screen, openbox title bar ~20px):
search box (150,46), `+ Add` (733,46), `Generator` (858,46), `Database ▾` (983,46),
`Lock` (1108,46), group tree from (180,85), entry list from (600,108), detail-panel
`Edit` / `History` / `Delete` along y=593.

## Run (agent path): CLI

`driver.sh cli ARGS` runs `pwvault.py ARGS` under `setsid`, so every prompt (master password
first, then any `input()` questions) is read from stdin, one line each:

```bash
D=.claude/skills/run-password-vault/driver.sh; V=/tmp/pwv-demo/vault.kdbx
printf 'correct horse battery\nGitHub\nhttps://github.com\nme\n' | $D cli --vault $V add -g --group Work
echo 'correct horse battery' | $D cli --vault $V list
echo 'correct horse battery' | $D cli --vault $V get github --show
echo 'correct horse battery' | $D cli --vault $V export csv /tmp/pwv-demo/out.csv
```

For an interactive terminal session instead, use tmux: `tmux new-session -d -s pw` and
`send-keys` / `capture-pane`; getpass then reads the tmux pty normally.

## Direct invocation

Most changes touch `pwvault.py` internals; import it and call it:

```bash
python3 - <<'EOF'
import tempfile
from pathlib import Path
import pwvault
p = Path(tempfile.mkdtemp()) / "v.kdbx"
v = pwvault.Vault.create(p, "correct horse battery")
v.add_entry(v.root, 'Say "hi"', "me", "-pw")
v.save()
v = pwvault.Vault.open(p, "correct horse battery")
print([(e.title, e.password) for e in v.entries(query="hi")])
pwvault.export(v, p.with_suffix(".csv"), "csv")
print(p.with_suffix(".csv").read_text().splitlines()[1])
EOF
```

## Run (human path)

```bash
python3 pwvault_gui.py [VAULT]   # opens a window; useless headless
python3 pwvault.py --help
```

## Test

```bash
xvfb-run -a python3.12 -m unittest discover -s tests   # 50 tests, ~50 s, GUI included
python3 -m unittest discover -s tests                  # without tkinter: GUI tests skip
```

Slow because every vault create/open runs Argon2.

## Gotchas

- **Without a window manager, keyboard input gets lost.** On bare Xvfb the input focus is
  PointerRoot; Tk never gets FocusIn, so typed text goes nowhere and clicks can land on stale
  dialogs (four stacked "Add entry" windows in one run). The driver starts openbox; keep it.
- **Screenshot coordinates include openbox's title bar.** The window is moved to 0,0, but its
  content starts ~20px down. `xdotool windowmove` targets the frame, and `windows` reports the
  client area (`2,40` here), so take clicks from the screenshots, not from `windows`.
- **Database ▾ is a Tk popup menu.** Click it, then navigate with `key Down ... Right/Return`
  rather than clicking menu items, which is less reliable.
- **Don't `pkill -f pwvault_gui` from a Bash tool call.** Your own shell's command line
  contains that string, so pkill kills the shell (exit 144). Use `driver.sh stop`. The same
  bit the driver once: a pasted comment mentioning `Xvfb :99` matched its own `pkill -f`, so
  its pattern is now anchored (`^Xvfb :99`). Keep it anchored.
- **The CLI's getpass reads `/dev/tty`, not stdin.** Piping a password works only after
  `setsid` drops the controlling terminal, which `driver.sh cli` does. Expect a
  `GetPassWarning: Can not control echo` on stderr; it's harmless.
- **No clipboard tool in the container.** `get` prints "No clipboard tool found"; use
  `--show`. The GUI falls back to Tk's own clipboard.
- **GUI's Python vs CLI's Python.** The driver picks the first Python with both tkinter and
  pykeepass for the GUI (3.12 here; override with `PWV_PYTHON`); `cli` uses plain `python3`.

## Troubleshooting

- **`ModuleNotFoundError: No module named 'tkinter'`**: the default `python3` (3.13) has no Tk;
  `apt-get install python3-tk` only covers 3.12. Run GUI code and GUI tests with `python3.12`.
- **`driver: no window named 'pwvault' after 20s`**: the GUI crashed at startup; `$D log`
  shows the traceback (usually missing pykeepass in the GUI's Python).
- **Typed text doesn't appear in a dialog**: the dialog isn't focused; run
  `$D focus "<dialog title>"` before `type`.
