#!/usr/bin/env bash
# Drive pwvault headlessly: the Tk GUI on Xvfb + openbox (xdotool for input, ImageMagick for
# screenshots), and the CLI with prompts fed on stdin. Run from the repo root.
# Usage: driver.sh <command> [args]   (see `driver.sh help`)
set -euo pipefail

DISPLAY_NUM="${PWV_DISPLAY:-:99}"
SESSION="${PWV_TMUX:-pwv-gui}"
SHOTS="${PWV_SHOTS:-/tmp/pwvault-shots}"
LOG="${PWV_LOG:-/tmp/pwvault-gui.log}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
export DISPLAY="$DISPLAY_NUM"

die() { echo "driver: $*" >&2; exit 1; }

# The GUI needs a Python that has both tkinter and pykeepass; on Ubuntu the apt python3-tk
# package only covers the distro Python (3.12), not e.g. a separately installed 3.13.
pick_python() {
  for py in ${PWV_PYTHON:-} python3 python3.12 python3.13 python3.11 python3.10; do
    command -v "$py" >/dev/null 2>&1 || continue
    "$py" -c "import tkinter, pykeepass" >/dev/null 2>&1 && { echo "$py"; return; }
  done
  die "no Python with both tkinter and pykeepass; see Prerequisites in SKILL.md"
}

wait_window() {  # wait_window NAME [TIMEOUT_S] -> prints the window id
  local name="$1" t="${2:-20}" id
  for _ in $(seq 1 $((t * 4))); do
    id=$(xdotool search --name "$name" 2>/dev/null | tail -1 || true)
    [ -n "$id" ] && { echo "$id"; return; }
    sleep 0.25
  done
  die "no window named '$name' after ${t}s (GUI log: $LOG)"
}

cmd="${1:-help}"; shift || true
case "$cmd" in
  start)  # start [VAULT]: Xvfb + openbox + GUI; main window at 0,0 and focused
    vault="${1:-${PWVAULT_PATH:-$HOME/.local/share/pwvault/vault.kdbx}}"
    py=$(pick_python)
    tmux kill-session -t "$SESSION" 2>/dev/null || true
    pkill -f "^Xvfb $DISPLAY_NUM( |$)" 2>/dev/null || true  # anchored: never match a caller shell
    sleep 0.5
    tmux new-session -d -s "$SESSION" "Xvfb $DISPLAY_NUM -screen 0 1280x720x24"
    for _ in $(seq 1 40); do xdotool getdisplaygeometry >/dev/null 2>&1 && break; sleep 0.25; done
    tmux new-window -t "$SESSION" "DISPLAY=$DISPLAY_NUM openbox"
    sleep 1
    tmux new-window -t "$SESSION" "cd '$REPO' && DISPLAY=$DISPLAY_NUM $py pwvault_gui.py '$vault' 2>&1 | tee '$LOG'"
    id=$(wait_window pwvault)
    xdotool windowmove "$id" 0 0
    xdotool windowactivate --sync "$id"
    echo "started: window $id, vault $vault, python $py"
    ;;
  focus)  # focus NAME: raise and focus a window by title (e.g. "Add entry", pwvault)
    id=$(wait_window "${1:?window name}" 10)
    xdotool windowactivate --sync "$id"
    eval "$(xdotool getwindowgeometry --shell "$id")"
    echo "focused $id at $X,$Y size ${WIDTH}x$HEIGHT"
    ;;
  type)   # type TEXT: type into the focused widget
    xdotool type --delay 20 "${1:?text}"
    ;;
  key)    # key KEYS...: e.g. Return, Tab, ctrl+n, ctrl+l
    xdotool key "$@"; sleep 0.3
    ;;
  click)  # click X Y: left-click at screen coordinates (main window sits at 0,0)
    xdotool mousemove "${1:?x}" "${2:?y}" click 1; sleep 0.3
    ;;
  ss)     # ss NAME: full-screen screenshot -> $SHOTS/NAME.png
    mkdir -p "$SHOTS"
    sleep 0.5
    import -window root "$SHOTS/${1:?name}.png"
    echo "$SHOTS/$1.png"
    ;;
  windows)  # list visible top-level windows: id, geometry, title
    for id in $(xdotool search --onlyvisible --name . 2>/dev/null); do
      name=$(xdotool getwindowname "$id" 2>/dev/null || true)
      [ -n "$name" ] || continue
      eval "$(xdotool getwindowgeometry --shell "$id")"
      echo "$id ${X},${Y} ${WIDTH}x${HEIGHT} $name"
    done
    ;;
  log)    # print the GUI's stdout/stderr (tracebacks land here)
    cat "$LOG" 2>/dev/null || true
    ;;
  stop)
    tmux kill-session -t "$SESSION" 2>/dev/null || true
    pkill -f "^Xvfb $DISPLAY_NUM( |$)" 2>/dev/null || true  # anchored: never match a caller shell
    echo stopped
    ;;
  cli)    # cli ARGS...: run the CLI with prompts (passwords too) read from this script's stdin
    # setsid drops the controlling terminal, so getpass reads stdin instead of /dev/tty.
    cd "$REPO"
    exec setsid -w python3 pwvault.py "$@"
    ;;
  help|*)
    sed -n 's/^  \([a-z|]*\)) *# \{0,1\}\(.*\)/  \1  \2/p' "${BASH_SOURCE[0]}"
    ;;
esac
