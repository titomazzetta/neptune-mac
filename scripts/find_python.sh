# find_python.sh — sourced by neptune.sh, check_updates.sh and redflag_scan.sh.
# Not executable on its own; it only defines functions.
#
# Neptune's scan needs nothing beyond macOS. The HTML report, the JSON, the AI
# brief, the browser-extension check and the catalog comparison need a python3
# (3.6+) — and "is there a python3?" turned out to be the wrong question.
#
# The first real laptop run (2026-10, macOS 26) had a working Apple python3 in
# /usr/bin and a leftover /usr/local/bin/python3 earlier on PATH that could not
# execute (exit 126). Neptune asked PATH, got the broken one, and told the user
# to install the Command Line Tools they already had. So: try each candidate,
# use the first that RUNS, and when none does, say exactly why.
#
# On a Mac without the Command Line Tools, /usr/bin/python3 is a stub that pops
# an "install developer tools" dialog, so it is only tried when xcode-select
# reports them installed.

# shellcheck disable=SC2034  # NEP_PY* are read by the scripts that source this
export LC_ALL=C   # the same byte-safe locale as every script that sources it

# The places a python3 usually lives, after whatever PATH finds first. A test
# can replace the list; nothing else should.
NEP_PY_CANDIDATES=${NEP_PY_CANDIDATES:-"/opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3"}

# py_failure <path> <exit status> — why a candidate did not run, in words.
py_failure() {
  case "$2" in
    126) echo "$1 is there but cannot run (usually an Intel-only build on an Apple-silicon Mac without Rosetta, or a leftover from an old installer)" ;;
    127) echo "$1 is a broken link to a python that was removed" ;;
    3)   echo "$1 is older than Python 3.6" ;;
    *)   echo "$1 stopped with status $2 when started" ;;
  esac
}

# find_python — sets NEP_PY to a python3 that runs, or "" with NEP_PY_WHY.
# NEP_PY_NOTE is set when the one on PATH failed and another was used, so the
# person can fix their PATH. Honours NEPTUNE_PYTHON, which neptune.sh exports
# for the scans it runs, so one run uses one interpreter.
find_python() {
  local C SEEN="" RC FIRST_BAD="" FROM_PATH
  NEP_PY=""; NEP_PY_WHY=""; NEP_PY_NOTE=""
  if [ -n "${NEPTUNE_PYTHON:-}" ] && [ -x "$NEPTUNE_PYTHON" ]; then NEP_PY=$NEPTUNE_PYTHON; return 0; fi
  FROM_PATH=$(command -v python3 2>/dev/null || true)
  # shellcheck disable=SC2086  # the candidate list is space-separated paths
  for C in "$FROM_PATH" $NEP_PY_CANDIDATES; do
    [ -n "$C" ] || continue
    case " $SEEN " in *" $C "*) continue ;; esac
    SEEN="$SEEN $C"
    [ -x "$C" ] || continue
    if [ "$C" = /usr/bin/python3 ] && [ "$(uname -s)" = Darwin ] && ! xcode-select -p >/dev/null 2>&1; then
      [ -n "$NEP_PY_WHY" ] || NEP_PY_WHY="only Apple's placeholder python3 is here, and it needs the Command Line Tools (xcode-select --install)"
      continue
    fi
    "$C" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 6) else 3)' >/dev/null 2>&1; RC=$?
    if [ "$RC" -eq 0 ]; then
      NEP_PY=$C
      [ -n "$FIRST_BAD" ] && NEP_PY_NOTE="using $C, because $FIRST_BAD"
      return 0
    fi
    [ -n "$FIRST_BAD" ] || FIRST_BAD=$(py_failure "$C" "$RC")
    NEP_PY_WHY=$FIRST_BAD
  done
  [ -n "$NEP_PY_WHY" ] || NEP_PY_WHY="no python3 was found; the Command Line Tools provide one (xcode-select --install)"
  return 1
}
