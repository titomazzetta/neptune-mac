#!/bin/bash
# Local lint — run before committing. Mirrors CI.
set -u
cd "$(dirname "$0")/.." || exit 1
fail=0
echo "== syntax (bash -n) =="
# tests/*.sh too. unit.sh once failed to PARSE on bash 3.2 and nothing here
# noticed, because this loop only ever looked at scripts/.
for f in scripts/*.sh tests/*.sh; do bash -n "$f" && echo "  ok  $f" || { echo "FAIL $f"; fail=1; }; done
echo "== shellcheck =="
if command -v shellcheck >/dev/null; then
  shellcheck --shell=bash --severity=warning scripts/*.sh || fail=1
else
  echo "  (shellcheck not installed — brew install shellcheck)"
fi
echo "== bash 3.2 traps =="
grep -nE '\$\([^)]*\bcase\b' scripts/*.sh && { echo "ERROR case-in-subshell"; fail=1; } || echo "  ok  no case-in-subshell"
# Pattern assembled from fragments so this gate does not match its own source.
# It scans tests/ now, and this file is in tests/ — adjacent quoted strings
# concatenate in bash, so the literal never appears on the line.
BUILTINS='de''clare -A|\b(map''file|read''array)\b'
grep -nE "$BUILTINS" scripts/*.sh tests/*.sh && { echo "ERROR 3.2-incompatible builtin"; fail=1; } || echo "  ok  no 3.2-incompatible builtins"
# A heredoc inside $( ) — same family as case-in-subshell. bash 3.2 scans the
# heredoc body for backticks and $( even inside $( ), so a script that merely
# MENTIONS them fails to parse. bash -n on the CI runner cannot catch this:
# bash 5 parses it happily.
grep -nE '\$\(.*<<' scripts/*.sh tests/*.sh && { echo "ERROR heredoc inside \$() — breaks bash 3.2; put it in its own file"; fail=1; } || echo "  ok  no heredoc-in-subshell"
echo "== blast radius (destructive scripts) =="
if ./tests/blast_radius.sh > /tmp/neptune_blast.log 2>&1; then
  echo "  ok  $(tail -2 /tmp/neptune_blast.log | head -1 | sed 's/^ *//')"
else
  grep -A3 '^  FAIL' /tmp/neptune_blast.log
  echo "ERROR blast-radius tests failed — run ./tests/blast_radius.sh for detail"; fail=1
fi
rm -f /tmp/neptune_blast.log
echo "== unit tests =="
if ./tests/unit.sh > /tmp/neptune_unit.log 2>&1; then
  echo "  ok  $(tail -2 /tmp/neptune_unit.log | head -1 | sed 's/^ *//')"
else
  grep -A2 '^  FAIL' /tmp/neptune_unit.log
  echo "ERROR unit tests failed — run ./tests/unit.sh for detail"; fail=1
fi
rm -f /tmp/neptune_unit.log
exit $fail
