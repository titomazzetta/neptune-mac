#!/bin/bash
# Local lint — run before committing. Mirrors CI.
set -u
cd "$(dirname "$0")/.." || exit 1
fail=0
echo "== syntax (bash -n) =="
for f in scripts/*.sh; do bash -n "$f" && echo "  ok  $f" || { echo "FAIL $f"; fail=1; }; done
echo "== shellcheck =="
if command -v shellcheck >/dev/null; then
  shellcheck --shell=bash --severity=warning scripts/*.sh || fail=1
else
  echo "  (shellcheck not installed — brew install shellcheck)"
fi
echo "== bash 3.2 traps =="
grep -nE '\$\([^)]*\bcase\b' scripts/*.sh && { echo "ERROR case-in-subshell"; fail=1; } || echo "  ok  no case-in-subshell"
grep -nE 'declare -A|\b(mapfile|readarray)\b' scripts/*.sh && { echo "ERROR 3.2-incompatible builtin"; fail=1; } || echo "  ok  no 3.2-incompatible builtins"
exit $fail
