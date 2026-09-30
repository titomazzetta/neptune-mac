#!/bin/bash
# Local lint + test — run before committing. CI runs the same steps (and, on
# the macOS job, runs them again under /bin/bash 3.2 and BWK awk).
set -u
cd "$(dirname "$0")/.." || exit 1
fail=0

echo "== syntax (bash -n) =="
# tests/*.sh too: unit.sh once failed to PARSE on bash 3.2 and nothing noticed,
# because this loop only looked at scripts/.
for f in scripts/*.sh tests/*.sh; do bash -n "$f" && echo "  ok  $f" || { echo "FAIL $f"; fail=1; }; done

echo "== shellcheck =="
if command -v shellcheck >/dev/null; then
  # A UTF-8 locale for shellcheck itself: it reads the em-dashes in comments,
  # and under the C locale it dies with "invalid character" instead of linting.
  LC_ALL=C.UTF-8 shellcheck --shell=bash --severity=warning scripts/*.sh tests/*.sh \
    && echo "  ok  no warnings" || fail=1
else
  echo "  (shellcheck not installed — brew install shellcheck)"
fi

echo "== bash 3.2 traps =="
grep -nE '\$\([^)]*\bcase\b' scripts/*.sh tests/*.sh && { echo "ERROR case-in-subshell"; fail=1; } || echo "  ok  no case-in-subshell"
# Assembled from fragments so this gate does not match its own source.
BUILTINS='de''clare -A|\b(map''file|read''array)\b|\$\{[a-zA-Z_]+(\^\^|,,)'
grep -nE "$BUILTINS" scripts/*.sh tests/*.sh | grep -vE '^[^:]+:[0-9]+:[[:space:]]*#' && { echo "ERROR 3.2-incompatible builtin"; fail=1; } || echo "  ok  no 3.2-incompatible builtins"
# A heredoc inside $( ) or <( ): bash 3.2 scans the body for backticks and $(
# even inside a substitution, so a body that merely MENTIONS them fails to
# parse. bash -n on a bash 5 runner cannot catch it.
grep -nE '(\$|<)\(.*<<' scripts/*.sh tests/*.sh && { echo "ERROR heredoc inside a substitution — breaks bash 3.2"; fail=1; } || echo "  ok  no heredoc-in-substitution"
# The multi-line version of both, plus backticks (comments count): bash 3.2
# re-parses a substitution's text when it runs, so bash -n never sees these.
if command -v python3 >/dev/null; then
  python3 tests/bash32_gate.py scripts/*.sh tests/*.sh && echo "  ok  no case, heredoc or backtick inside any \$( ) or <( )" || fail=1
fi

echo "== destructive-script guardrails =="
# Coarse, and deliberately so: the blast-radius harness below is the real test.
# This only catches the safety gate being deleted or a bypass being added.
g=0
for f in scripts/uninstall.sh scripts/remove_mackeeper.sh scripts/clean_caches.sh; do
  grep -qE 'read -r?.*(\[y/N\]|yes)' "$f" || { echo "ERROR $f has no confirmation prompt"; g=1; }
  grep -nE '^[[:space:]]*-?-?(yes|force|assume-yes|y)\)' "$f" && { echo "ERROR $f accepts a confirmation-bypass flag"; g=1; }
done
[ "$g" -eq 0 ] && echo "  ok  confirmation prompts present, no bypass flags" || fail=1

echo "== python =="
if command -v python3 >/dev/null; then
  for f in scripts/*.py tests/*.py; do
    python3 -c 'import ast, sys; ast.parse(open(sys.argv[1], encoding="utf-8").read(), sys.argv[1])' "$f" \
      && echo "  ok  $f" || { echo "FAIL $f"; fail=1; }
  done
  if python3 -m unittest discover -s tests -p 'test_*.py' > /tmp/neptune_py.log 2>&1; then
    echo "  ok  $(grep -E '^Ran ' /tmp/neptune_py.log)"
  else
    grep -E '^(FAIL|ERROR):' /tmp/neptune_py.log
    echo "ERROR python tests failed — run python3 -m unittest discover -s tests -v for detail"; fail=1
  fi
  rm -f /tmp/neptune_py.log
else
  echo "  (python3 not installed — renderer tests skipped; the core scan does not need it)"
fi

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
