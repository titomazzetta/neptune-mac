#!/usr/bin/env python3
"""Check that every finding shape in a findings file gets remediation advice.

The remediation table lives inside the python block in scripts/neptune.sh,
because that block is the single renderer behind both --json and --html and a
second copy of the table is exactly the drift this project keeps writing DEVLOG
entries about. So this test does not re-implement it: it extracts the real
source between two markers and executes it.

If the extraction markers stop matching, that is a failure too — a test that
silently stops testing is worse than no test (DEVLOG: the harness whose 27
assertions were never counted).

Usage: advice_coverage.py <findings-file>   -> prints unmapped titles, if any
"""
import sys

SRC = "scripts/neptune.sh"
START = "import html, json, os, re, shlex"
END = "# ---------------------------------------------------------------------------\nsc, ack, counts"

src = open(SRC, encoding="utf-8").read()
try:
    body = src[src.index(START):src.index(END)]
except ValueError:
    sys.exit("EXTRACT FAILED: markers not found in %s — this test is no longer "
             "testing the real remediation table" % SRC)

# The extracted block reads sys.argv and the environment at import time.
# Give it inert values: we only want the remediation table, not a render.
findings_file = sys.argv[1]
sys.argv = ["neptune-renderer", "/dev/null", "/dev/null", "healthy"]

ns = {"__name__": "advice_under_test"}
exec(compile(body, "neptune-renderer", "exec"), ns)  # noqa: S102 - deliberate
advise = ns["advise"]

unmapped = []
for line in open(findings_file, encoding="utf-8", errors="replace"):
    f = line.rstrip("\n").split("|")
    if len(f) < 4:
        continue
    if advise(f[3]).get("unmapped"):
        unmapped.append(f[3][:60])

print("\n".join(unmapped))
