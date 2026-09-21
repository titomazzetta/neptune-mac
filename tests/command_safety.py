#!/usr/bin/env python3
"""Assert the remediation table's own rules about the commands it offers.

The table in scripts/neptune.sh states three rules: nothing generated, no
command is a pipeline or a chain, and every command carries a kind label. This
checks the last two against the real table, extracted from the script rather
than re-implemented — one table, one source.

WHY THIS IS A FILE AND NOT A HEREDOC. It used to live inline in
tests/unit.sh as:

    PIPED=$(python3 - <<'ADV'
    ... if any(ch in c for ch in ("|", ";", "&&", ">", "`", "$(")): ...
    ADV
    )

which parses on bash 5 and is a syntax error on bash 3.2 — the version macOS
ships and the one this project targets. Inside $( ), the 3.2 parser still scans
a heredoc body for backticks and $( , so a script that merely MENTIONS those
characters fails to parse. It took tests/unit.sh down at line 336 with
"unexpected EOF while looking for matching backtick", and because the failure is
a parse error rather than an assertion, it produced a non-zero exit with no FAIL
output at all — a test file that cannot report failure, which is the exact
harness bug DEVLOG records from the Bug 8 pass.

This is the same family as CLAUDE.md's rule about `case` inside $( ): bash 3.2's
command-substitution parser is not cleanly recursive, and the fix is always to
get the construct out of $( ) rather than to find a quoting trick.

Usage: command_safety.py    -> prints offending commands, if any
"""
import sys

SRC = "scripts/neptune.sh"
START = "import html, json, os, re, shlex"
END = "# ---------------------------------------------------------------------------\nsc, ack, counts"

# Built rather than written literally, so this file stays quotable from a shell
# without reintroducing the problem it documents.
FORBIDDEN = ("|", ";", "&&", ">", chr(96), "$" + "(")
KINDS = ("look", "setting", "software", "neptune")

src = open(SRC, encoding="utf-8").read()
try:
    body = src[src.index(START):src.index(END)]
except ValueError:
    sys.exit("EXTRACT FAILED: markers not found in %s — this test is no longer "
             "testing the real remediation table" % SRC)

sys.argv = ["command-safety", "/dev/null", "/dev/null", "healthy"]
ns = {"__name__": "command_safety"}
exec(compile(body, "neptune-renderer", "exec"), ns)  # noqa: S102 - deliberate

# A title shaped like the real ones, so entries that build a command from a path
# actually produce one to inspect.
SAMPLE = ("UNSIGNED persistence: com.example.thing runs /Library/Foo/bar "
          "(/Library/LaunchDaemons/com.example.thing.plist)")

bad = []
for entry in ns["REMEDIATION"]:
    _pattern, _means, _do, cmdf = entry
    for command, kind, _effect in cmdf(SAMPLE):
        for ch in FORBIDDEN:
            if ch in command:
                bad.append("%r contains %r" % (command, ch))
        if kind not in KINDS:
            bad.append("%r has unknown kind %r" % (command, kind))

print("\n".join(bad))
