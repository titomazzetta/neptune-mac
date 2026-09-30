#!/usr/bin/env python3
"""bash32_gate.py — find the constructs bash 3.2 cannot run inside $( ) or <( ).

bash 3.2 does not parse the body of a command or process substitution when it
parses the script; it re-scans the text when the substitution RUNS. So these
fail at run time, and `bash -n` — on any bash — passes them:

  * a `case` statement (its `)` patterns close the substitution early)
  * a heredoc (its body is scanned for backticks and $( )
  * a backtick ANYWHERE in the body, including in a comment: an odd number of
    them is "bad substitution: no closing `)'" (DEVLOG Bug 19 — a comment that
    explained the case rule, in backticks, broke clean_caches.sh on 3.2)

This walks every $( and <( with a small quote-aware scanner, finds the matching
close, and reports those three things inside. Heuristic, but it is the check
that matched the bug that shipped; the macOS CI job runs the real 3.2 as well.

Usage: bash32_gate.py FILE...   -> prints problems, exits 1 if any
"""
import re
import sys


def substitutions(src):
    """Yield (line, body) for each $( or <( — skipping $(( arithmetic."""
    i, n = 0, len(src)
    while i < n:
        if src[i] in "$<" and src.startswith("(", i + 1) and not src.startswith("((", i + 1):
            # ignore a $( that is itself inside single quotes on this line
            line_start = src.rfind("\n", 0, i) + 1
            if src.count("'", line_start, i) % 2 == 1:
                i += 1
                continue
            j, depth, quote = i + 2, 1, None
            while j < n and depth:
                c = src[j]
                if quote:
                    if c == "\\" and quote == '"':
                        j += 2
                        continue
                    if c == quote:
                        quote = None
                elif c == "#" and (j == 0 or src[j - 1] in " \t\n;"):
                    j = src.find("\n", j)
                    if j < 0:
                        j = n
                    continue
                elif c in "'\"":
                    quote = c
                elif c == "\\":
                    j += 2
                    continue
                elif c == "(":
                    depth += 1
                elif c == ")":
                    depth -= 1
                j += 1
            yield src.count("\n", 0, i) + 1, src[i + 2:j - 1]
            i += 2
        else:
            i += 1


def problems(path):
    src = open(path, encoding="utf-8", errors="replace").read()
    out = []
    for line, body in substitutions(src):
        # Strip single-quoted strings: nothing inside them is special to the
        # parser... except that bash 3.2 still counts backticks in comments.
        code = re.sub(r"'[^']*'", "''", body)
        if re.search(r"(^|[\s;(])case\s", code):
            out.append("%s:%d: case inside a substitution" % (path, line))
        if "<<" in code and "<<<" not in code:
            out.append("%s:%d: heredoc inside a substitution" % (path, line))
        if "`" in code:
            out.append("%s:%d: backtick inside a substitution (comments count)" % (path, line))
    return out


if __name__ == "__main__":
    found = [p for f in sys.argv[1:] for p in problems(f)]
    if found:
        print("\n".join(found))
    sys.exit(1 if found else 0)
