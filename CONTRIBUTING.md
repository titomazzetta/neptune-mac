# Contributing to Neptune

Thanks for helping. A few rules keep Neptune safe and portable.

## Issues
Use the templates: **Bug report**, or **False positive / vendor quirk** (with the
`--json --sanitize` entry and your evidence). Security problems go to the
private report link, never a public issue.

## Before you open a PR
- Run `tests/lint.sh` locally. CI runs the same checks, and `main` is protected:
  a PR can merge only when all three CI jobs pass (`.github/rulesets/main.json`).
- Fill in the PR template — Summary, Changes, Safety, Verification. "Tests pass"
  is not verification; say what ran, where, and what it showed.
- Read `CLAUDE.md` — the bash 3.2 constraints and the read-only / human-in-the-loop
  guarantees are non-negotiable.

## Hard rules
1. **bash 3.2 compatible.** macOS ships bash 3.2. No `case` inside `$()`, no
   unguarded empty-array expansion under `set -u` (use `${ARR[@]:+"${ARR[@]}"}`),
   no associative arrays, no `mapfile`/`readarray`.
2. **Read-only by default.** Only `uninstall.sh`, `remove_mackeeper.sh` and
   `clean_caches.sh` delete, and each must show everything and require a typed
   confirmation first. Don't add silent deletion or a confirmation-skipping flag;
   `tests/lint.sh` fails the build on one.
3. **No telemetry, no secrets, no bundled API keys.**
4. **Keep scripts independent.** Prefer editing one script to coupling many.
5. **Record, don't print.** A finding must go through a helper that calls
   `record` with a `CHECK` id — `pass` for a clean result, `unknown` when the
   check could not run. A finding that only prints is invisible to the score,
   the JSON and the HTML. Every new check id needs a remediation entry in
   `scripts/neptune_render.py`; `tests/test_render.py` fails until it has one.
6. **Fail closed.** If a check cannot decide, it records `unknown`. Never let
   an error path fall through to "ok".
7. **Destructive changes come with decoys.** Touch discovery or deletion in a
   destructive script and add a hostile case to `tests/blast_radius.sh` in the
   same commit.

## Style
Match the existing color helpers, section headers, and output format. Small,
reviewable commits. Explain *why* in the PR, not just what.
