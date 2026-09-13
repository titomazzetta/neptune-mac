# Contributing to Neptune

Thanks for helping. A few rules keep Neptune safe and portable.

## Before you open a PR
- Run `tests/lint.sh` locally. CI runs the same checks and will block on failure.
- Read `CLAUDE.md` — the bash 3.2 constraints and the read-only / human-in-the-loop
  guarantees are non-negotiable.

## Hard rules
1. **bash 3.2 compatible.** macOS ships bash 3.2. No `case` inside `$()`, no
   unguarded empty-array expansion under `set -u` (use `${ARR[@]:+"${ARR[@]}"}`),
   no associative arrays, no `mapfile`/`readarray`.
2. **Read-only by default.** Only `uninstall.sh` and `remove_mackeeper.sh` mutate,
   and both must show everything and require typed confirmation first. Don't add
   silent deletion or a confirmation-skipping flag.
3. **No telemetry, no secrets, no bundled API keys.**
4. **Keep scripts independent.** Prefer editing one script to coupling many.
5. **Preserve the finding-line prefixes** (`[ok]`/`[!!]`/`[FLAG]`/`[XX]`) —
   `neptune.sh` greps them to build its digest.

## Style
Match the existing color helpers, section headers, and output format. Small,
reviewable commits. Explain *why* in the PR, not just what.
