## Summary

<!-- What this changes and why, in two or three sentences. Lead with the user-visible effect. -->

## Changes

<!-- One line per logical change. Reference DEVLOG bug numbers where a change fixes one. -->
-

## Safety

<!-- Neptune's constraints, checked for this change. Delete a line only if it truly does not apply. -->
- [ ] Read-only by default: nothing new changes the machine without being shown and confirmed
- [ ] No `--yes`/`--force`, no unattended path, no telemetry or third-party network call
- [ ] Destructive discovery changed? A hostile decoy was added to `tests/blast_radius.sh`
- [ ] New check id? It has a remediation entry and a `fix.sh` plan (tests enforce both)
- [ ] bash 3.2: no `case`, heredoc or backtick inside `$( )`/`<( )`; empty arrays guarded

## Verification

<!-- What was run, where, and what it showed. "Tests pass" is not enough — say which, on which platform. -->
- [ ] `./tests/lint.sh` (Linux)
- [ ] macOS CI job green (bash 3.2 + BWK awk + end-to-end run)
- [ ] Run on a real Mac:

## Docs

- [ ] README / SECURITY footprint / CHANGELOG / DEVLOG updated where behaviour changed
