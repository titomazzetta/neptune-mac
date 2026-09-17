# Roadmap

Tasks are roughly ordered. Each is scoped to be picked up independently by a
developer or an agent. Respect every constraint in `CLAUDE.md` — especially the
bash 3.2 rules and the read-only/human-in-the-loop guarantees.

## Now

### 1. Structured `--json` output  ⭐ headline feature
Add a `--json` flag to `neptune.sh` (and ideally each scan) that emits findings as
structured JSON alongside or instead of the pretty text report.

**Why this first:** it's the spine everything else hangs on. It lets any advisor —
Claude reading a paste, a local model, a future orchestrator — consume Neptune's
findings *without* being handed the ability to run destructive commands. That
decoupling (Neptune emits findings; something else decides; the human acts) is the
project's safety model. Keep it.

Shape each finding as: `{id, scan, severity, title, detail, path?, signer?,
category}`. Severity in `{info, warn, flag}`. Keep the human-readable report too;
`--json` is additive.

Constraint: bash 3.2 has no JSON tooling. Emit JSON by hand with careful escaping,
or detect and use `python3` (present on all modern macOS) as a JSON encoder. Do
not add a brew dependency.

### 2. `neptune` orchestrator (interactive front-end)
A single entry command that: runs the observe suite → shows a consolidated,
numbered findings list → for each actionable finding offers `keep / delete / skip /
explain` → executes only approved actions via the existing `uninstall.sh` /
`check_updates.sh` → writes a final "what changed" report.

Constraints: this is the `observe → decide → act` lifecycle. The **act** stage must
reuse the existing confirmed-deletion paths — do NOT bypass their confirmations.
The orchestrator is a conductor over the modular scripts, not a rewrite of them.
Keep the individual scripts runnable standalone.

## Next

### 3. `advisor` integration (decoupled)
A `docs/advisor.md` prompt template already defines the "read my report and
recommend" loop. Optionally add `neptune advise` that pipes the `--json` report to
a **local** model if one is present (e.g. an Ollama endpoint on localhost). Never
require it; never embed a cloud API key. If no local model is found, print the
paste-to-an-LLM instructions instead.

### 4. Config file
Optional `~/.neptune/config` for user preferences: known-good vendor allowlist (so
recurring vendor-quirk flags can be acknowledged and hidden), staleness threshold,
report location. Never let config disable a security check silently — an
acknowledged flag should still be counted, just marked "acknowledged."

### 5. ~~rapportd / ephemeral-port noise suppression~~ — done
Moved to Done. Turned out to be broader than `rapportd`: on a real machine 7 of
10 flags were ephemeral churn, Splice included, so the fix collapses the whole
dynamic range rather than special-casing Apple daemons.

## Not planned

Removed from the roadmap deliberately, so they stop reading as debt:

- **Interactive orchestrator with keep/delete/skip** (was #2). Substantial work
  and real risk for a tool whose value is the diagnosis, not the doing. The
  destructive paths already exist, are confirmed, and are better entered
  knowingly. `--acknowledge` covers the "I've seen this, stop counting it" case
  that motivated most of it.
- **Bundled local-model advisor** (was #3). `--json` plus `docs/advisor.md` is
  the decoupled version and it works with any model. Shipping an integration
  means shipping a dependency and a key-handling story, and the value over
  "paste this file" is small.
- **Windows sibling** (was #6). The concepts map; nothing else does.

## Later / exploratory

### 6. Windows sibling
The concepts map to Windows (Autoruns-style persistence, `netstat` listeners) but
the implementation doesn't. A PowerShell sibling suite is a possible expansion,
kept as a separate directory/tool — not a port that muddies the bash scripts.

### 7. Mocked-macOS test fixtures
CI can lint and syntax-check but can't run the scanners meaningfully (a Linux/CI
runner has none of the real persistence/process state). Explore fixture files that
mock `launchctl`/`lsof`/`system_profiler` output so scan *logic* can be unit-tested
against known inputs. Non-trivial; high value for regression safety.

### 8. Portfolio polish (job-search value)
- ~~**Sanitized sample report**~~ — done: [`docs/sample-report.txt`](docs/sample-report.txt).
- ~~**Keep `docs/DEVLOG.md` current**~~ — ongoing, and current through Bug 8.
- **Demo recording** — an asciinema cast or GIF of a real `./neptune.sh` run,
  embedded in the README. Hiring managers skim; seeing it work beats reading about
  it. Scaffolding and recording instructions are in the README's Demo section;
  the recording itself needs live system state.

## Done

- Master runner (`neptune.sh`) with consolidated report + action digest
- Guided uninstaller (`uninstall.sh`) with discovery/confirm/verify
- Deep network check (`netcheck_plus.sh`)
- bash 3.2 compatibility fixes (empty-array guards, awk-not-case-in-subshell)
- lsof per-process AND-semantics fix; subshell flag-propagation fix

**2026-09 audit pass** — see [`CHANGELOG.md`](CHANGELOG.md) for the full list and
[`docs/DEVLOG.md`](docs/DEVLOG.md) Bugs 6–8 for the reasoning:

- Code-signing authority read at the wrong verbosity — no signer was ever
  identified, and the Apple-detection branch was unreachable (Bug 7)
- Action digest double-counted findings and promoted explanatory prose to
  findings (Bug 8)
- Ephemeral listener-port churn suppressed in the baseline (item 5 above)
- A security check that cannot run now says so instead of passing quietly
- `uninstall.sh` no longer terminates processes before the confirmation prompt
- Public-IP lookup made opt-in; `SECURITY.md` added documenting the full
  threat model, footprint, and what Neptune does *not* detect
