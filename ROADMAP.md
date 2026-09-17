# Roadmap

Each task is scoped to be picked up independently by a developer or an agent.
Respect every constraint in `CLAUDE.md` — especially the bash 3.2 rules and the
read-only / human-in-the-loop guarantees.

Shipped work is in [`CHANGELOG.md`](CHANGELOG.md); the reasoning behind each fix
is in [`docs/DEVLOG.md`](docs/DEVLOG.md).

## Now

### 1. Fixture tests for the parsing layer
Unit-test the pure text-processing functions against captured command output. No
macOS required, and no mocking of `launchctl` / `lsof` / `system_profiler` — that
framing is what kept this deferred as "non-trivial", and it skips the cheap half.

Every bug in the 2026-09 audit lived in this layer and would have been caught here:

- digest extraction from scan text (Bug 8)
- `sig()`'s authority classification, given captured `codesign -dvv` output (Bug 7)
- the ephemeral-port collapse, given captured `lsof` output
- the double-NAT / CGNAT hop classifier, given a traceroute fixture (Bug 5's
  logic, currently protected by nothing)
- MAC extraction from `arp -an`, including the non-zero-padded form
- the JSON encoder's escaping and `--sanitize`

Structured findings make the assertions trivial: feed records in, assert on
scores, counts and verdict.

**One honest gap this closes:** the system-proxy check is correct on the evidence
available, but nobody has run it against a machine with a proxy actually
configured. A fixture settles that permanently.

### 2. Per-check coverage accounting
`unknown` findings surface checks that could not run, but the summary still can't
say how many checks *ran*. Target:

```
27 checks · 24 clean · 2 attention · 1 could not run
```

That requires each scan to count its checks, not just its findings. Completes the
idea the firewall fix started: "no red flags" must mean "every check ran and found
nothing", never "the checks that ran found nothing".

## Next

### 3. Per-scan `--json`
`neptune.sh --json` works. The individual scans can already record findings, so
letting each emit its own JSON standalone is mostly plumbing — useful for anyone
scripting against one scan rather than the suite.

### 4. Config beyond the allowlist
`~/.neptune/allow` exists. A `~/.neptune/config` could hold staleness threshold
and report location. Same rule as the allowlist: config may never silently
disable a check. An acknowledged finding is still counted and still listed.

### 5. Portfolio polish
- ~~Sanitized sample report~~ — done: [`docs/sample-report.txt`](docs/sample-report.txt)
  (regenerate it against current output; the committed one is a pre-fix exhibit).
- ~~Keep `docs/DEVLOG.md` current~~ — ongoing, current through Bug 8.
- **Demo recording** — an asciinema cast plus a GIF generated from it. Scaffolding
  and scrub instructions are in the README's Demo section; the recording needs
  live system state.

## Not planned

Removed deliberately, so they stop reading as debt:

- **Interactive orchestrator with keep/delete/skip.** Substantial work and real
  risk for a tool whose value is the diagnosis, not the doing. The destructive
  paths already exist, are confirmed, and are better entered knowingly.
  `--acknowledge` covers the "I've seen this, stop counting it" case that
  motivated most of it.
- **Bundled local-model advisor.** `--json` plus [`docs/advisor.md`](docs/advisor.md)
  is the decoupled version and works with any model. Shipping an integration means
  shipping a dependency and a key-handling story, for little gain over "paste this
  file" — and "no API keys" is a claim `SECURITY.md` invites you to verify.
- **Windows sibling.** The concepts map (Autoruns-style persistence, `netstat`
  listeners); the implementation doesn't. A PowerShell suite would be a separate
  tool, not a port that muddies these scripts.

## Done

- Master runner with a consolidated report
- Guided uninstaller with discovery / confirm / verify
- Deep network check (`netcheck_plus.sh`)
- bash 3.2 compatibility fixes (empty-array guards, awk-not-case-in-subshell)
- `lsof` per-process AND-semantics fix; subshell flag-propagation fix

**2026-09 audit pass** — full list in [`CHANGELOG.md`](CHANGELOG.md):

- Code-signing authority read at the wrong verbosity, so no signer was ever
  identified and the Apple-detection branch was unreachable (Bug 7)
- Action digest double-counted findings and promoted explanatory prose to
  findings (Bug 8)
- `uninstall.sh` no longer terminates processes before the confirmation prompt
- Ephemeral listener-port churn suppressed in the baseline
- A security check that cannot run now says so instead of passing quietly
- Public-IP lookup made opt-in; `SECURITY.md` added

**2026-09 verdict layer:**

- Structured finding records; verdict and per-category health scores
- `--acknowledge` with a keyed allowlist in `~/.neptune/allow`
- `--json` and `--json --sanitize`
