# Roadmap

Each task is scoped to be picked up independently by a developer or an agent.
Respect every constraint in `CLAUDE.md` — especially the bash 3.2 rules and the
read-only / human-in-the-loop guarantees.

Shipped work is in [`CHANGELOG.md`](CHANGELOG.md); the reasoning behind each fix
is in [`docs/DEVLOG.md`](docs/DEVLOG.md).

## Now

### 1. Login items from Background Task Management
Since macOS 13, apps can register login items and helpers through
`SMAppService`, and those live in the Background Task Management database rather
than in a `LaunchAgents` folder. They still appear as running processes and
listeners, but not in the persistence audit — a real gap, stated in
`SECURITY.md`. `sfltool dumpbtm` (root) prints the database; the work is a
parser plus fixture tests, which needs a real capture from a machine with a few
such items (a sanitized `sudo sfltool dumpbtm` from the development Mac), not a
guess at the format. Each item then goes through the same `sig()` as every other
persistence target.

### 2. A demo recording
An asciinema cast, scrubbed, and a GIF rendered from it. The procedure is in
[`docs/demo/RECORDING.md`](docs/demo/RECORDING.md); it needs live system state,
so it is recorded by hand rather than in CI.

## Next

### 3. Per-scan `--json`
Each scan already records structured findings; letting one emit JSON standalone
is mostly plumbing — useful for scripting against one scan rather than the suite.

### 4. Config beyond the allowlist
A `~/.neptune/config` could hold the staleness threshold and report location.
Same rule as the allowlist: config may never silently disable a check.

### 5. Notarization status for apps
`spctl --assess` distinguishes notarized from merely signed. Cheap to add to the
stale-apps and unmanaged-apps listings, and a meaningful extra signal.

## Not planned

Removed deliberately, so they stop reading as debt:

- **Unattended or "fix everything" modes.** `--fix` (1.1) is guided on purpose:
  one finding, one shown command, one `y`. A mode that applies fixes without a
  person reading each one is the cleaner-product pattern this project exists
  to argue against, and it will not be added.
- **Bundled local-model advisor.** `--json` plus [`docs/advisor.md`](docs/advisor.md)
  is the decoupled version and works with any model. Shipping an integration means
  shipping a dependency and a key-handling story, for little gain over "paste this
  file" — and "no API keys" is a claim `SECURITY.md` invites you to verify.
- **Windows sibling.** The concepts map (Autoruns-style persistence, `netstat`
  listeners); the implementation doesn't. A PowerShell suite would be a separate
  tool, not a port that muddies these scripts.

## Done

**v1.1.0** — guided fixing: `./neptune.sh --fix` walks the last run's findings
with the exact command for each and a y/N per item, hands deletion to the
confirmed scripts, logs every change, and re-scans at the end. Self-updating
apps are compared against Homebrew's local catalog.

**v1.0.0 — 2026-09** (full list in [`CHANGELOG.md`](CHANGELOG.md)):

- Fail-closed pipeline: integrity check, crashed/missing/silent scans become
  unknowns, an error can never read as healthy (Bug 13)
- Every check records a stable id and a `pass` when clean — the report proves
  coverage, and the HTML opens with a ten-control posture panel
- Ad-hoc signatures classified as their own class (Bug 16)
- `--acknowledge N` resolves against the saved listing you read (Bug 14)
- Suite-mode de-duplication (Bug 17); a bloat score that can move (Bug 18)
- `clean_caches.sh`; `check_updates.sh` that never installs a major upgrade
- Tests that source the shipping code; a macOS CI job under bash 3.2 with a
  real end-to-end run; pinned, least-privilege CI; attested releases

**Earlier:** the verdict layer, scores and `--json`/`--html`; the 2026-09 audit
pass (Bugs 1–12); blast-radius testing of the destructive scripts; the master
runner, guided uninstaller and deep network check.
