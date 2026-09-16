# CLAUDE.md — Working notes for agents developing Neptune

You are working on **Neptune**, a suite of macOS maintenance and security-audit
shell scripts. This file is your operating manual. Read it fully before changing code.

## Background & philosophy (read this for judgment calls)

Neptune was built by removing its opposite — a commercial "cleaner" (MacKeeper)
that installed resident daemons, an endpoint-security extension, and traffic
filters that taxed the machine while being hard to remove. Neptune does the
*legitimate* jobs those products fake (persistence auditing, staleness, updates,
network health) the honest way: on-demand, transparent, read-only by default,
human-in-the-loop.

It is also the author's applied-security portfolio piece (built during a
cybersecurity job search), so the code should read like the work of someone who
thinks about failure modes, blast radius, and trust — because that judgment is the
real deliverable.

**The heuristic for any ambiguous decision:** choose the option a
privacy-respecting, no-BS security engineer would choose — never the option a
"cleaner" product would. That single test resolves most design questions. When in
doubt, prefer: read-only over mutating, explicit over silent, calibrated over
alarmist, portable over clever. See `docs/PHILOSOPHY.md` for the full vision.

## What Neptune is

A collection of independent, on-demand bash scripts that audit and clean a Mac.
No daemons, nothing resident, nothing scheduled. Every script runs only when
invoked and (with two exceptions) changes nothing. The design philosophy is the
opposite of the "cleaner" apps it was built to remove: transparent, modular,
read-only by default, human-in-the-loop for anything destructive.

## The non-negotiable constraints

These are hard rules. Breaking any of them is a regression, even if the code
"works" on your test machine.

1. **macOS ships bash 3.2 (2007).** This is the single most important constraint.
   Modern bash idioms silently break on it. Specifically:
   - `case` statements inside `$(...)` command substitution FAIL to parse. Use awk.
   - Under `set -u`, expanding an empty array `"${ARR[@]}"` is an "unbound variable"
     error. ALWAYS guard: `${ARR[@]:+"${ARR[@]}"}`.
   - No associative arrays, no `${var^^}`, no `mapfile`/`readarray`.
   - Test mentally against bash 3.2, not the bash on the CI runner.
   The CI runs shellcheck with `--shell=bash` and these bugs have bitten this
   project repeatedly. When in doubt, prefer POSIX-portable constructs.

2. **Read-only is the default.** Only `remove_mackeeper.sh` and `uninstall.sh`
   delete anything, and both MUST show the user everything first and require an
   explicit typed confirmation before any destructive action. Never add silent
   deletion to any script. Never add a `--force`/`--yes` flag that skips the
   confirmation on a destructive script without extremely clear justification.

3. **Human-in-the-loop for destructive actions.** The safety of this tool is that
   a person is watching when files are deleted as root. Do not automate away the
   confirmation step. Do not add unattended/cron modes to the destructive scripts.

4. **No secrets, no network calls to third parties, no telemetry.** Neptune never
   phones home. The only network use is optional (e.g. a speed test hitting a
   public endpoint). Never add API keys, analytics, or bundled credentials.

5. **`sudo` only where genuinely required, cached once.** Scripts prompt for sudo
   once up front and reuse the cached credential; they never run the whole script
   as root. A script that refuses to run under `sudo` (checking `id -u`) is
   intentional — keep that guard.

## Repository layout

```
scripts/         the nine Neptune scripts (the actual tool)
tests/           shellcheck config + syntax smoke tests
docs/            extended docs, the report-reading guide, the AI-advisor prompt
.github/workflows/  CI (lint, syntax, bash 3.2 compat gate)
README.md        public overview
ROADMAP.md       what's next — pick tasks from here
CLAUDE.md        this file
```

## The scripts (current state)

| Script | Role | Mutates? |
|---|---|---|
| `neptune.sh` | Master runner — runs all scans, one combined report | no |
| `sentry.sh` | Baseline diff, process→network map, staleness | baseline files only |
| `redflag_scan.sh` | Deep audit: persistence, listeners, interception | no |
| `audit_system.sh` | Resources, persistence, disk | no |
| `network_check.sh` | NAT, DNS, latency, connections | no |
| `netcheck_plus.sh` | Deep network: Wi-Fi quality, LAN census, ASUS audit | no |
| `check_updates.sh` | macOS + brew + App Store updates | only with `--upgrade` |
| `uninstall.sh` | Guided app removal | YES — confirmed |
| `remove_mackeeper.sh` | Targeted MacKeeper/Clario removal | YES — confirmed |

## How to work on this codebase

- **Every change must pass `shellcheck` and `bash -n`.** Run `tests/lint.sh`
  locally before committing; CI enforces it.
- **Match the existing style.** Color helpers (`ok`/`warn`/`flag`), section
  headers, the `[ok]/[!!]/[FLAG]/[XX]` prefixes are consistent across scripts —
  keep them. A finding-line prefix is load-bearing: `neptune.sh` greps for
  `[FLAG]`/`[XX]` to build its digest.
- **Never widen a destructive glob without tracing it.** The `rm -rf` targets in
  the uninstallers are built from discovery output; a careless glob is how you
  delete someone's home folder. Show, confirm, then delete.
- **Prefer editing one script over touching many.** These are independent by
  design; a change to `sentry.sh` should not require changes elsewhere.

## Current priorities

See `ROADMAP.md`. The headline next feature is **structured `--json` output**,
which unlocks the AI-advisor loop without giving any agent the keys to run
destructive commands unsupervised. That decoupling is deliberate — read the
roadmap's rationale before building it.
