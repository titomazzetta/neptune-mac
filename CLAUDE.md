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
invoked and (with three exceptions, each confirmed) changes nothing. The design philosophy is the
opposite of the "cleaner" apps it was built to remove: transparent, modular,
read-only by default, human-in-the-loop for anything destructive.

## The non-negotiable constraints

These are hard rules. Breaking any of them is a regression, even if the code
"works" on your test machine.

0. **Every script runs under `export LC_ALL=C`.** macOS awk (BWK 20200816)
   ABORTS the whole program when a string function meets invalid UTF-8 in a
   UTF-8 locale, and `lsof` truncates names by bytes, so half a character is a
   normal input. In the C locale all text is bytes — nothing aborts and awk
   behaves the same on macOS and Linux (DEVLOG Bug 13). A new script sets it on
   the line after `set -u`; `tests/unit.sh` fails if one does not.

1. **macOS ships bash 3.2 (2007).** This is the single most important constraint.
   Modern bash idioms silently break on it. Specifically:
   - `case` statements inside `$(...)` command substitution FAIL to parse. Use awk.
   - A **heredoc inside `$(...)`** fails too, and for the same reason: the 3.2
     parser scans the heredoc body for backticks and `$(` even though it is
     already inside a substitution, so a script that merely *mentions* those
     characters is a syntax error. Put the heredoc's contents in their own file.
     `bash -n` on the CI runner cannot catch this — bash 5 parses it happily —
     so there is a grep gate for it.
   - **Never let `substr()` cut a multibyte character.** These titles are full
     of em-dashes; a byte-slice that lands inside one leaves invalid UTF-8,
     which crashes the python renderer (Bug 10), and macOS awk then prints
     `towc: multibyte conversion failure` to stderr the moment anything touches
     those bytes (Bug 12). Build strings from whole words instead of slicing.
   - Under `set -u`, expanding an empty array `"${ARR[@]}"` is an "unbound variable"
     error. ALWAYS guard: `${ARR[@]:+"${ARR[@]}"}`.
   - No associative arrays, no `${var^^}`, no `mapfile`/`readarray`.
   - Test mentally against bash 3.2, not the bash on the CI runner.
   The CI runs shellcheck with `--shell=bash` and these bugs have bitten this
   project repeatedly. When in doubt, prefer POSIX-portable constructs.

2. **Read-only is the default.** Only `remove_mackeeper.sh`, `uninstall.sh` and
   `clean_caches.sh` delete anything, and each MUST show the user everything
   first and require an explicit typed confirmation before any destructive
   action. (`clean_caches.sh` never elevates: it only empties folders inside the
   user's own `~/Library/Caches` that they picked by number.) Never add silent
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
scripts/         the eleven Neptune scripts, the renderer (neptune_render.py), the
                 extension inspector (neptune_inspect.py), vendor-quirks.tsv,
                 the phrasebook (phrases.tsv), and find_python.sh (sourced:
                 the one way any script picks a python3 — the first that runs)
tests/           lint.sh (runs everything), unit.sh, test_render.py,
                 blast_radius.sh, macos.sh, e2e_assert.py, fixtures/
docs/            extended docs, the report-reading guide, the AI-advisor prompt
.github/workflows/  ci.yml (Linux, workflow lint, macOS + real run), release.yml
README.md        public overview
ROADMAP.md       what's next — pick tasks from here
CLAUDE.md        this file
```

## The scripts (current state)

| Script | Role | Mutates? |
|---|---|---|
| `neptune.sh` | Master runner — verdict, scores, `--json`, `--html`, `--replay`, one combined report | `~/.neptune/allow` with `--acknowledge`; `history.tsv`, `seen.tsv`, `last-listing.tsv` every run; nothing with `--replay` |
| `sentry.sh` | Baseline diff, process→network map, staleness | baseline files only |
| `redflag_scan.sh` | Deep audit: persistence, listeners, interception | no |
| `audit_system.sh` | Resources, persistence, disk | no |
| `network_check.sh` | NAT, DNS, latency, connections | no |
| `netcheck_plus.sh` | Deep network: Wi-Fi quality, LAN census, router checklist (standalone, not in the suite) | no |
| `check_updates.sh` | macOS + brew + App Store updates; self-updating apps vs Homebrew's catalog; writes the per-app inventory (`$NEPTUNE_INVENTORY`) the reports list app by app | only with `--upgrade`, asking per source; never a major upgrade |
| `fix.sh` | Guided fixer behind `neptune.sh --fix`: per-finding fix, exact command, y/N; k/u/skip for software you may have chosen; `--only` queue | settings/updates the user confirms one at a time; `~/.neptune/allow` on k; deletes nothing itself; logs to `~/.neptune/fix-log.tsv` |
| `clean_caches.sh` | Cache inventory; empties the ones you pick | YES — `--apply`, pick, type `yes`; never as root |
| `uninstall.sh` | Guided app removal | YES — confirmed; nothing with `--dry-run` |
| `remove_mackeeper.sh` | Targeted MacKeeper/Clario removal | YES — confirmed; nothing with `--dry-run` |

## How to work on this codebase

- **Every change must pass `shellcheck` and `bash -n`.** Run `tests/lint.sh`
  locally before committing; CI enforces it.
- **Match the existing style.** Colour helpers (`ok`/`warn`/`flag`/`unknown`),
  section headers, and the `[ok]/[!!]/[FLAG]/[XX]` prefixes are consistent across
  scripts — keep them.
- **One renderer, one remediation table.** `--json` and `--html` come out of
  `scripts/neptune_render.py`, and its `REMEDIATION` table — keyed by check id —
  is the only place that says "here is what to do about X". Its rules: no
  generated commands, no pipelines or chains, every command labelled
  `look`/`setting`/`software`/`neptune`, and an honest "no automated suggestion"
  where none exists. An `unknown` gets could-not-check advice, never the fix for
  a failure. `tests/test_render.py` imports the module and asserts all of it,
  including that every `CHECK=` id in the scans has an entry.
- **One voice, kept apart from the record.** What a person reads comes from
  `scripts/phrases.tsv` (headline + context per check id), and the explanation
  ladder (`SHORT`, `UNDO`, `PROGRAMS`/`FLAGS` in the renderer). Never reword a
  recorded title to change how it reads: titles are acknowledge keys. A new
  check id needs a phrasebook row; a new suggested command needs every program
  and flag in `PROGRAMS`/`FLAGS` — tests fail otherwise. Voice: say what the
  thing is, then what is off about it; plain words; no capitals for emphasis.
- **The HTML report stays script-free.** No JavaScript, ever — the reading-level
  switch is radio inputs and CSS, sections are `<details>`. A feature that
  needs script (right-click menus, drag to queue) belongs in the CLI instead.
- **Findings are recorded, not scraped.** Each check sets `CHECK=<stable-id>`
  and reports through a helper that prints AND calls `record`, appending
  `severity|category|scan|check|title` to `$NEPTUNE_FINDINGS`:
  `flag`/`bad` → attention, `warn`/`upd` → notice, `unknown` → unknown,
  `info` → info (about the run; costs nothing), `pass` → pass (the check ran
  clean — this is what lets the report prove coverage). A finding that prints
  but does not record is invisible to the score, the JSON and the HTML.
- **Fail closed.** A check that cannot decide records `unknown`, never falls
  through to "ok". The runner turns a crashed, missing or silent scan into an
  `unknown` record, and `nep_run_pipeline` turns lost records into an integrity
  failure. Nothing in that chain may be weakened to make a run "look" healthier.
- **Suite mode.** `neptune.sh` exports `NEPTUNE_SUITE=1`; a check two scans can
  both do (double NAT, the persistence listing, listeners) is done once, by the
  owning scan. One problem, one finding.
- **Testable seams.** Pure functions go above the `NEPTUNE_LIB` guard in each
  script, with no side effects at source time; `tests/unit.sh` sources the
  shipping scripts and calls them. Never test a transcription of shipped code.
- **Never widen a destructive glob without tracing it.** The `rm -rf` targets in
  the uninstallers are built from discovery output; a careless glob is how you
  delete someone's home folder. Show, confirm, then delete. A search term must
  match as a WHOLE WORD — bounded by an ASCII non-alphanumeric byte or the
  start/end of the filename — because `-iname "*Mail*"` also matches MailMate.
  Bytes above 0x7F are word characters, so `Mail` never matches `Mailé`.
  Any change to discovery has to keep `tests/blast_radius.sh` green, and if you
  add a new search location, add a decoy for it to that harness in the same
  commit. The harness is the only thing standing between this script and
  someone's data.
- **The vendor catalogue labels, it never suppresses.** `vendor-quirks.tsv`
  attaches a name and a sentence to a finding. It must not change severity,
  scoring, or the acknowledged flag, and no entry may assert that software is
  safe — only describe what it does. Acknowledging stays a deliberate act by the
  person running the tool.
- **The fixer only offers what it can show.** `fix.sh`'s `plan_for` is the one
  table of fixes, keyed by check id like the remediation table. A fix is a
  documented single-purpose command or a hand-off to a confirmed Neptune script;
  commands are plain words (no eval, no pipes, no globbing — tested); deletion
  is never done by `fix.sh` itself. Where no honest one-command fix exists,
  write guidance. A new check id needs a `plan_for` entry — the unit test fails
  on one without a kind or guidance.
- **Prefer editing one script over touching many.** These are independent by
  design; a change to `sentry.sh` should not require changes elsewhere.

## Current priorities

See `ROADMAP.md`. v1.0.0 shipped the fail-closed pipeline, check ids and pass
records, the posture panel, ad-hoc signing as its own class, the cache cleaner,
and tests that source the shipping code on macOS under bash 3.2.

v1.1.0 added the guided fixer (`--fix`) and the Homebrew-catalog comparison
for self-updating apps. v1.2.0 added the phrasebook, the explanation-ladder
report, the fix queue and the AI brief. Two false alarms from real runs are
queued first: an empty launch-agent plist (it runs nothing, so it should not
be an unknown) and a helper whose binary vanished because its app updated
while running (restart the app, not a red flag). After those is **login items from Background Task Management**
(`sfltool dumpbtm`) — which needs a real captured fixture before any parser is
written. Unattended fixing, a bundled model advisor and a Windows sibling are
explicitly NOT planned.
