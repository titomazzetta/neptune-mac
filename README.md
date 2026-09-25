# 🔱 Neptune

[![CI](https://github.com/titomazzetta/neptune-mac/actions/workflows/ci.yml/badge.svg)](https://github.com/titomazzetta/neptune-mac/actions/workflows/ci.yml)

**An on-demand security audit and cleanup kit for macOS. No daemons, no
telemetry, no snake oil.**

Neptune answers three questions about a Mac, and shows its work:

1. **Is it secure?** Disk encryption, SIP, Gatekeeper, firewall, update
   policy, every third-party launch item and root helper with its code
   signature verified, processes running from odd places, network listeners,
   proxies, profiles and other ways traffic gets intercepted.
2. **Is anything running that shouldn't be?** What changed since your last
   known-good snapshot, which unsigned or ad-hoc-signed programs are talking to
   the network, and what persists across a reboot.
3. **What is it carrying that it doesn't need?** Stale apps, oversized caches,
   developer junk, pending updates, and a way to clear what you choose without
   touching what you didn't.

It is a set of readable bash scripts, built as the deliberate opposite of the
"cleaner" apps it was first written to remove. They run only when you run them,
change nothing unless they tell you exactly what and ask first, and never phone
home.

> Neptune is also a portfolio project: an applied demonstration of security
> engineering judgment. The design reasoning is in
> [`docs/PHILOSOPHY.md`](docs/PHILOSOPHY.md), the architecture in
> [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), and every bug found along the
> way — including the embarrassing ones — in [`docs/DEVLOG.md`](docs/DEVLOG.md).

## What a run tells you

```
$ ./neptune.sh --replay tests/fixtures/findings-2026-09-18.txt     # a real run, replayed

NEEDS ATTENTION

  security      52/100  [#####.....]
  network       80/100  [########..]
  bloat        100/100  [##########]
  maintenance   95/100  [#########.]

  15 checks passed · 11 attention · 4 minor · 0 could not run · 0 acknowledged · 2 informational

  NEEDS ATTENTION
    5. [security] UNSIGNED persistence: com.docker.socket runs /Library/PrivilegedHelperTools/com.docker.socket (/Library/LaunchDaemons/com.docker.socket.plist)
       known Docker pattern — see the HTML report for what it is
   11. [network] SECOND PRIVATE ROUTER in path: 10.0.0.1 (beyond your gateway 192.168.1.1)
  MINOR
   13. [security] Application firewall is OFF — a common default, but worth enabling on any machine that joins public Wi-Fi
   14. [maintenance] 11 Homebrew formulae have updates available
```

A verdict first, then four scores, then one numbered list of what to do. Add
`--html` for a report that **proves what it covered**: a posture panel showing
each security control as checked-and-passed, failed, or could-not-check; every
finding with what it means in plain English, what to do, and the exact command
labelled `reads only` / `changes a setting` / `installs or removes software`;
and every check that passed. The page has no JavaScript and makes no network
requests when opened — CI asserts both.

## Why you can trust the answer

A security tool is only as good as its failure modes. These are Neptune's, and
each one is enforced by a test, not a promise:

| Guarantee | How it is enforced |
|---|---|
| **An error can never read as "healthy."** A scan that crashes, is missing, or records nothing becomes an *unknown* finding; a scoring step that loses a record fails the report's integrity check; an unknown is never a pass. | `nep_run_pipeline` fail-closed checks; `tests/unit.sh` "Fail closed" section |
| **Exit codes you can script against.** `0` healthy · `1` needs attention · `2` incomplete · `64` usage · `77` no privileges. | `nep_exit_status`; asserted in unit tests and against a real macOS run in CI |
| **Runs on a stock Mac.** bash 3.2 (2007) and BWK awk, the versions Apple ships — every script runs in the C locale because macOS awk *aborts* mid-program on half a UTF-8 character ([Bug 13](docs/DEVLOG.md)). | Grep gates for 3.2 traps; the macOS CI job runs everything under `/bin/bash` 3.2 |
| **Deletes only what it showed you.** The three destructive scripts list first, need a typed confirmation, have no `--yes`, and are tested against a fake filesystem of decoys — including a "cache" symlinked into `~/Documents`. | `tests/blast_radius.sh` (45 assertions), including a real sandboxed delete compared against the dry run |
| **Ad-hoc signed is not "signed."** A valid signature with no developer identity — what commodity Mac malware ships with — is its own class, not a pass ([Bug 16](docs/DEVLOG.md)). | Five-class `sig()` tested against captured `codesign` output and a binary CI signs ad hoc itself |
| **Advice is looked up, never generated.** Every command in the report is one you can find in `man` or Apple's docs, or is Neptune's own; none is a pipeline; an unknown gets "could not check" advice, not the fix for a failure. | `tests/test_render.py` checks every command, every check id, and every `./script --flag` the report tells you to run |
| **Nothing leaves the machine.** Two opt-in flags reach the internet; nothing else does. Homebrew is run with its analytics off. | [`SECURITY.md`](SECURITY.md) gives the one `grep` that proves it |
| **Releases are verifiable.** Built in CI from the tag, with SHA-256 sums and a signed build-provenance attestation. Actions pinned to commit SHAs, least-privilege tokens. | `.github/workflows/release.yml`; `gh attestation verify` |

## Quick start

```bash
git clone https://github.com/titomazzetta/neptune-mac.git
cd neptune-mac/scripts

./neptune.sh              # the full read-only suite: verdict, scores, one report
./neptune.sh --html       # ...plus the readable report with posture and advice
```

It asks for your password once, for the handful of commands that need root to
*see* more (listening sockets, root's crontab, installed profiles); it never
changes anything with it. **Do not run it with `sudo`** — every script refuses.

Nothing to install. `--html` and `--json` need python3, which comes with the
Xcode Command Line Tools (`xcode-select --install`); the scan itself does not.

## Cleaning and de-bloating

Diagnosis first, then only what you choose:

```bash
./clean_caches.sh                     # your caches by size — changes nothing
./clean_caches.sh --apply             # pick by number, see exactly what goes, type "yes"
./uninstall.sh "Some App" --dry-run   # every file an app left behind, then stop
./uninstall.sh "Some App"             # ...then remove it, after you confirm
./check_updates.sh --upgrade          # asks before each source; never a major macOS upgrade
```

`clean_caches.sh` empties cache folders you pick, never Apple's own, iCloud's,
or Homebrew's (it points you at `brew cleanup` instead), never through a symlink,
and never as root. It marks the caches that are slow to rebuild — sample
libraries, plug-in scans — so "clear everything" is a choice you make knowingly.

## The scripts

| Script | What it does | Changes anything? |
|---|---|---|
| `neptune.sh` | **Start here.** Runs the five scans, then the verdict, scores, numbered list, and one combined report. `--html`, `--json`, `--sanitize`, `--replay`, `--acknowledge`. | only its own state in `~/.neptune` |
| `sentry.sh` | Change detection against a known-good baseline; process→network map with signing; stale apps. | its baseline in `~/.sentry` |
| `redflag_scan.sh` | Security posture; launchd persistence, cron, login hooks, root helpers — each target's signature verified; odd processes; listeners; proxies, profiles, network extensions, `/etc/hosts`; risky browser extensions. | no |
| `network_check.sh` | Double NAT and CGNAT, DNS reliability, gateway latency, per-app connections. | no |
| `audit_system.sh` | Top CPU/memory, kernel and system extensions, and where the disk went — with what is safely reclaimable. | no |
| `check_updates.sh` | macOS, Homebrew and App Store updates; apps nothing updates for you. | only with `--upgrade`, asking first |
| `clean_caches.sh` | Cache inventory; clears what you pick. | **yes** — confirmed; nothing without `--apply` |
| `uninstall.sh` | Complete app removal: finds every related file, shows it, confirms, deletes, verifies. | **yes** — confirmed; nothing with `--dry-run` |
| `remove_mackeeper.sh` | Staged MacKeeper/Clario removal — the job that started this project. | **yes** — confirmed; nothing with `--dry-run` |
| `netcheck_plus.sh` | Standalone deep network check: Wi-Fi quality, bufferbloat, a LAN device census that marks randomized MACs, and a router-settings checklist. | no |

The full footprint — every file written, every command elevated, every packet
sent — is in [`SECURITY.md`](SECURITY.md), with the commands to verify each
claim and to remove Neptune completely.

## Living with it

**Acknowledging vendor quirks.** Legitimate software fails signing checks all
the time: audio licence daemons, Docker's root helper. Neptune names the ones it
knows (`known Docker pattern`) but never decides for you that they are fine.
When you have decided, `./neptune.sh --acknowledge 5` (or `5,7`) marks item 5
*of the list you just read* — the numbering is saved, so it cannot drift under
you. Acknowledged findings stay listed and counted; they only stop deducting.

**Re-running.** Each run records its scores and when each finding was first and
last seen, so the next report shows what moved and what you fixed. Local plain
text in `~/.neptune`; delete it to forget.

**A second opinion.** `./neptune.sh --json --sanitize` exports the findings
with hostname, user, paths, IPs and MACs replaced, ready to hand to a colleague
or a model — [`docs/advisor.md`](docs/advisor.md) has the prompt that keeps a
model from inventing `sudo` one-liners. `--replay <file>` re-renders any saved
result without scanning.

**Reading the results.** A flag is a lead, not a verdict. [`docs/reading-reports.md`](docs/reading-reports.md)
covers telling a real finding from a vendor habit.
[`docs/sample-report.txt`](docs/sample-report.txt) is a real run, sanitized.

## Compatibility

Targets **bash 3.2 and BWK awk** as Apple ships them, so it runs on a stock Mac
with nothing installed. CI runs the full test suite on macOS under `/bin/bash`
3.2, plus a real end-to-end run of the suite on the runner.

| macOS | Hardware | Status |
|---|---|---|
| 26 Tahoe (26.6.2) | Apple Silicon | Primary development machine. Every scan, both uninstallers, full suite. |
| 15 Sequoia | Apple Silicon | Full suite, on someone else's machine — where DEVLOG Bug 4 surfaced. |
| 13 Ventura | Intel | Read-only scans only. |

Not tested: macOS 12 and earlier.

**Known deprecation risk.** The firewall check uses `socketfilterfw`, which
Apple has been moving away from. If it stops answering, the check reports
*could not be determined* — an unknown, which costs points and exits 2 — rather
than assuming the firewall is on. A check that silently degrades to "fine" is
how a security tool starts lying to you.

## What it does not do

It is not antivirus and not a compromise assessment. It has no malware
signatures, does not watch continuously, and cannot see what SIP and TCC hide.
It enumerates what is there, verifies what can be verified, and says plainly
where it could not look. The full list is in [`SECURITY.md`](SECURITY.md).

## Status

Version 1.0.0. See [`CHANGELOG.md`](CHANGELOG.md) for what changed,
[`ROADMAP.md`](ROADMAP.md) for what is next, and
[`CONTRIBUTING.md`](CONTRIBUTING.md) to help. A demo recording is pending; the
recording and scrubbing procedure is in [`docs/demo/RECORDING.md`](docs/demo/RECORDING.md).

Neptune can delete files — always after showing you what and asking. Review the
list before confirming, and keep backups. MIT licensed, no warranty; see
[`LICENSE`](LICENSE).
