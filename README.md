# 🔱 Neptune

[![CI](https://github.com/titomazzetta/neptune-mac/actions/workflows/ci.yml/badge.svg)](https://github.com/titomazzetta/neptune-mac/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/titomazzetta/neptune-mac/badge)](https://securityscorecards.dev/viewer/?uri=github.com/titomazzetta/neptune-mac)
[![Release](https://img.shields.io/github/v/release/titomazzetta/neptune-mac)](https://github.com/titomazzetta/neptune-mac/releases)

**An on-demand security audit, tune-up and cleanup kit for macOS. No daemons,
no telemetry, no snake oil.**

Neptune answers three questions about a Mac, shows its work — and then, if you
ask it to, fixes what it found, one confirmed step at a time:

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

The loop is **audit → understand → fix → re-measure**: `./neptune.sh` diagnoses
and changes nothing; `./neptune.sh --fix` walks the findings with the exact
command for each and a y/N per item; the next scan shows the before and after.

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

  ● Several things need you.
    11 to look at · 4 small · 0 couldn't check · 15 passed

    Security   52  ▰▰▰▰▰▱▱▱▱▱     Network    80  ▰▰▰▰▰▰▰▰▱▱
    Tidiness  100  ▰▰▰▰▰▰▰▰▰▰     Updates    95  ▰▰▰▰▰▰▰▰▰▱

  Look at these
     2  Your ISP's box shows up as a second router
        Often just IP passthrough. Your router's WAN address settles it.
     3  SoundID Reference starts at login without a developer signature
        Sonarworks ships it this way. Likely one to keep.
     9  WavesLocalServer accepts connections without a developer signature
        Only this Mac can reach it. Waves ships it this way. Likely one to keep.
  Small things
    13  The firewall is off
        A common default. Worth turning on if this Mac joins public Wi-Fi.
    14  11 formulae have Homebrew updates

  Next   ./neptune.sh --fix                  go through these one at a time
         ./neptune.sh --fix --only <n,n>     just the ones you pick, in that order
         ./neptune.sh --acknowledge <n>      keep something you recognize
```
<sub>(trimmed — the full list has 15 items)</sub>

A verdict, four scores, then one numbered list in plain words, with the next
step. Every run also writes, when python3 is available:

- **an HTML report** that opens with the verdict, a two-line synopsis and the
  scores, then *Protection at a glance* (each control checked, not assumed),
  *Do these next* ranked by what each is worth, the handful of *Recommended
  commands* that apply to this Mac, and every finding explained on a ladder —
  **Simple / Detailed / Technical** — down to what each part of each command
  does and how to undo it. No JavaScript, no network requests when opened; CI
  asserts both.
- **an AI brief** — the findings plus a ready prompt, already sanitized — for
  when something looks unfamiliar and you want a second opinion.
- **the JSON**, for tools, and a plain-text report with every scan's full output.

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
| **A fix runs only as shown.** `--fix` offers one fix per finding with its exact command and waits for `y`; commands run without `eval` or globbing; the fixer itself deletes nothing and logs what it applied. | `tests/unit.sh` "fix.sh" section: every check id has a plan, no command contains a pipe/chain/substitution, no `rm`/`eval` in the fixer |
| **Advice is looked up, never generated.** Every command in the report is one you can find in `man` or Apple's docs, or is Neptune's own; none is a pipeline; an unknown gets "could not check" advice, not the fix for a failure. | `tests/test_render.py` checks every command, every check id, and every `./script --flag` the report tells you to run |
| **Nothing leaves the machine.** Two opt-in flags reach the internet; nothing else does. Homebrew is run with its analytics off. | [`SECURITY.md`](SECURITY.md) gives the one `grep` that proves it |
| **Releases are verifiable.** Built in CI from the tag, with SHA-256 sums and a signed build-provenance attestation. Actions pinned to commit SHAs, least-privilege tokens. | `.github/workflows/release.yml`; `gh attestation verify` |
| **`main` only changes through reviewed, green PRs.** No direct pushes, no force-pushes; all three CI jobs must pass. The rule is a file in the repo, tested against the CI job names, and an independent OpenSSF Scorecard grades the setup weekly. | `.github/rulesets/main.json`; `tests/test_repo.py`; Scorecard badge above |

## Requirements

- **macOS 13 Ventura or later** (run on 13, 15 and 26 — see [Compatibility](#compatibility)), Apple silicon or Intel.
- **An administrator account.** The scan asks for your password once, for the few
  read-only commands that need root to *see* more (every listening socket, root's
  crontab, installed profiles). It never runs as root and never changes anything with it.
- **Nothing to install.** Optional: the Xcode Command Line Tools
  (`xcode-select --install`) for the HTML/JSON reports, which need python3;
  Homebrew, if you use it, is checked for updates and cache bloat.
- **Recommended: Full Disk Access for Terminal** (System Settings → Privacy &
  Security → Full Disk Access → add Terminal). Without it macOS hides a few
  protected folders from Terminal, so some disk-usage numbers read low. Neptune
  does not read your mail, messages or browsing data either way.

## Install

**From a release (verifiable):**

```bash
gh release download --repo titomazzetta/neptune-mac --pattern 'neptune-mac-*.tar.gz' --pattern SHA256SUMS
shasum -a 256 -c SHA256SUMS
gh attestation verify neptune-mac-*.tar.gz --repo titomazzetta/neptune-mac
tar xzf neptune-mac-*.tar.gz && cd neptune-mac-*/scripts
```

The checksum proves the download is intact; the attestation proves it was built
by this repository's release workflow from a tagged commit — not on someone's
laptop. (A browser download adds macOS's quarantine flag; clear it with
`xattr -dr com.apple.quarantine .` after verifying.)

**Or from source:**

```bash
git clone https://github.com/titomazzetta/neptune-mac.git && cd neptune-mac/scripts
```

**Do not run anything with `sudo`** — every script refuses, and asks for
privileges itself only where it needs them.

## Your first run

1. **Scan.** Read-only; takes a few minutes, mostly waiting on `softwareupdate`
   and `brew update`.
   ```bash
   ./neptune.sh
   ```
   One line per scan while it runs (`--verbose` streams everything).
2. **Read.** The terminal ends with a verdict, four scores and one numbered list.
   The HTML report lands on your Desktop (`--out DIR` to change): start at the
   top, and switch to *Detailed* or *Technical* when you want the why and how.
3. **Fix.** Walk the list one item at a time; nothing changes without a `y`.
   Software you recognize gets *k keep / u uninstall / skip* instead.
   ```bash
   ./neptune.sh --fix                 # everything, in list order
   ./neptune.sh --fix --only 13,2,9   # a queue: just these, in this order
   ```
4. **Re-measure.** Accept the re-scan offered at the end. The HTML report shows
   each score's change since the last run — the proof that the fixes worked.

Exit codes make it scriptable: `0` healthy · `1` needs attention ·
`2` incomplete (something could not be checked) · `64` usage error ·
`77` administrator privileges refused.

## Fixing what it found

```bash
./neptune.sh --fix               # walk the last run's list: fix, command, y/N — per item
./neptune.sh --fix --only 13,2   # queue just those items, in that order
./fix.sh --plan                  # what would be offered for each item; changes nothing
```

The HTML report's *Do these next* list ends with the queue command already
filled in, and every finding shows its number, so building your own queue is
editing a list of numbers.

For each numbered finding, `--fix` shows what the fix is, the exact command, and
what kind of change it is — *changes a setting*, *installs or removes software*,
*Neptune command* — then waits for a `y`. It turns on the firewall, disables the
Guest account, installs pending updates, clears Homebrew's cache, hands
cache-clearing and app removal to the confirmed tools below, or opens the right
System Settings pane. For software you might have chosen — an unsigned audio
helper, a licence daemon, Docker's root helper — it asks **k** keep (listed,
no longer costing points), **u** uninstall (through `uninstall.sh`, which shows
every file first), or skip; a double NAT you have confirmed is passthrough can
be kept the same way. Where there is no honest one-command fix — double NAT is a router setting,
FileVault needs you to store a recovery key — it says what to do instead of
inventing a command. It deletes nothing itself, logs every change it applies to
`~/.neptune/fix-log.tsv`, and ends by offering to re-scan.

**Updates, done the way you'd want them:** everything Homebrew and the App Store
manage is upgraded in one confirmed step (`check_updates.sh --upgrade`; Apple's
minor updates install by name, never the major upgrade). Apps that update
themselves are compared against Homebrew's catalog — already on disk, no extra
network call — so the report says *Audacity 3.7.8 → 3.7.9, update it in the app*
instead of just "check your apps".

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
| `neptune.sh` | **Start here.** Runs the five scans, then the verdict, scores, numbered list, and one combined report. `--html`, `--json`, `--sanitize`, `--replay`, `--acknowledge`, `--fix`. | only its own state in `~/.neptune` |
| `fix.sh` | The guided fixer behind `--fix`: each finding's fix with its exact command, applied only on `y`, logged. `--plan` to preview. | **settings and updates you confirm, one at a time**; deletes nothing itself |
| `sentry.sh` | Change detection against a known-good baseline; process→network map with signing; stale apps. | its baseline in `~/.sentry` |
| `redflag_scan.sh` | Security posture; launchd persistence, cron, login hooks, root helpers — each target's signature verified; odd processes; listeners; proxies, profiles, network extensions, `/etc/hosts`; risky browser extensions. | no |
| `network_check.sh` | Double NAT and CGNAT, DNS reliability, gateway latency, per-app connections. | no |
| `audit_system.sh` | Top CPU/memory, kernel and system extensions, and where the disk went — with what is safely reclaimable. | no |
| `check_updates.sh` | macOS, Homebrew and App Store updates; self-updating apps compared against Homebrew's catalog. | only with `--upgrade`, asking first |
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

**A second opinion.** Every run writes `neptune_ai_brief_<date>.md` next to the
report: the findings with a prompt on top, with your computer name, username,
home folder and network addresses replaced (private ranges keep their prefix
and `127.0.0.1` stays, because *only this Mac* versus *your whole network* is
the finding). Paste it into a model when a background process or an old app
looks unfamiliar. The prompt asks for Neptune's own commands rather than
invented `sudo` one-liners — [`docs/advisor.md`](docs/advisor.md) explains why.
`--replay <file>` re-renders any saved result without scanning.

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

## Troubleshooting

| You see | What it means |
|---|---|
| `Could not obtain administrator privileges` (exit 77) | The password prompt was declined, or this account is not an administrator. Nothing was scanned. |
| **COULD NOT BE CHECKED** items, exit 2 | A check could not run — no network for update checks, an unreadable file, a command that gave no answer. Neptune reports that as unknown, never as a pass. The finding says which check and why. |
| No HTML report or AI brief, or `--replay needs python3` | Install the Command Line Tools: `xcode-select --install`. The plain scan works without them, and Neptune never launches the macOS "install developer tools" dialog on its own. |
| `permission denied: ./neptune.sh` | The files lost their executable bit (common with zip downloads): `chmod +x *.sh`, and `xattr -dr com.apple.quarantine .` if macOS blocks them. |
| Disk-usage numbers look low | Terminal lacks Full Disk Access; see [Requirements](#requirements). |
| A finding is software you know and use | `./neptune.sh --acknowledge <n>` (or choose it in `--fix`). It stays listed and counted; it stops costing points. |
| It flagged something and you are not sure | Read the finding's advice in the HTML report, then [`docs/reading-reports.md`](docs/reading-reports.md). If it is a false positive, [open a report](https://github.com/titomazzetta/neptune-mac/issues/new/choose) with the sanitized JSON. |

## What it does not do

It is not antivirus and not a compromise assessment. It has no malware
signatures, does not watch continuously, and cannot see what SIP and TCC hide.
It enumerates what is there, verifies what can be verified, and says plainly
where it could not look. The full list is in [`SECURITY.md`](SECURITY.md).

## Status

Version 1.2.0. See [`CHANGELOG.md`](CHANGELOG.md) for what changed,
[`ROADMAP.md`](ROADMAP.md) for what is next, and
[`CONTRIBUTING.md`](CONTRIBUTING.md) to help. A demo recording is pending; the
recording and scrubbing procedure is in [`docs/demo/RECORDING.md`](docs/demo/RECORDING.md).

Neptune can delete files — always after showing you what and asking. Review the
list before confirming, and keep backups. MIT licensed, no warranty; see
[`LICENSE`](LICENSE).
