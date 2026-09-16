# 🔱 Neptune

**On-demand macOS maintenance and security auditing. No daemons, no telemetry,
no snake oil.**

Neptune is a small suite of independent shell scripts that audit and clean a Mac —
built as the deliberate opposite of the "cleaner" and "antivirus" apps it was
originally written to remove. Everything is transparent, runs only when you invoke
it, and is read-only unless it very explicitly tells you otherwise and asks first.

> **Note:** Neptune is also a portfolio project — an applied demonstration of
> security engineering, systems, and network-defense skills. For the full vision,
> the design philosophy, and what it demonstrates, see
> [`docs/PHILOSOPHY.md`](docs/PHILOSOPHY.md). For the honest engineering story —
> the bugs found and fixed during development — see [`docs/DEVLOG.md`](docs/DEVLOG.md).

## Why it exists

Commercial Mac "cleaners" tend to install background daemons, kernel/endpoint
extensions, and traffic filters that quietly tax the machine they claim to speed
up — while being hard to fully remove. Neptune was born from tearing one of those
out and realizing the *legitimate* jobs it pretended to do (spot unwanted
persistence, find stale software, check for outdated packages, sanity-check the
network) are better done by a handful of readable scripts you run on demand and
can audit yourself.

**Design principles**

- **On-demand, never resident.** No launch agents, no cron, no menu-bar process.
- **Read-only by default.** Only two scripts delete anything, and both show you
  everything and require confirmation first.
- **Modular.** Each script does one job and fails independently.
- **Transparent.** It's all bash you can read. No compiled blobs, no API keys.
- **Human-in-the-loop.** A person is always at the keyboard for destructive steps.
- **No third-party network calls by default.** The full suite contacts nobody.
  Exactly two opt-in flags reach the internet and neither runs unless you ask:
  `network_check.sh --public-ip` (asks api.ipify.org what your public IP is) and
  `netcheck_plus.sh --load` (saturates the link against a public test file to
  measure bufferbloat). Latency checks ping your own gateway and 1.1.1.1.

## The scripts

| Script | What it does |
|---|---|
| `neptune.sh` | **Master runner.** Runs all scans, produces one combined report with an action digest on top. |
| `sentry.sh` | Change detection vs a saved baseline (tripwire-style), process→network map, app staleness. |
| `redflag_scan.sh` | Deep audit: security baseline, all persistence with code-signing, cron/hooks, listeners, traffic interception, browser extensions. |
| `audit_system.sh` | Top resource consumers, persistence with signing, system/kernel extensions, disk-space hogs. |
| `network_check.sh` | NAT topology (double-NAT detection), DNS, latency, per-app connections. |
| `netcheck_plus.sh` | Deep network: Wi-Fi signal quality, bufferbloat, LAN device census, ASUS router settings audit. |
| `check_updates.sh` | Outdated macOS / Homebrew / App Store software; `--upgrade` to install. |
| `uninstall.sh` | Guided complete app removal — finds every related file, shows it, confirms, deletes, verifies. |
| `remove_mackeeper.sh` | Targeted, staged MacKeeper/Clario eradication. Kept as reference methodology. |

## Effects at a glance

What each script actually does to your machine. Full detail, including how to
verify all of it yourself before running anything, is in
[`SECURITY.md`](SECURITY.md).

| Script | Elevates | Writes | Leaves your network |
|---|---|---|---|
| `neptune.sh` | prompts once, shared with children | report to Desktop | — |
| `sentry.sh` | `lsof` | report to Desktop, baseline in `~/.sentry` | ping, DNS, traceroute |
| `redflag_scan.sh` | `lsof`, root crontab, profiles | report to Desktop | — |
| `audit_system.sh` | `du` on system paths | nothing | — |
| `network_check.sh` | no | nothing | ping, DNS, traceroute; `--public-ip` adds api.ipify.org |
| `netcheck_plus.sh` | no | nothing | ping, DNS, ARP sweep; `--load` adds a public test file |
| `check_updates.sh` | only with `--upgrade` | nothing (installs with `--upgrade`) | via `softwareupdate` / `brew` / `mas` |
| `uninstall.sh` | after confirmation | **deletes**, confirmed | — |
| `remove_mackeeper.sh` | after confirmation | **deletes**, confirmed | — |

No script runs wholesale as root — every one refuses to start under `sudo` and
elevates only specific commands. Nothing is installed, scheduled, or left
running: the entire footprint is `~/.sentry` plus the reports on your Desktop.

## Quick start

```bash
git clone https://github.com/<you>/neptune-mac.git
cd neptune-mac/scripts
chmod +x *.sh
xattr -d com.apple.quarantine *.sh 2>/dev/null   # if macOS quarantines them

./neptune.sh          # run the full read-only suite, get one report
```

Reports are written to your Desktop, colors stripped, ready to read or share.

See [`docs/SETUP.md`](docs/SETUP.md) for full setup, contributor, and push notes.

**Do not run these with `sudo`.** They prompt for elevation only where needed.

## Demo

<!-- DEMO EMBED — replace this block once the recording exists.
     Inline GIF (renders and autoplays directly in the README):

![Neptune full suite run](docs/demo/neptune-demo.gif)

     Link out to the asciinema cast (selectable text, seekable, ~50x smaller).
     Keep BOTH: the GIF is what a skimmer sees, the cast is what a reviewer audits.

[![asciicast](https://asciinema.org/a/REPLACE_ID.svg)](https://asciinema.org/a/REPLACE_ID)
-->

> **Recording pending.** The scaffolding below is ready; the cast needs live
> system state, so it's recorded by hand rather than generated in CI. In the
> meantime, [`docs/sample-report.txt`](docs/sample-report.txt) is a real run's
> full output.

<details>
<summary><strong>How to record it</strong> (maintainer notes)</summary>

**Record the cast — this is the source of truth.**

```bash
brew install asciinema agg

# -i 2 caps dead air at 2s. A real ./neptune.sh run spends minutes inside
# lsof sweeps, mdls, traceroute and `brew update`; without this the demo is
# 90% waiting. --cols/--rows keep it legible when scaled down in a README.
asciinema rec docs/demo/neptune-demo.cast \
  -i 2 --cols 100 --rows 30 \
  -c "./scripts/neptune.sh"
```

**Scrub it before committing.** This is the step that matters. A live Neptune
run prints your hostname, your username in every `/Users/...` path, your gateway
and LAN addresses, your full installed-app inventory, and every open listener
port on the machine — a tidy reconnaissance profile of your own Mac. The cast is
plain JSON, so it can be read and sed'd before it ever leaves the machine:

```bash
less docs/demo/neptune-demo.cast          # actually read it
sed -i '' -e "s/$(hostname -s)/demo-mac/g" \
          -e "s|/Users/$USER|/Users/demo|g" \
          docs/demo/neptune-demo.cast
```

Then re-read it and check the addresses by eye. Use the same placeholder
conventions as `docs/sample-report.txt` so the two artifacts agree. Recording on
a scratch user account avoids most of this.

**Generate the inline GIF from the cast** — derived, never recorded separately,
so the two can't drift:

```bash
agg docs/demo/neptune-demo.cast docs/demo/neptune-demo.gif --font-size 14
```

**Then** uncomment the embed block above and fill in the asciinema ID (or drop
the badge line entirely and ship GIF-only — see the trade-off below).

**Keep it short.** Target 45–90 seconds. If a full suite run won't compress into
that, record a single scan (`./scripts/redflag_scan.sh`) plus the final digest
instead — one scan that clearly finds something beats five that scroll past.

</details>

<details>
<summary><strong>Why both formats</strong> (asciinema vs GIF)</summary>

Record **asciinema, publish both** — the GIF generated from the cast.

**GitHub will not render an asciinema player inline.** The badge is a clickable
thumbnail that navigates off-site. Since the stated reason for having a demo is
that reviewers skim, a demo behind a click is a demo most of them won't watch. A
GIF autoplays in the README and costs zero clicks. That alone settles the
*embed* question in the GIF's favor.

But the GIF is a bad *source* artifact: several MB of pixels in a repo that's
otherwise 2,600 lines of readable text, with no selectable output, no diff, and
no way to confirm what it leaks without watching it frame by frame. The `.cast`
is JSON — small enough to sit in the repo permanently, diffable, greppable, and
**auditable before publishing**, which is the whole reason the scrub step above
is even feasible. For a tool whose pitch is "it's all bash you can read," an
opaque binary blob as the only demo artifact is off-message.

So: cast is the source, GIF is the render, `agg` regenerates one from the other.
The skimmer gets autoplay; the reviewer gets something they can verify; and the
artifact you have to trust is the one you can read.

**If you only want to maintain one:** ship the GIF. Inline beats auditable when
the audience is a hiring manager with thirty seconds — just keep it under ~3 MB
and scrub the terminal contents before recording rather than after.

</details>

## Reading the results

Every scan ends with a summary; `neptune.sh` consolidates them into one **action
digest**. Flags are *leads, not verdicts* — legitimate vendor software (audio
tools, Docker, VPNs) routinely fails code-signing checks for benign reasons. See
[`docs/reading-reports.md`](docs/reading-reports.md) for how to tell a real
finding from a vendor quirk, and [`docs/advisor.md`](docs/advisor.md) for using
an LLM to help interpret a report.

**See the actual output:** [`docs/sample-report.txt`](docs/sample-report.txt) is
a real `./neptune.sh` run on a live machine, sanitized (hostname, username,
addresses replaced with obvious placeholders) and committed verbatim otherwise —
rough edges included. It's the fastest way to judge whether this tool is worth
running, without running it.

## Compatibility

macOS, including Intel and Apple Silicon. Scripts target **bash 3.2** (the version
Apple ships) so they run everywhere without installing anything.

## Status & roadmap

Neptune is actively evolving. The next major feature is structured (`--json`)
report output and an orchestrated, interactive `observe → decide → act`
front-end. See [`ROADMAP.md`](ROADMAP.md) for what's planned and
[`CHANGELOG.md`](CHANGELOG.md) for what's changed.

The scripts have been run on live machines throughout, and the most recent audit
pass found and fixed real defects in them — including a signing check that never
read a signature and an uninstaller that stopped processes before asking. Those
are written up in [`docs/DEVLOG.md`](docs/DEVLOG.md), along with a wrong
diagnosis that was caught and retracted. If that record makes the tool look less
polished than a clean README would, that is the intended trade: a security tool
that hides its own history is asking you to trust a claim instead of evidence.

## Safety & disclaimer

Neptune can delete files (via `uninstall.sh` and `remove_mackeeper.sh`), always
after showing you what and asking. You are responsible for reviewing the list
before confirming. Keep backups.

**Read [`SECURITY.md`](SECURITY.md) before the first run.** It documents exactly
what leaves your machine (nothing, by default), what runs as root and why, what
gets written to disk, how to remove Neptune completely, how to verify every one
of those claims yourself with five `grep` commands — and, just as importantly,
what Neptune does *not* detect. A scanner that implies more coverage than it has
is worse than no scanner.

This is a personal tool shared in good faith, with no formal security audit,
provided as-is under the MIT License — no warranty.

## License

MIT. See [`LICENSE`](LICENSE).
