# 🔱 Neptune

**On-demand macOS maintenance and security auditing. No daemons, no telemetry,
no snake oil.**

Neptune is a small suite of independent shell scripts that audit and clean a Mac —
built as the deliberate opposite of the "cleaner" and "antivirus" apps it was
originally written to remove. Everything is transparent, runs only when you invoke
it, and is read-only unless it very explicitly tells you otherwise and asks first.

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

## Quick start

```bash
git clone https://github.com/<you>/neptune-mac.git
cd neptune-mac/scripts
chmod +x *.sh
xattr -d com.apple.quarantine *.sh 2>/dev/null   # if macOS quarantines them

./neptune.sh          # run the full read-only suite, get one report
```

Reports are written to your Desktop, colors stripped, ready to read or share.

**Do not run these with `sudo`.** They prompt for elevation only where needed.

## Reading the results

Every scan ends with a summary; `neptune.sh` consolidates them into one **action
digest**. Flags are *leads, not verdicts* — legitimate vendor software (audio
tools, Docker, VPNs) routinely fails code-signing checks for benign reasons. See
[`docs/reading-reports.md`](docs/reading-reports.md) for how to tell a real
finding from a vendor quirk, and [`docs/advisor.md`](docs/advisor.md) for using
an LLM to help interpret a report.

## Compatibility

macOS, including Intel and Apple Silicon. Scripts target **bash 3.2** (the version
Apple ships) so they run everywhere without installing anything.

## Status & roadmap

Neptune is actively evolving. The current tools are stable and battle-tested. The
next major feature is structured (`--json`) report output and an orchestrated,
interactive `observe → decide → act` front-end. See [`ROADMAP.md`](ROADMAP.md).

## Safety & disclaimer

Neptune can delete files (via `uninstall.sh` and `remove_mackeeper.sh`), always
after showing you what and asking. You are responsible for reviewing the list
before confirming. Keep backups. This is a personal tool shared in good faith,
provided as-is under the MIT License — no warranty.

## License

MIT. See [`LICENSE`](LICENSE).
