# Security & data handling

Neptune asks you to run shell scripts on your Mac, some of them with `sudo`, and
two of them delete files as root. That is a lot of trust to ask for. This document
exists so you can grant it deliberately rather than hopefully.

Read it before the first run. Everything here is verifiable from the source in
this repository — nothing below relies on taking the author's word.

---

## What leaves your machine

**By default: nothing.** No telemetry, no analytics, no crash reporting, no
"anonymous usage statistics", no update check, no API keys, no accounts. Neptune
has no server side. The scripts contain no credentials and no bundled binaries.

Network activity is limited to the following, and you can confirm each by reading
the scripts:

| What | Where | When |
|---|---|---|
| ICMP ping to your own gateway | your LAN | latency checks |
| ICMP ping / traceroute to `1.1.1.1` | Cloudflare DNS | latency, double-NAT detection |
| DNS lookups (`apple.com`, `example.org`, …) | your configured resolver | DNS timing |
| ARP sweep of your own subnet | your LAN | `netcheck_plus.sh` device census |
| HTTPS to `api.ipify.org` | third party | **only** with `network_check.sh --public-ip` |
| HTTPS to a public 100MB test file | third party | **only** with `netcheck_plus.sh --load` |

The last two are opt-in and off unless you pass the flag. Everything else is your
own network and the same public DNS resolver your machine already uses.

`check_updates.sh` invokes `softwareupdate`, `brew` and `mas` if installed. Those
are Apple's and Homebrew's own tools making their own normal network requests —
Neptune does not proxy, wrap, or inspect them.

To confirm all of the above yourself:

```bash
grep -rnE 'curl|wget|nc |ftp|https?://' scripts/
```

That returns exactly three hits, and you should expect all three:

- `network_check.sh` — the `api.ipify.org` lookup, inside `if $PUBLIC_IP`.
- `netcheck_plus.sh` — the bufferbloat test file, inside `if $LOAD`.
- `check_updates.sh` — **not a network call.** It is the Homebrew install
  command printed as text, inside `note '...'` single quotes, shown to you when
  `brew` is missing. Nothing executes it.

If you ever get a fourth hit, something has changed that this document does not
describe.

---

## What runs as root, and exactly why

No script runs wholesale as root. Every script **refuses to start** under `sudo`
(`id -u` check) because running the whole thing elevated is unnecessary and would
write root-owned files into your home directory. Instead each prompts once, caches
the credential, and elevates only specific commands.

| Script | Elevates? | What needs it |
|---|---|---|
| `neptune.sh` | prompts once, passes to children | see below |
| `sentry.sh` | yes | `lsof` (see all listeners, not just yours) |
| `redflag_scan.sh` | yes | `lsof`, root crontab, `profiles list`, firewall state |
| `audit_system.sh` | yes | `du` on `/Library`, `/private/var` |
| `network_check.sh` | **no** | — |
| `netcheck_plus.sh` | **no** | — |
| `check_updates.sh` | only with `--upgrade` | installing updates |
| `uninstall.sh` | yes, after confirmation | removing files outside `$HOME` |
| `remove_mackeeper.sh` | yes, after confirmation | removing files outside `$HOME` |

The read-only scans use root to *see more*, never to change anything.

---

## What gets written to disk

Neptune installs nothing. There is no launch agent, no daemon, no login item, no
cron entry, no menu-bar process, nothing scheduled. It runs when you run it and
then it is gone.

It writes three kinds of file — reports, its own small state, and (only when
you ask for it) structured findings:

| Path | What | Written by |
|---|---|---|
| `~/Desktop/neptune_full_report_*.txt` | combined report | `neptune.sh` |
| `~/Desktop/sentry_report_*.txt` | scan report | `sentry.sh` |
| `~/Desktop/redflag_report_*.txt` | scan report | `redflag_scan.sh` |
| `~/.sentry/baseline.txt` | known-good snapshot | `sentry.sh` |
| `~/.sentry/current.txt` | latest snapshot | `sentry.sh` |
| `~/.sentry/format` | baseline format version | `sentry.sh` |
| `~/.neptune/allow` | findings you acknowledged as known-good | `neptune.sh --acknowledge` |
| `~/Desktop/neptune_findings_*.json` | structured findings | `neptune.sh --json` |
| `~/Desktop/neptune_report_*.html` | readable report with remediation | `neptune.sh --html` |
| `~/.neptune/history.tsv` | one line per run: date, verdict, four scores, four counts | every `neptune.sh` run |

`history.tsv` deserves its own sentence, because a file that accumulates is the
shape telemetry usually takes. It is tab-separated plain text, it holds ten
numbers and a date per run and nothing about individual findings, it never
leaves the machine, and `rm ~/.neptune/history.tsv` ends it with no other
consequence than losing the comparison in the next HTML report. It exists so a
second run can answer "did what I did help?" — a findings list alone cannot.

The HTML report contains **no JavaScript, no external stylesheet, no webfont and
no image request**. Opening it makes no network connections, and you can read
the whole file in a text editor. That is deliberate: a security report you have
to trust in order to read is not much of a security report. Verify it:

```bash
grep -ci '<script' ~/Desktop/neptune_report_*.html    # expect: 0
grep -c 'https\?://' ~/Desktop/neptune_report_*.html  # expect: 0
```

**Reports contain sensitive information about your machine**: hostname, your
username in file paths, LAN addresses, your installed application inventory, and
every listening port. Treat a report like a system inventory, because that is what
it is. `docs/sample-report.txt` shows the shape of one with those values replaced.

The same applies to `--json` output, which is likely to get pasted somewhere —
into an issue, a chat window, an LLM. Use `--sanitize` for anything
leaving the machine — it applies to `--json` and `--html` alike, and replaces
hostname, username, every `/Users/<name>` path regardless of whose it is, IP
addresses and MAC addresses, so you share the findings without the
fingerprint. Neptune does not
upload either file anywhere; moving it is your decision and your action.

### Removing Neptune completely

```bash
rm -rf ~/.sentry ~/.neptune           # the only state it keeps
rm -f ~/Desktop/neptune_full_report_*.txt \
      ~/Desktop/sentry_report_*.txt \
      ~/Desktop/redflag_report_*.txt \
      ~/Desktop/neptune_findings_*.json \
      ~/Desktop/neptune_report_*.html      # your reports
rm -rf /path/to/neptune-mac           # the repo itself
```

That is the whole footprint. A tool built as the opposite of a "cleaner" owes you
an uninstall that fits in three commands.

---

## Verify before you run

Neptune is readable bash, on purpose. You are encouraged to check it rather than
trust it.

```bash
# 1. Read the two scripts that can delete things. They are the only ones that
#    matter for safety, and both are under 300 lines.
less scripts/uninstall.sh
less scripts/remove_mackeeper.sh

# 2. Find every rm in the project.
grep -n 'rm -rf' scripts/*.sh
```

Three files match, and the third is not what it looks like:

- `uninstall.sh`, `remove_mackeeper.sh` — the real deletions, both behind the
  confirmation gate.
- `neptune.sh` — `rm -rf "$TMP"` in an `EXIT` trap, removing the `mktemp -d`
  scratch directory it created for itself. It never touches your files.

```bash
# 3. Confirm the confirmation prompts exist and no flag can skip them.
grep -n 'y/N' scripts/*.sh
grep -rnE '\-\-force|\-\-yes' scripts/          # expect: no output

# 4. Confirm nothing phones home (see the table above for the three expected hits).
grep -rnE 'curl|wget|https?://' scripts/

# 5. Confirm nothing INSTALLS persistence.
grep -rnE 'launchctl|crontab|LaunchAgents' scripts/
```

Step 5 returns a lot, and all of it should be reads or removals. Neptune
enumerates persistence, so it naturally mentions these constantly. What matters
is the verb: you will find `launchctl list`, `launchctl print`, `launchctl
bootout` (unload), and `crontab -l` (list). You should find **no** `launchctl
load`, `launchctl bootstrap`, or `crontab -` writing a new entry, and no script
that creates a `.plist` in any `LaunchAgents` directory. Neptune installs no
persistence of its own — that is the entire premise of the project.

Neptune is distributed as source only. There is no installer, no package, no
`curl | bash` one-liner — and there never will be, because the whole point is that
you can read what you are about to run.

---

## The destructive scripts

`uninstall.sh` and `remove_mackeeper.sh` are the only scripts that delete
anything. Both follow the same shape:

1. **Discover** — find every related file, read-only.
2. **Show** — print the complete list, with sizes, before anything happens.
3. **Confirm** — require a typed `y`. Anything else aborts.
4. **Act** — delete only what was displayed.
5. **Verify** — re-scan and report what remains.

Deliberate design decisions:

- **No `--force` / `--yes` flag.** There is no way to skip the confirmation.
  Adding one is explicitly forbidden in `CONTRIBUTING.md`.
- **No unattended mode.** A person is at the keyboard when files are removed as
  root. That is the safety property; automating it away would remove it.
- **Process termination happens after the prompt, by PID.** The script lists the
  processes it intends to stop, gets your agreement, then signals exactly those
  process IDs — not a fresh pattern match that might catch something started in
  the meantime. (This was not always true; see `docs/DEVLOG.md`.)
- **Search terms are matched literally, not as regular expressions**, and terms
  under three characters skip the process scan entirely.

If you abort at the prompt, nothing on your system has been changed.

---

## What Neptune does NOT do

A scanner that implies more coverage than it has is worse than no scanner. Neptune
does not:

- **Detect malware by signature or behaviour.** It has no threat database and
  makes no attempt at one. It enumerates persistence, listeners and interception
  points and tells you what is there. Deciding what belongs is your job, with
  `docs/reading-reports.md` to help. Real-time protection is XProtect's and
  Gatekeeper's job and Neptune does not duplicate it badly.
- **Prove a machine is clean.** A determined attacker with root can hide from
  every tool listed here, Neptune included. It raises the floor; it is not a
  compromise assessment.
- **Inspect kernel memory, firmware, or the Secure Enclave.**
- **See processes or files that SIP and TCC hide**, or files in locations Terminal
  lacks Full Disk Access for. Where it cannot look, it says so.
- **Monitor continuously.** It is a snapshot. Between runs, nothing is watching —
  that is the trade for having nothing resident.
- **Work on anything but macOS.** It is built on `launchctl`, `codesign`, `lsof`,
  `scutil` and `system_profiler`.

Coverage gaps that are known and specific:

- `network_check.sh` runs `lsof` unprivileged, so its connection census shows only
  your own processes. It says so in its output. `sentry.sh` and `redflag_scan.sh`
  elevate and do cover root-owned daemons.
- Spotlight-based staleness detection misses apps launched via helpers or excluded
  from indexing. Those are listed separately and explicitly marked unreliable.
- The system-proxy check is correct on the evidence available but has not been
  verified against a machine with a proxy actively configured. See `ROADMAP.md`.

---

## Reporting a problem

If you find a bug that causes Neptune to delete something it shouldn't, to report
a false "all clear", or to leak data off the machine, please open an issue — or
if you'd rather not do so publicly, contact the maintainer directly through the
address on the GitHub profile.

A false "all clear" is treated as the most serious class of bug in this project,
above crashes. `docs/DEVLOG.md` documents every one found so far, including the
ones that were embarrassing.

---

## Honest limitations of this document

This is a personal project, not an audited product. It has no formal security
review, no third-party audit, and no guarantee of maintenance. It is offered
under the MIT licence with no warranty — see `LICENSE`.

What it does have is source you can read in an afternoon and a development log
that does not hide the mistakes.
