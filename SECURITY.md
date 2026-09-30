# Security & data handling

Neptune asks you to run shell scripts on your Mac, some of them with `sudo`, and
three of them delete files — two as root, one (the cache cleaner) as you. That is a lot of trust to ask for. This document
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
| HTTPS to `speed.cloudflare.com` (up to 100 MB, 8 s cap) | third party | **only** with `netcheck_plus.sh --load` |

The last two are opt-in and off unless you pass the flag. Everything else is your
own network and the same public DNS resolver your machine already uses.

`check_updates.sh` invokes `softwareupdate`, `brew` and `mas` if installed. Those
are Apple's and Homebrew's own tools making their own normal network requests —
Neptune does not proxy, wrap, or inspect them. It does run every `brew` command
with `HOMEBREW_NO_ANALYTICS=1`: Homebrew sends install analytics by default, and
a tool whose premise is "no telemetry" should not cause any on your behalf.

To confirm all of the above yourself:

```bash
grep -rnE '\bcurl\b|\bwget\b|https?://' scripts/
```

That returns three places, and you should expect all three:

- `network_check.sh` — the `api.ipify.org` lookup, inside `if $PUBLIC_IP`.
- `netcheck_plus.sh` — the Cloudflare speed-test download (two lines, one
  command), inside `if $LOAD`. It checks that the download actually happened
  and discards the result if not, rather than reporting "no bufferbloat" from a
  test that never loaded the link.
- `check_updates.sh` — **not a network call.** It prints `https://brew.sh` as
  text when Homebrew is missing. Nothing fetches it.

If you ever find a fourth, something has changed that this document does not
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
| `check_updates.sh` | only with `--upgrade` | installing updates, one label at a time |
| `uninstall.sh` | yes, after confirmation | removing files outside `$HOME` |
| `remove_mackeeper.sh` | yes, after confirmation | removing files outside `$HOME` |
| `clean_caches.sh` | **never** | your caches are yours; it refuses to run as root |

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
| `~/.neptune/seen.tsv` | one line per finding: its key, first seen, last seen, run count | every `neptune.sh` run |
| `~/.neptune/last-listing.tsv` | the numbered list from your last run | every `neptune.sh` run |

`--out DIR` moves every report — including the ones `sentry.sh` and
`redflag_scan.sh` write for themselves — to `DIR` instead of the Desktop.
`--replay` writes no state at all.

`last-listing.tsv` is what makes `--acknowledge 5` mean item 5 *of the list you
read*, not item 5 of a fresh scan whose numbering may have shifted. It holds the
same titles the report shows.

`seen.tsv` holds the same kind of thing at finding granularity — the
digit-collapsed key `--acknowledge` already uses, plus two dates and a counter —
so a report can say "flagged in each of the last six runs" instead of "flagged".
A finding that stops appearing keeps its row with the date it was last seen,
which is the record of something being fixed. Same terms as below: local, plain
text, one `rm` to forget.

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

### Before you trust the uninstallers

`uninstall.sh` and `remove_mackeeper.sh` are the only things here that delete,
and both run `rm -rf` as root. Two things you can check rather than take on
faith:

```bash
./uninstall.sh "Some App" --dry-run     # the exact delete set, then it stops
./tests/blast_radius.sh                  # the test suite behind that claim
```

`--dry-run` prints the set and exits before the confirmation prompt and before
`sudo` is requested. That set is not a description of intent — it is the list
the delete stage then works from, and a test compares the two directly by doing
a real removal inside a sandbox.

`tests/blast_radius.sh` builds a fake macOS layout in a temp directory, with
decoys that deliberately collide with the target's name, vendor and bundle-id
prefix, and asserts that the target's files are all found and that nothing else
is. It found a real over-match the first time it ran: `./uninstall.sh Dovetail`
also selected `DovetailPro`'s preferences, because discovery matched the name as
a substring rather than as a whole word. On a real Mac that is
`./uninstall.sh Mail` taking MailMate's data with it.

The harness works through `NEPTUNE_ROOT`, an environment variable that prefixes
every system path the destructive scripts touch. It can only ever **narrow**
what they reach — every path is built from the prefix and discovery only looks
inside it — and while it is set, `sudo` is refused outright and the script says
so on screen. If `HOME` is not inside that prefix, or contains `..`, the script
refuses to run at all rather than redirect half of itself.

### Removing Neptune completely

```bash
rm -rf ~/.sentry ~/.neptune           # the only state it keeps (allow,
                                      # history.tsv, seen.tsv, last-listing.tsv)
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
# 1. Read the three scripts that can delete things. They are the only ones
#    that matter for safety.
less scripts/uninstall.sh
less scripts/remove_mackeeper.sh
less scripts/clean_caches.sh

# 2. Find every rm in the project.
grep -n 'rm -rf' scripts/*.sh
```

Four files match, and the fourth is not what it looks like:

- `uninstall.sh`, `remove_mackeeper.sh` — the real deletions, both behind the
  confirmation gate. (One `uninstall.sh` hit is a comment.)
- `clean_caches.sh` — empties the cache folders you picked by number, after you
  typed `yes`; it re-checks each one is a real folder, not a symlink, at the
  moment of deletion.
- `neptune.sh` — `rm -rf "$TMP"` in an `EXIT` trap, removing the `mktemp -d`
  scratch directory it created for itself. It never touches your files.

```bash
# 3. Confirm the confirmation prompts exist and no flag can skip them.
grep -nE 'read -r?.*(y/N|yes)' scripts/*.sh
grep -nE '^\s*--?(yes|force)\)' scripts/*.sh     # expect: no output (no flag parses)

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

`uninstall.sh`, `remove_mackeeper.sh` and `clean_caches.sh` are the only scripts
that delete anything. All three follow the same shape:

1. **Discover** — find every related file, read-only.
2. **Show** — print the complete list, with sizes, before anything happens.
3. **Confirm** — require a typed answer (`y` for the uninstallers, the whole
   word `yes` for the cache cleaner). Anything else aborts.
4. **Act** — delete only what was displayed.
5. **Verify** — re-scan and report what remains.

`clean_caches.sh` is deliberately narrow: only the *contents* of folders
directly inside `~/Library/Caches`, only ones you pick by number, never Apple's
own caches, iCloud state or Homebrew's (which `brew cleanup` owns), never a
symlink, never as root. A selection it cannot parse exactly — `9` when there
are eight items, `2-x` — is refused whole rather than guessed at.

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
- **Word boundaries are ASCII punctuation only.** `./uninstall.sh Mail` matches
  `Mail` and `com.apple.mail.plist`, never `MailMate` — and never `Mailé`
  either: a non-ASCII letter continues a word rather than ending it.

All three are exercised by `tests/blast_radius.sh` on every CI run, against a
fake filesystem full of decoys, including a "cache" that is really a symlink
into `~/Documents`.

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
- The system-proxy check is tested against a captured configured-proxy
  fixture, but has not been run on a machine with a proxy actively configured.
- Login items registered through Apple's newer `SMAppService` API live in the
  Background Task Management database, not in a `LaunchAgents` folder, and are
  not yet enumerated. They still show up as running processes and listeners.
  This is the next item in `ROADMAP.md`.

---

## Verifying a release

Releases are built by GitHub Actions from the tagged commit, never on a
laptop. Each one ships a `SHA256SUMS` file and a signed build-provenance
attestation that ties the tarball to the exact workflow run and commit that
produced it:

```bash
shasum -a 256 -c SHA256SUMS
gh attestation verify neptune-mac-v1.0.0.tar.gz --repo titomazzetta/neptune-mac
```

The CI that builds them runs with a read-only token by default, pins every
action to a full commit SHA (a tag can be moved; a SHA cannot), never persists
credentials into the checkout, and grants write access only to the one release
job that needs it. Dependabot keeps the pins current. See
`.github/workflows/`.

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
