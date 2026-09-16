# Changelog

All notable changes to Neptune. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); this project has no release
cadence, so entries are grouped by audit pass rather than version number.

Bug numbers reference entries in [`docs/DEVLOG.md`](docs/DEVLOG.md), which
explains each in full — symptom, root cause, fix, and what was learned.

---

## Audit pass — 2026-09

The first systematic review of the whole suite against live output from a real
machine, rather than against expectation.

### Fixed — correctness

- **Code-signing authority was never read** (DEVLOG Bug 7). `codesign -dv` does
  not emit the certificate chain; `Authority=` only appears at `-dvv`. Every
  signing check in the suite matched nothing, on every binary, since it was
  written. Consequences: all signers rendered `(unknown)`; `sentry.sh`'s
  Apple-detection branch was structurally unreachable so nothing was ever
  classified as an Apple binary; and `check_updates.sh` listed Safari.app as an
  unmanaged third-party app. Six call sites, four scripts.
- **Action digest double-counted and included prose** (DEVLOG Bug 8). It matched
  the numbering of each scan's own summary, so every finding appeared twice, and
  `sort -u` interleaved two scans' numbering. `network_check.sh` explained double
  NAT with seven consecutive `bad()` calls, so one problem became seven findings.
  45 digest lines for 18 real findings, now one line per finding in scan order.
- **`FLAGCOUNT` rendered as a doubled zero** on clean runs — `grep -c` prints `0`
  *and* exits 1, so the `|| echo 0` fallback appended a second zero.
- **`audit_system.sh` reported Apple's own launch daemons as orphaned.**
  `limit.maxfiles` and `limit.maxproc` name a bare command; `redflag_scan.sh`
  resolved these and reported them fine, so the two scans printed opposite
  verdicts on the same plist in the same combined report.
- **LAN census silently dropped devices.** MAC matching assumed zero-padded
  octets, but macOS formats with `ether_ntoa()`, which does not pad — so
  `8:0:27:a:b:c` was invisible. The device count also included `(incomplete)`
  ARP entries and disagreed with the table printed beneath it.

### Fixed — safety

- **`uninstall.sh` terminated processes before the confirmation prompt**, via
  `pkill -f` matching the whole command line case-insensitively. A short search
  term killed an unpredictable set of unrelated programs with no list and no
  prompt, and "Aborted. Nothing was changed." was untrue. Processes are now
  listed read-only, shown in the review list, and signalled by stored PID only
  after confirmation. Terms under three characters skip the scan entirely.
- **Fuzzy app-name matching passed user input to `grep` as a regular
  expression**, and that value flowed into `find -iname`, `pkill -f` and the
  deletion list. Now matched as a literal substring.
- **Two scripts could run wholesale as root.** `audit_system.sh` and
  `check_updates.sh` lacked the `id -u` guard the other seven carried.

### Fixed — privacy

- **The public-IP lookup is now opt-in.** `network_check.sh` queried
  `api.ipify.org` on every run, and `neptune.sh` runs it as part of the standard
  suite — an undisclosed third-party request from a tool that advertises no
  telemetry, with the result written into the report users are told to share.
  Now behind `--public-ip`.

### Changed

- **Ephemeral listener ports are collapsed in the baseline** (ROADMAP #5). Seven
  of ten flags on a clean machine were `rapportd` and Splice holding different
  dynamic ports than last boot. Ports in 49152–65535 are recorded as
  `:ephemeral`; a new listening process or one moving from loopback to all
  interfaces is still flagged. **Existing baselines are replaced once** on first
  run after this change, with an explicit notice — a cross-format diff would look
  like dozens of new listeners.
- **A security check that cannot run now says so.** The firewall check read a
  source that returns nothing on current macOS and fell through to an unprefixed
  note, while the summary reported an otherwise clean baseline. It now tries
  `socketfilterfw` first and emits `[!!]` if every source is unreadable.
- **`network_check.sh` discloses its blind spot** — it calls `lsof` unprivileged,
  so its connection census sees only the current user's processes.
- Subnet sweep is throttled to batches of 32 with an explicit `wait`, instead of
  254 simultaneous pings followed by a three-second guess.

### Added

- [`SECURITY.md`](SECURITY.md) — threat model, exactly what leaves the machine,
  what runs as root and why, everything written to disk, complete removal
  instructions, five `grep` commands to verify every claim independently, and an
  explicit list of what Neptune does *not* detect.
- [`docs/sample-report.txt`](docs/sample-report.txt) — a real sanitized run, so
  the output can be judged without running anything.
- A Demo section in the README with recording scaffolding.
- This changelog.

### Documentation

- DEVLOG Bugs 6, 7 and 8.
- **A retraction.** A wrong diagnosis got five commits, a CI gate and a full
  devlog entry before being caught by a verification step on the actual target
  machine. All of it was reverted, and the episode is documented in the DEVLOG
  under "Correction — a bug that did not exist". A development log that drops its
  own worst moment isn't a development log.
- Corrected a script miscount in `CLAUDE.md` and `PHILOSOPHY.md` — there are
  nine scripts, not ten.
- `tests/lint.sh` and CI unchanged in scope, still green.

---

## Earlier

Development history before this audit pass is recorded in
[`docs/DEVLOG.md`](docs/DEVLOG.md) as Bugs 1–5: the false "all clear" from a
subshell-scoped array, `lsof` selector OR-semantics, the bash 3.2 `case`-in-`$()`
parser crash, the empty-array crash under `set -u` found on someone else's Mac,
and the double-NAT detector's false negative.
