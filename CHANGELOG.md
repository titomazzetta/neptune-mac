# Changelog

All notable changes to Neptune. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); this project has no release
cadence, so entries are grouped by audit pass rather than version number.

Bug numbers reference entries in [`docs/DEVLOG.md`](docs/DEVLOG.md), which
explains each in full — symptom, root cause, fix, and what was learned.

---

## Readable reports and the re-measure loop — 2026-09-19

The verdict layer answered "is this machine OK?". This answers "so what do I do,
and did it help?".

### Added
- **`--html`** — a readable report next to the text one. Every finding opens
  into what it means, what to do, and the command to do it, each command
  labelled `reads only` / `changes a setting` / `installs or removes software` /
  `Neptune command`. No JavaScript, no external stylesheet, no webfont, no image
  request: opening it makes no network connections, and CI asserts that.
- **Remediation table**, shared by `--json` and `--html` from a single renderer.
  Nothing generated, no pipelines or chains, and an honest "no automated
  suggestion" where none exists. `tests/unit.sh` asserts all three rules against
  the real table, extracted from `neptune.sh` rather than re-implemented.
- **`~/.neptune/history.tsv`** — one tab-separated line per run: date, verdict,
  four scores, four counts. The next HTML report shows what each category did
  since last time. Local plain text, nothing about individual findings, deleted
  with one `rm`.
- **`--sanitize` now applies to `--html`** as well as `--json`, and replaces any
  `/Users/<name>` path rather than only the one matching `$USER` — a finding can
  name another account's home directory, and "the variable happened to match" is
  not a sanitiser.
- **CI renderer smoke test** — builds JSON and HTML from the real-world fixture
  on every push and asserts the HTML is well-formed, script-free and
  self-contained.

### Fixed
- **`--json` crashed on the first finding of a real report.** The acknowledge
  key was truncated with `substr(key, 1, 90)`, which counts bytes; cutting an
  em-dash in half left an invalid UTF-8 sequence that python refused to decode.
  Truncation now cuts back to the previous space, and records are read with
  `errors="replace"`. (Bug 10)
- `codesign -dvv` suggestions pointed at the `.plist` rather than the binary it
  launches, which tells you nothing about the signature.

### Note on upgrading
The acknowledge-key change affects keys longer than 90 characters, which now end
at a word boundary. If you have acknowledged a long finding, re-acknowledge it
once. `~/.neptune/allow` is a plain text file you can also edit by hand.

---

## First full run of the verdict layer — 2026-09-18

The verdict layer shipped, then ran end to end on a live Mac for the first time.
It worked — and the working output immediately showed three things reading the
code had not. See DEVLOG Bug 9.

### Added
- **`info` severity** — recorded and exported like any other finding, shown under
  `FOR INFORMATION`, deducting nothing and not entering the verdict. For things
  Neptune did (a baseline-format migration, a mode it ran in) as opposed to
  things wrong with the machine. A clean Mac was losing 4 security points to
  Neptune's own format upgrade.
- **CI gate on recorded finding titles** — a finding is printed with its
  surrounding paragraph and recorded as one line; the gate fails if any recorded
  title ends on a word that cannot end a sentence. It derives the helper list per
  script from which helpers call `record()`, and caught a second instance in a
  code path this machine does not take on its first run.
- **Drift guard between `tests/unit.sh` and `scripts/neptune.sh`** — the test
  file transcribes neptune.sh's scoring weights; the assertion fails if the two
  copies stop matching character for character.

### Fixed
- Digest item that read `...Root-owned daemons are NOT` — the recorded title was
  half a sentence whose other half lived in an unprefixed echo. (Bug 9a)
- CGNAT branch recorded the same finding twice, the first time as a fragment.
  (Bug 9a)
- Baseline-format migration notice deducted from the security score. (Bug 9b)
- `sentry.sh` and `network_check.sh` reported different gateway latencies in the
  same report — 3-ping vs 5-ping samples, neither stated. Both now ping 5 times
  and report worst alongside average, so link variance reads as variance instead
  of as a contradiction. (Bug 9c)

---

## Verdict layer — 2026-09

Neptune reported an expert's findings list; a real run on a clean machine
produced ~18 of them, nearly all known vendor quirks. `PHILOSOPHY.md` says a
scanner you learn to ignore is worse than none, so the tool was failing its own
test. It now answers "is this machine OK?" before it answers "here is everything
I found".

### Added
- **Verdict and per-category health scores** — security, network, bloat,
  maintenance, each out of 100. Every deduction traces to a listed finding.
  Repeats of the same kind of issue cost about a third of the first, because
  nine unsigned launch items are usually one vendor habit, not nine problems.
- **`--acknowledge N[,N...]`** — mark known-good vendor quirks. They stay listed
  and counted; they only stop deducting. Stored in `~/.neptune/allow`, keyed so
  the entry survives the PIDs, ports and versions that change every run. All
  numbers resolve against the current listing before anything is written, since
  acknowledging one finding renumbers the rest.
- **`--json`** and **`--json --sanitize`** — structured findings, optionally
  with hostname, username, IP and MAC addresses replaced, so a findings file can
  be shared or pasted into a model without handing over a map of the machine.
  `docs/advisor.md` covers that workflow, including why the model should
  recommend `./uninstall.sh <app>` rather than novel shell you paste blind.
- Structured finding records internally: scans emit
  `severity|category|scan|title` and everything renders from those. Nothing
  re-parses the scans' prose — the step that made one problem count as seven.
  Standalone runs are unaffected; the recorder is a no-op unless the master
  runner sets it.

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
