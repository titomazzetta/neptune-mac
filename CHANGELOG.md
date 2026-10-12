# Changelog

All notable changes to Neptune. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); entries before 1.0.0
are grouped by audit pass rather than version number.

Bug numbers reference entries in [`docs/DEVLOG.md`](docs/DEVLOG.md), which
explains each in full — symptom, root cause, fix, and what was learned.

---

## [Unreleased]

### Added
- **Updates, app by app** in the HTML report, the JSON (`software`) and the AI
  brief. `check_updates.sh` already knew which apps were behind; the report only
  showed counts ("1 formula and 2 casks"). Now every outdated item is listed with
  its installed and latest version, grouped by how it gets updated: Homebrew
  (`brew upgrade`), Apple (Software Update), the App Store, or the app itself /
  its developer (with `brew install --cask --adopt` as the way to hand it to
  Homebrew). Apps Homebrew's catalog does not know are listed as "check these
  yourself" — never as current — and the run now says so instead of staying
  silent. The terminal shows versions too: `wget 1.21.3 -> 1.21.4`.

### Fixed
- **A `mas` that could not run read as "App Store apps are up to date".** On a
  laptop with a leftover Intel Homebrew and no Rosetta, `/usr/local/bin/mas`
  exited 126 with no output, and no output was taken to mean no updates. It is
  now "could not check", with the reason.
- **"Install the Command Line Tools" on a Mac that had them.** On the first
  laptop run, PATH offered a leftover `/usr/local/bin/python3` that could not
  execute (exit 126), ahead of a working Apple `/usr/bin/python3`. Neptune
  asked PATH, got the broken one, skipped the HTML report and blamed the
  developer tools. `scripts/find_python.sh` now tries each candidate, uses the
  first that actually runs (one interpreter for the whole run), says which one
  failed and why, and names the real reason when none runs.
- The browser-extension check took PATH's python3 without running it first,
  so an interpreter that could not start produced an empty list. It now uses
  the same finder, and says it could not inspect rather than finding nothing.

## [1.2.0] — 2026-10-07

Neptune learns to talk like a person and to show its work: plain words in the
terminal, an HTML report you can read at three depths, a fix queue, an AI
brief for a second opinion — and the repository around it gets the guard
rails a security tool should have.

### Changed — how Neptune reads
- **Plain words everywhere.** `scripts/phrases.tsv` turns each recorded title
  into a headline and a one-line context ("The firewall is off" / "A common
  default. Worth turning on if this Mac joins public Wi-Fi."). Titles, check
  ids and acknowledge keys are untouched, so rewording never un-keeps anything.
  A test reads the table with Python's regex engine too and requires the same
  headline as awk for every fixture finding.
- **The terminal** shows one progress line per scan, then a one-screen summary:
  verdict, counts, four scores, the numbered list in plain words, and the next
  step. `--verbose` streams everything as before. Colour only on a terminal;
  `NO_COLOR` respected; ASCII fallback outside UTF-8.
- **The HTML report** is rebuilt around a first view (verdict, synopsis, scores,
  counts), then *Protection at a glance*, *Do these next* (ranked by score
  gain, with the queue command filled in), *Recommended commands* for this Mac,
  and each finding on an explanation ladder — Simple / Detailed / Technical,
  switched with CSS only — down to what every part of every command does and
  how to undo it. Passed checks, kept items and scoring are collapsed. Still no
  JavaScript and no network requests.
- Categories read as **Security, Network, Tidiness, Updates** (ids unchanged).

### Added
- **`--fix --only 9,2,12`** — a queue: those items, in that order. An unknown
  number stops it before anything runs.
- **k keep / u uninstall / skip** in `--fix` for software you may have chosen,
  and keep for a double NAT you have confirmed is passthrough.
- **AI brief** (`neptune_ai_brief_<date>.md`) on every run with python3: the
  findings plus a prompt, always sanitized. HTML, JSON and the brief are now
  automatic; `--no-html` skips them.
- CI writes the macOS run's verdict and scores to the job summary, and keeps the
  sanitized brief with the uploaded report.
- **Branch protection as code:** `.github/rulesets/main.json` — no direct or
  force pushes to `main`, all three CI jobs required. `tests/test_repo.py` fails
  if a CI job is renamed without updating the rule.
- **OpenSSF Scorecard** workflow (weekly, pinned, read-only default token) and
  README badge.
- Issue templates (bug report; false positive / vendor quirk), a code of
  conduct, and private vulnerability reporting in SECURITY.md.
- README: requirements, verified install from a release, a first-run
  walkthrough, and troubleshooting.
- `tests/test_repo.py`: ruleset ↔ CI job names, SHA pins, read-only default
  tokens, and every relative link in the docs resolves. `tests/lint.sh` now runs
  every python test file.

### Fixed
- From the first real run of this release (1 Oct 2026, macOS 27.0.1):
  - a stray `Terminated: 15` line at the end of every run on macOS (the sudo
    keep-alive is now disowned; the exit trap still stops it);
  - "New since your last snapshot: listener:Code\x20H:127.0.0.1:ephemeral" now
    reads "Code H started listening for connections / Only this Mac can reach
    it", and new apps, login items, helpers and extensions each get their own
    sentence;
  - a new app in /Applications or a new localhost-only listener since the
    snapshot is now a small thing, not something to look at — new login items,
    root helpers, extensions and network-reachable listeners still are;
  - "5 things from your snapshot are gone" had the advice for a brand-new
    snapshot; it now has its own check id (`baseline-gone`) and its own advice;
  - "1 formulae and 2 casks" reads "1 formula and 2 casks";
  - a vendor name on a check that could not run said "Google ships it this
    way"; it now says "Probably Google's, but Neptune couldn't look inside to
    confirm".
- The sanitizer turned `127.0.0.1` into `0.0.0.0` — "only this Mac" into "your
  whole network" — and `/Users/Shared` into a user's home. Loopback, `0.0.0.0`
  and `/Users/Shared` are kept; private ranges keep their prefix.
- A known vendor's name no longer hides a fact about the finding: "Only this
  Mac can reach it" stays beside "Waves ships it this way".

## [1.1.0] — 2026-09-30

Neptune goes from diagnosing to fixing — with the same rule as everything else:
nothing changes without being shown and confirmed.

### Added
- **`./neptune.sh --fix`** (`scripts/fix.sh`): walks the last run's numbered
  findings. For each, the fix, its exact command and what kind of change it is,
  then y / Enter to skip / q to stop. Turns on the firewall, disables the Guest
  account and auto-login, re-enables update checks, runs one confirmed upgrade
  for macOS/Homebrew/App Store, clears Homebrew's cache, hands cache-clearing
  and app removal to the confirmed scripts, offers `--acknowledge` for vendor
  helpers you recognize, or opens the right System Settings pane. Guidance, not
  invented commands, where no honest fix exists. Deletes nothing itself; logs
  every applied fix to `~/.neptune/fix-log.tsv`; offers a re-scan at the end.
  `./fix.sh --plan` previews without changing anything.
- **Self-updating apps compared against Homebrew's catalog** — the cask catalog
  `brew update` already keeps on disk, so no extra network call. "Audacity
  3.7.8 → 3.7.9" instead of "check your apps". Conservative comparison: two
  spellings of one release are not reported as outdated.
- The saved listing carries the check id (sixth column), which the fixer keys on.

## [1.0.0] — 2026-09-25

The "look at everything" pass: every scan re-read for what it does when
something goes wrong, the pipeline made fail-closed, tests pointed at the code
that ships, and CI extended to the platform it ships on. Bugs 13–21 in the
DEVLOG.

### Fixed
- **The silent all-clear, again (Bug 13).** macOS awk aborts on half a UTF-8
  character; the scoring awk ran with `2>/dev/null`, so an abort produced an
  empty findings list, which scored HEALTHY. Every script now runs under
  `LC_ALL=C`, the scorer proves it finished (a stats line written in `END`),
  lost or malformed records fail the report's integrity check, and a missing,
  crashed or silent scan becomes an `unknown` finding.
- **`--acknowledge N` resolved against a fresh scan (Bug 14)**, so N could be a
  different finding from the one you read. It now resolves against the saved
  listing of the run you read, shows what it resolved to, and asks.
- **Two checks that could never fire (Bug 15):** the Chrome extension walk
  stopped one directory short of every manifest; `--load` downloaded from a
  retired host and reported "no bufferbloat" from a test that never loaded.
- **Ad-hoc signatures passed as "signed" (Bug 16).** Now a class of its own.
- **One problem, several findings (Bug 17).** Suite mode, per-binary de-duplication.
- **A bloat score frozen at 100 (Bug 18):** `audit_system.sh` recorded nothing;
  its kext check would have counted `kextstat`'s header as a kext.
- `sentry.sh` re-sorts both sides before `comm`, so a baseline written under the
  old locale cannot produce phantom NEW lines.
- The `towc` DEVLOG entry (12b) corrected: it was an abort, not a warning.
- **The cache cleaner reported "nothing to clear" on bash 3.2 (Bug 19)** — a
  backtick in a comment inside `<( )`. Found by running the suites under bash
  3.2.57 built from Apple's source, before release. Inventory failures now stop
  the script; `tests/bash32_gate.py` checks every substitution for the three
  constructs 3.2 cannot run.
- **Apple binaries classed as a third-party developer on macOS 26 (Bug 20)** —
  the signing leaf is now "macOS Software Signing"; Safari was listed as
  self-updating. Found by the first 1.0 run on the development Mac.
- **Two contradicted all-clears (Bug 21):** "every listener is signed" beside an
  unsigned one that was reported as persistence; a removal-only baseline diff
  that recorded nothing.
- Gateway-latency advice now explains wireless mesh backhaul; the QoS hint names
  more than one router brand.

### Added
- **Check ids and pass records.** Every check records a stable id, and a `pass`
  when clean — the report shows what was covered, not only what failed. Record
  format v2: `severity|category|scan|check|title` (v1 still replays).
- **Posture panel** at the top of the HTML report: ten controls, each passed,
  failed, warn, could-not-check or acknowledged.
- **`clean_caches.sh`** — cache inventory; `--apply` clears only caches you pick
  by number, after you type `yes`. Never Apple's, iCloud's or Homebrew's, never
  through a symlink, never as root. Blast-radius tested.
- **`check_updates.sh`**: minor updates and major upgrades reported separately;
  `--upgrade` installs by label and never the major upgrade; every network call
  has a timeout; brew runs with analytics off; results recorded with check ids.
- **Exit code 77** when administrator privileges are refused; `--out DIR`
  applies to every report the suite writes.
- `netcheck_plus.sh`: marks randomized (private) MACs in the LAN census; a
  brand-neutral router checklist.
- Vendor label for Homebrew services (ad-hoc signed by design).
- `docs/ARCHITECTURE.md`.

### Changed
- The renderer is a python module (`neptune_render.py`) with its remediation
  table keyed by check id; `unknown` results get could-not-check advice rather
  than the advice for a failure; `--sanitize` also scrubs acknowledge keys.
- Uninstaller word boundaries are ASCII-only: `Mail` no longer matches `Mailé`.
- Python floor stated and enforced as 3.6.

### Tests and CI
- `tests/unit.sh` sources the shipping scripts (`NEPTUNE_LIB=1`) instead of
  carrying transcriptions of them; `tests/test_render.py` imports the renderer;
  `tests/macos.sh` proves the platform assumptions on a real Mac.
- CI: a macOS job running every suite under `/bin/bash` 3.2 and BWK awk plus a
  real end-to-end run checked by `tests/e2e_assert.py`; actionlint; every action
  pinned to a commit SHA; read-only default token; Dependabot for the pins.
- Releases: built in CI from the tag, with `SHA256SUMS` and a signed
  build-provenance attestation (`gh attestation verify`).

---

## macOS reality check — 2026-09-21

Everything above was written and tested on Linux. Running it on the target
platform found three things, one confirming and two breaking.

### Confirmed
- **Bug 10 is real on macOS.** `awk version 20200816`: `length("x—y")` is 5 and
  `substr($0,1,2)` returns `78 e2` — a bare lead byte. The DEVLOG entry now
  carries that evidence instead of a Linux result standing in for it.

### Fixed
- **`tests/unit.sh` was a syntax error on bash 3.2** — a python heredoc inside
  `$( )`, which the 3.2 parser breaks on because it scans the body for backticks
  and `$(` even there. Moved to `tests/command_safety.py`. It failed as a parse
  error, so the file exited non-zero having printed no failures at all. (Bug 12a)
- **The Bug 10 fix printed `awk: towc: multibyte conversion failure`** on every
  long finding. Cutting at byte 90 and trimming back produces correct output but
  briefly holds an invalid UTF-8 string, and macOS awk warns when the next
  `sub()` touches it. The key is now built from whole words, so the invalid
  intermediate never exists. (Bug 12b)

### Added
- `bash -n` now covers `tests/*.sh`, not only `scripts/*.sh`.
- A gate for heredocs inside `$( )` — which `bash -n` on the CI runner cannot
  catch, because bash 5 parses them fine.
- An assertion that the acknowledge-key builder writes nothing to stderr, pinned
  against a reproduction of the version that did.
- The bash 3.2 trap gates now scan `tests/` as well, with their patterns
  assembled from fragments so they cannot match their own source.

---

## Testing the dangerous parts — 2026-09-19

The six gaps from the 2026-09-19 review, closed.

### Added
- **`tests/blast_radius.sh`** — a fake macOS layout with deliberately colliding
  decoy paths, asserting that the destructive scripts find everything belonging
  to the target and nothing else. Includes a real sandboxed removal compared
  against the dry-run listing. 25 assertions, in CI.
- **`--dry-run`** on `uninstall.sh` and `remove_mackeeper.sh` — prints the exact
  delete set and stops, before the confirmation and before `sudo` is requested.
- **`NEPTUNE_ROOT`** — a path prefix for the destructive scripts, used by the
  harness. Can only narrow what they reach; refuses `sudo` while set; refuses to
  run if `HOME` is outside it or contains `..`.
- **Exit codes**: 0 healthy, 1 needs attention, 2 a check could not run, 64
  usage error. Acknowledged findings do not affect them.
- **`~/.neptune/seen.tsv`** — first seen, last seen and run count per finding,
  so a report can say "seen in 6 runs, first on 2026-09-01" instead of
  "flagged". Rows survive a finding going away, as the record that it was fixed.
- **`scripts/vendor-quirks.tsv`** — a catalogue naming software that routinely
  trips the signature checks (Waves, Sonarworks, Docker, PACE/iLok and others),
  with a sentence each. A label, never a suppression: matched findings are still
  counted and still deduct. Surfaced in the terminal listing, the HTML report
  and the JSON.
- **Tested-on matrix** in the README, stating which macOS versions have actually
  run which scripts, and which have not.

### Fixed
- **`./uninstall.sh Mail` would have deleted MailMate's data.** Discovery
  matched the app name as a bare substring, so removing one app selected files
  belonging to any app whose name contains it. The term now has to match as a
  whole word. Near misses are shown under their own heading rather than silently
  dropped. (Bug 11)
- **`remove_mackeeper.sh` asked before it looked.** It confirmed, then
  discovered, deactivated, killed and deleted while narrating — so the user
  agreed to a description rather than to a list, which is the one rule both
  destructive scripts are supposed to follow. Inventory now happens first and
  nothing mutates until the full list is on screen.
- The sandbox containment guard accepted `$ROOT/../elsewhere`, because a prefix
  check is not containment. Found by the harness, minutes after being written.

### Documented
- `socketfilterfw`'s deprecation path, and why the firewall check degrades to
  *unknown* rather than to *fine*.

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
