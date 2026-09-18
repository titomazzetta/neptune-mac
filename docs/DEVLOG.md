# Devlog — how Neptune was built, and what broke along the way

This is an honest engineering record: the bugs, the wrong turns, and the fixes.
It's here on purpose. A security tool is only as trustworthy as the rigor behind
it, and the most useful thing I can show isn't that the tool works — it's *how I
found the places where it didn't, and what I did about them.* Every entry below is
a real issue caught during development on live machines, not a hypothetical.

The through-line: in a scanner, **a false "all clear" is worse than a false
alarm.** Most of these fixes exist because I distrusted a clean-looking result and
checked it.

---

## Bug 1 — The false "all clear" (the one that mattered most)

**Symptom:** `sentry.sh` printed `[FLAG]` lines during a run, then ended with an
"All clear — nothing flagged" summary. Both. In the same run.

**Why it mattered:** this is the cardinal sin of detection tooling. A tool that
reports clean while it's actively finding things trains the user to trust a lie.
If I'd shipped this, every "all clear" from Neptune would have been worthless.

**Root cause:** the flag-collecting loop ran inside a pipeline (`... | while
read`), which bash executes in a *subshell*. The `FLAGS` array populated inside the
subshell evaporated when it exited, so the summary counted zero. A classic bash
scoping trap.

**Fix:** restructured the loop to use process substitution (`while read ... < <(...)`)
so it runs in the current shell and the array survives. Verified the summary count
now matches the flags printed.

**Lesson applied everywhere:** audited every script for the same
pipeline-into-while pattern and the same subshell-state-loss class of bug.

---

## Bug 2 — Every process reported identical network listeners

**Symptom:** the process→network map in `sentry.sh` showed *every* process
listening on the *same* huge list of ports — obviously wrong.

**Root cause:** `lsof -i -p <pid>` ORs its selectors by default, so it returned
every network file on the system for each PID instead of just that process's
sockets. The output looked plausible enough to almost miss.

**Fix:** added `-a` to AND the selectors (`lsof -a -i -p <pid>`), so each process
shows only its own connections. This also killed a batch of false flags (e.g. a
sync app appearing to "listen on everything").

**Lesson:** a tool that produces *plausible* wrong output is more dangerous than
one that crashes. Cross-checked the corrected output against known-good processes.

---

## Bug 3 — bash 3.2 parser crash: `case` inside command substitution

**Symptom:** `redflag_scan.sh` died with a syntax error at the
suspicious-process-location check — but only on macOS, not on newer bash.

**Root cause:** macOS ships **bash 3.2 (2007)** for licensing reasons. Bash 3.2's
parser cannot handle a `case` statement inside `$(...)` command substitution. The
code was valid modern bash and invalid on the exact platform the tool targets.

**Fix:** rewrote the check in `awk` (no shell `case` in the subshell). Added a CI
gate that greps for this pattern so it can never return.

**Lesson:** "works on my machine" is a threat model failure when your machine
isn't the deployment target. Neptune now targets bash 3.2 explicitly, and CI
enforces it.

---

## Bug 4 — bash 3.2 empty-array crash under `set -u` (found on someone else's Mac)

**Symptom:** `uninstall.sh` crashed at the deletion stage —
`PLISTS[@]: unbound variable` — on a machine where the app being removed had *no*
launch agents. It had worked on every prior test because those apps all happened
to have persistence items.

**Why it mattered:** it failed on a *friend's* machine during real use, on the
empty-set edge case — exactly the input that testing on my own already-populated
machines never exercised. And it failed at the deletion stage.

**Root cause:** under `set -u` (unset-variable protection, itself a safety choice),
bash 3.2 treats expanding an empty array `"${ARR[@]}"` as referencing an unbound
variable. Newer bash doesn't. So the safety flag plus the old bash plus the empty
edge case combined into a crash.

**Fix:** guarded every array expansion with `${ARR[@]:+"${ARR[@]}"}` (nine sites).
Added a CI check flagging unguarded expansions for review.

**Silver lining:** it crashed *before* deleting anything — because the destructive
work is staged after the confirmation and the loops are ordered defensively. The
fail-safe design meant a bug at the delete stage lost no data.

**Lesson:** test the empty set, the single element, and the "none found" path — not
just the happy path with rich data. Edge cases are where security tools fail.

---

## Bug 5 — Double-NAT detector's false negative

**Symptom:** the NAT check reported "single NAT, clean" on a network that showed
two private-address hops in traceroute.

**Root cause:** the logic counted private hops, but the home router often *doesn't
answer* traceroute, so the count came up short and the tool declared all clear —
another false negative. Separately, ISP-side CGNAT (100.64/10) looks like
double-NAT but isn't the user's problem to fix.

**Fix:** rewrote the logic to treat the local gateway as NAT layer one implicitly
(answered or not), flag any *additional* private router as possible double-NAT, and
special-case CGNAT as ISP-side. Also added the honest caveat that an
IP-passthrough gateway can echo its private IP as a hop — so the tool tells the
user how to *confirm* (check the router's WAN IP) rather than asserting a verdict.

**Lesson:** absence of evidence isn't evidence of absence. A silent participant
(the non-responding router) must be modeled, not assumed away. And when the tool
can't be certain, it should say how to check — not guess.

---

## Bug 6 — CI was red, and the lint findings weren't all cosmetic

**Symptom:** GitHub Actions failing on `main`. `shellcheck --severity=warning`
returned eight findings across five scripts: five SC2034 (unused variable) and
three SC2010 (`ls | grep`).

**Why it mattered — the honest version:** most of these were not live bugs. Four
unused colour variables hurt nobody. But a red CI badge is worse than the sum of
its findings: it trains you to stop reading the build. The bash-3.2 gate and the
destructive-confirmation guard — the two checks that exist *specifically* because
Bugs 3, 4 and 5 happened — live in the same workflow. Once the run is red by
default, a real regression in those gates arrives as "still red," and nobody
looks. A muted alarm is the same failure mode as a false "all clear"; it just
takes longer to bite.

**Root cause, per finding:**

- *SC2034, four colour variables* (`RED` in `check_updates.sh` and `neptune.sh`,
  `CYN` in `redflag_scan.sh`): copy-paste drift. Every script starts from the same
  colour-helper preamble, and each one uses a different subset.
- *SC2034, `SUDO_NEEDED` in `audit_system.sh`*: a `check_plists()` parameter that
  was never read in the function body. All three call sites dutifully passed the
  literal `no`. An interface that was designed, never implemented, and never
  noticed because the argument was always the same.
- *SC2034, `SYSEXT` in `redflag_scan.sh`*: dead code with a sting in it. The
  variable was assigned from a `systemextensionsctl` pipeline and then never read;
  the check below re-runs the command independently. Harmless — but it meant a
  chunk of filtering logic sat in the traffic-interception section looking load-
  bearing while doing nothing. Dead code in a security scanner reads as coverage
  you don't have.
- *SC2010, three `ls | grep '\.app$'` sites* (`sentry.sh` snapshot, `uninstall.sh`
  usage listing and fuzzy fallback): parsing `ls` output to enumerate
  `/Applications`. The classic objection is filenames with spaces or newlines.

**Fix:** removed the dead variables (each confirmed unused by grep first — no
script sources another, so nothing consumed them externally), dropped the
vestigial parameter and its three call-site arguments, and replaced the `ls`
pipelines with plain globs guarded by `[ -e "$A" ] || continue` for the
no-match case. bash 3.2 throughout: no `globstar`, no arrays, no `${var,,}`.
Verified byte-identical output against the old pipelines for names containing
spaces and quotes, for a no-match search term, and for an empty directory.

**The one finding that wasn't cosmetic.** The fuzzy app-name fallback in
`uninstall.sh` was:

```bash
MATCH=$(ls /Applications 2>/dev/null | grep -i "$APPNAME" | grep '\.app$' | head -1)
```

`grep` treats `$APPNAME` as a **regular expression**. `$APPNAME` is user input, and
the value it resolves to flows onward into `find -iname`, `pkill -f`, and the
deletion list. So `./uninstall.sh "."` matched the first app alphabetically rather
than failing to find anything — and a term containing `*`, `[`, or `+` either
errored or matched something the user didn't mean. The confirmation gate still
stood between that and any deletion, which is exactly why this never became an
incident. But "the safety net caught it" is not the same as "the input was
handled correctly," and this is the destructive script. The replacement matches
the term as a **literal substring** via a `case` pattern with the expansion
quoted, so metacharacters are inert.

**Lesson:** triage lint findings, don't batch-dismiss them. The instinct with a
wall of style warnings is to silence the noisy ones and move on; seven of these
eight genuinely were noise. The eighth was untrusted input reaching a regex on the
path to `rm -rf`, wearing the same yellow SC2010 badge as a cosmetic `ls | grep`.
The severity of a lint rule is a property of the rule. The severity of a *finding*
is a property of where it sits in your blast radius — which the linter can't know
and you can.

**Second lesson, aimed at future me:** a green CI is a precondition for CI being
useful at all, not a nice-to-have. Fix it the day it goes red.

---

## Bug 7 — The signature check that never read a signature

**Symptom:** every signed item in every scan reported `(unknown)`. Splice,
Docker, Zoom, Arturia, Pioneer, PACE — all of them, on every run, on every
machine. `signed (unknown authority)` in `audit_system.sh`; `— unknown` in the
listener table; `signed:unknown` for privileged helpers.

I had read past it for a long time as a cosmetic wart.

**Root cause:** `codesign -dv` does not print the certificate chain. It prints
`Executable=`, `Identifier=`, `Format=`, `CodeDirectory`, `Signature size`, and
`Timestamp` — and stops. `Authority=` lines only appear at verbosity 2. So every

```bash
AUTH=$(codesign -dv "$BIN" 2>&1 | grep -m1 '^Authority=' | cut -d= -f2)
```

matched nothing, always, and `${AUTH:-unknown}` did exactly what it was told.
Six call sites across four scripts.

**Why it was worse than cosmetic.** `sentry.sh` classifies Apple binaries like
this:

```bash
case "$AUTH" in
  "Software Signing"|"Apple Mac OS Application Signing") echo "apple" ;;
  *) echo "signed" ;;
esac
```

`AUTH` was always empty, so the first branch was **structurally unreachable**.
Nothing was ever classified as Apple — `/bin/launchctl` came back "(unknown)"
like everything else. The Apple-vs-third-party distinction, which is the
difference between "the OS starts this" and "someone else starts this", had
never once worked.

Third consequence, and the one that finally gave it away: `check_updates.sh`
skips Apple's own apps with `grep -q "Authority=Apple Root CA"`. That never
matched either, so **Safari.app** sat in the list of "apps NOT managed by brew or
the App Store — these rely on their own updaters." Safari is Apple's. Seeing that
in a real report is what sent me back to `codesign`.

**Fix:** `-dvv` at all six sites. Verified against a real bundle:

```
$ codesign -dv  /Applications/Splice.app 2>&1 | grep '^Authority='
$ codesign -dvv /Applications/Splice.app 2>&1 | grep '^Authority='
Authority=Developer ID Application: Distributed Creation Inc (9962T6AKMH)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
```

**Lesson:** `PHILOSOPHY.md` claims this project does "persistence analysis —
enumerating every macOS persistence vector and verifying each against code
signatures." The enumeration was real. The verification was half-real: it could
tell signed from unsigned, because `codesign -v` genuinely answers that, but the
part that says *who* silently returned nothing from the day it was written.

The tell was on screen the whole time. A field reading `(unknown)` for every row
is not a formatting quirk — a value that is constant across all inputs is a value
that isn't being computed. I had trained myself to skim past it because it looked
like noise, which is the same reflex that makes a noisy scanner dangerous. See
Bug 8.

---

## Bug 8 — The bugs were all in the reporting layer, not the collection layer

**Symptom:** a full `./neptune.sh` run on a clean machine produced an action
digest claiming 25 findings across ~45 lines, for about 18 real ones — with
sentence fragments like `[XX] passthrough on the ISP gateway` listed as action
items, every finding printed twice, and the numbering running 1., 10., 2., 3.

**Why group these:** Neptune's *collection* was fine. It correctly found four
unsigned launch items, two unsigned root helpers, a second private router, and a
real latency problem. Every defect in this pass was downstream of that — in what
gets counted, what gets surfaced, and what gets said when a check can't run. Four
faults, one theme:

**1. A finding prefix is load-bearing, so anything wearing one becomes a
finding.** The digest matched `[0-9]+\. ` alongside the `[FLAG]`/`[!!]`/`[XX]`
prefixes — but `1. `, `2. ` is how each scan numbers its *own* end-of-scan
summary, which restates the same findings. So everything appeared twice, and
`sort -u` then interleaved two scans' independent numbering into nonsense.
Meanwhile `network_check.sh` explained double NAT with **seven consecutive
`bad()` calls**, so one problem became seven findings and its prose became action
items. Fixed by collecting prefixed lines only, and by letting continuation prose
be continuation prose. One finding, one prefixed line.

**2. A scanner that is 70% noise is a scanner you stop reading.** Seven of
`sentry.sh`'s ten flags were `rapportd` and Splice holding different ports than
at the last baseline. macOS reassigns ports in 49152–65535 every boot, so the
port number is churn and the process plus interface scope is the signal. The
baseline now records those as `:ephemeral`. Verified it still catches a new
listening process, and still catches one moving from `[::1]` to `*` — the two
things the check exists for. (Roadmap #5, and it turns out to be the difference
between a flag list you read and one you skim.)

**3. A check that could not run reported nothing at all.** The firewall check
read `com.apple.alf globalstate`, which returns nothing on macOS 26.6.2, and fell
through to an unprefixed `note` that the digest does not collect — while the RED
FLAG SUMMARY went on to report an otherwise clean security baseline. A reader
sees SIP enabled, Gatekeeper enabled, eight unrelated flags, and reasonably
concludes the baseline was checked. A third of it wasn't. Now queries
`socketfilterfw` first and, if every source is unreadable, says so as `[!!]`.

**4. Two scans disagreed about the same file, in the same report.**
`redflag_scan.sh` resolved plists naming a bare command (`launchctl`, `open`) via
`command -v` and reported them fine. `audit_system.sh` lacked that step and
called Apple's own `limit.maxfiles` and `limit.maxproc` orphaned plists. Both
verdicts printed in the same combined report, pages apart.

**Lesson, and it is the roadmap's:** the digest was built by grepping the scans'
prettified human output. That interposes a parser — one whose input format was
never specified — between "what was found" and "what was reported", and every
fault above lives in that gap. Fixing the greps fixed these four instances. It
did not close the gap.

This is the concrete argument for the structured-findings work in `ROADMAP.md`,
and it changes its shape: `--json` should not be a second output path bolted
alongside the text report, because that leaves the parser in place and adds a
second consumer that can disagree with the first. Findings should be recorded as
structured records **at the point of discovery**, with both the human report and
the JSON rendered from that one list. Then the digest is a filter over an array,
and a summary that contradicts its own findings stops being expressible.

The advisor loop needs that guarantee more than it needs JSON. A model reasoning
over a view that can silently diverge from what the human sees is worse than no
advisor at all.

**Second lesson:** every bug in this pass was findable from fixture strings — a
captured `codesign` block, a captured `lsof` block, a few lines of scan output.
None needed a Mac. `ROADMAP.md` defers test fixtures as "non-trivial" because it
frames them as mocking `launchctl`, `lsof` and `system_profiler`. The pure
text-processing layer needs no mocks, and that is where the bugs actually were.

---

## Correction — a bug that did not exist, and how it nearly got shipped

Not a bug in Neptune. A wrong diagnosis *about* Neptune that got as far as five
commits, a CI gate, a rule in `CLAUDE.md` and a full devlog entry before it was
caught. It is recorded here because this file claims every entry is a real issue,
and an honest record that quietly drops its own worst moment is not honest.

**The claim.** During the audit above, working with an AI assistant, a conclusion
was reached that `neptune.sh`'s action digest and `redflag_scan.sh`'s
system-proxy check were silently dead on macOS. The reasoning: both matched on
`\s`, `\s` is a GNU extension, macOS ships BSD grep, and BSD treats `\s` as the
literal letter *s*. Every finding Neptune prints is indented two spaces, so the
digest would match nothing and the master runner would report "Nothing flagged
anywhere. Fully clean run." on every machine, forever — Bug 1 reproduced one
layer up, in the flagship script.

It was a tidy story. It explained a real class of failure, it fit the project's
stated worst-case, and it was completely wrong.

**The evidence that "confirmed" it.** The claim was tested on a Linux box by
*substituting* `s*` for `\s*` and showing the substituted pattern matched
nothing. That demonstrates only: *if `\s` were treated literally, this would
break.* It never tested whether `\s` is treated literally. The premise was
assumed on the way in and the conclusion came back out wearing a test result's
clothes.

**What the target machine actually says:**

```
$ grep --version
grep (BSD grep, GNU compatible) 2.6.0-FreeBSD

$ printf '  [FLAG] test\n' | grep -E '^\s*\[FLAG\]'
  [FLAG] test
```

Apple's grep is GNU-compatible and supports `\s`. Running `./neptune.sh` produced
a fully populated digest. The digest had never been broken. Neither had the proxy
check, nor the `\b` in the MacKeeper team-ID extraction.

**What it cost.** Five commits, a CI gate enforcing a rule that wasn't needed, a
`CLAUDE.md` constraint describing a platform that doesn't behave that way, and a
ninety-line postmortem of an event that never happened. All retracted before
anything was applied to the repository — but only because the diagnosis was
accompanied by a five-second verification command, and that command was actually
run instead of skipped as a formality.

**Lessons, in order of importance:**

1. **Verifying a simulation of your premise is not verifying your premise.** This
   is the whole failure in one line. The test was constructed by assuming the
   thing under test. It could only ever return "confirmed."
2. **A diagnosis that explains your worst fear deserves more scrutiny, not less.**
   "The digest has been silently reporting all-clear this whole time" is exactly
   the narrative this project is primed to believe, because Bug 1 was real. That
   made it land as obviously true rather than as a claim needing evidence.
3. **Run the check on the target, not a model of the target.** Bug 3's lesson was
   "works on my machine is a threat model failure when your machine isn't the
   deployment target." This is the same lesson arriving from the opposite
   direction, and it was in this very file, unread, the whole time.
4. **Confident, fluent, well-structured reasoning is not evidence.** The wrong
   diagnosis arrived with a mechanism, a worked example, a proposed fix, a CI
   gate and a commit message. None of that is verification. It is worth being
   deliberately more suspicious of a conclusion that arrives fully formed —
   whether it came from a tool, a colleague, or yourself at 2am.

**What was kept from the episode.** Nothing, in code. The `[[:space:]]` rewrites
were discarded along with everything else, because keeping a change justified by
a false premise means carrying a lie in the commit history. The real bugs found
in the same pass — Bugs 7 and 8 — survived, because those were diagnosed from
actual output captured on the actual machine.

That is the difference the whole episode is about.

---

## Bug 9 — Three defects the verdict layer's first real run exposed

The verdict layer shipped and was then run, for the first time, end to end on
the machine it was written for. It worked: 17 findings, continuous numbering,
real signers named where every line had previously read `(unknown)`, sentry down
from 10 flags to 2. The interesting part is what a working run makes visible
that no amount of reading the code had.

### 9a — A finding that stopped mid-sentence

**Symptom.** Item 15 of the digest:

```
   15. [network] Unprivileged view: your own processes only. Root-owned daemons are NOT
```

**Cause.** In `network_check.sh` the finding is one `warn` call whose sentence
continues into the next line of output — a plain, unprefixed `echo`. That is the
correct pattern for *printing* (Bug 8 established that a finding prefix marks a
finding and elaboration must not carry one). But `record()` only ever sees the
`warn` argument. In the scan's own output the paragraph reads fine; in the
digest, where a finding is one line stripped of its context, it stops mid-clause.

The CGNAT branch had the same shape and worse: two consecutive `warn` calls for
one problem, recording it twice and recording the first half as its own fragment.
That is Bug 8 again, surviving in a branch this machine does not take — which is
why it was never seen.

**Fix.** Each records one complete clause and continues in an unprefixed echo.

**The durable part** is the test. It derives, per script, which helpers actually
call `record()`, then fails if any of their titles ends on a word that cannot end
an English sentence. The helper list is derived rather than hardcoded for a
specific reason: `netcheck_plus.sh` has a `note()` that only echoes, so a
hardcoded list would fail on that one and would miss whatever recording helper
gets added next. The gate found the CGNAT pair on its first run — a bug in a code
path the author's own machine cannot reach.

It is a smell test, not a parser, and that is the right size for the problem. The
defect was always obvious to a human reading one line out of context. CI is just
the thing that does not get bored.

### 9b — The tool billed the user for its own upgrade

**Symptom.** Item 12, counted as a security notice, costing 4 points:

```
   12. [security] Baseline format changed (v1 -> v2); baseline REPLACED, nothing diffed this run
```

**Cause.** `BASELINE_FORMAT` bumped to 2 when sentry started collapsing ephemeral
listener ports, so the old baseline was not comparable and was replaced rather
than diffed — deliberate, and loudly announced on purpose, because a silent
baseline reset is how a tripwire quietly stops being a tripwire. But it was
emitted through `warn()`, and `warn()` records a `notice`, and a notice deducts.
A machine with nothing wrong with it lost security points because Neptune had
upgraded its own file format.

**Fix.** A fourth severity, `info`: recorded like any other finding so `--json`
and the printed report cannot disagree, rendered in its own block, deducting
nothing and not entering the verdict.

```
  FOR INFORMATION — about this run, not about your machine (no score impact)
    · [security] Baseline format changed (v1 -> v2); baseline REPLACED, nothing diffed this run
```

Unnumbered, because the numbers are the argument to `--acknowledge` and there is
nothing here to acknowledge.

**Lesson.** A score is a claim about the machine. The moment it also reflects
things the tool did to itself, it stops being that claim, and the user is right
to stop reading it. The category existed implicitly the whole time — "things the
user should see that are not defects" — and went into the nearest bucket because
no bucket fit.

### 9c — The report contradicted itself about the user's own router

**Symptom.** In one combined report, two minutes apart:

```
sentry.sh          Gateway 192.168.50.1: 38.555 ms
network_check.sh   Gateway (192.168.50.1):  9.372 ms avg
```

**Cause.** Not a parsing bug and not a wrong number — both were accurate. sentry
pinged 3 times, `network_check` pinged 5, they sampled different moments, and
neither said so. On Wi-Fi one power-save wake-up moves a 3-ping average by 30 ms.
It also means sentry's "LAN latency high" warning was firing off a sample too
small to support the claim.

**Fix.** A common 5-ping sample in both, and avg reported alongside worst:

```
  Gateway (192.168.1.1):  9.372 ms avg, 38.555 ms worst (5 pings)
```

Reporting max is the better output on its own merits — an average hides the one
200 ms outlier that is the actual symptom of a bad mesh hop. Here it also turns
the contradiction into the finding.

**Lesson.** Two scans measuring the same thing must agree or explain themselves;
a reader cannot distinguish "the link is variable" from "this tool is broken"
when only one number is shown and the sample behind it is not stated. This is the
same failure as Bug 7's cross-scan disagreement about `limit.maxfiles` — a
different pair of scans, the same lost trust.

**What the three have in common.** None was findable by reading the code, and all
three were obvious within thirty seconds of reading real output. The verdict
layer's value turned out to be partly diagnostic: compressing five scans into one
screen put a fragment, a self-inflicted deduction and a contradiction next to
each other where they could not be missed.

---

## Cross-cutting practices that came out of these

- **CI as a regression net for exactly these bugs.** The pipeline runs shellcheck,
  `bash -n` syntax checks, a **bash-3.2-compatibility gate** (fails on
  case-in-subshell, associative arrays, mapfile; flags unguarded empty-array
  expansion), and a guard verifying the destructive scripts still contain their
  confirmation prompts. The bugs I hit by hand can't silently come back.
- **Calibration over alarmism.** Legitimate vendor software (Waves, Sonarworks,
  Docker, PACE/iLok) fails code-signing checks routinely. Rather than flag-spam,
  Neptune labels these as expected quirks and teaches the user to spot what's
  *beyond* the known-good set. A scanner you learn to ignore is worse than none.
- **Fail-safe defaults.** Read-only unless explicitly told otherwise; sudo cached
  once, never run-as-root wholesale; confirmation before every deletion; verify
  after every removal.
- **Real-world validation.** Every script was run on multiple live machines
  (including a non-technical user's), which is where Bug 4 surfaced. Lab-only
  testing would have shipped it.

## Where it's going

See `ROADMAP.md`. The next step — structured `--json` output feeding an optional,
decoupled AI advisor — is designed so a model can *recommend* fixes but never
*execute* destructive commands unsupervised. Observe → decide → act, with the human
kept at the act boundary. That's the same fail-safe instinct as everything above,
applied to the AI layer.
