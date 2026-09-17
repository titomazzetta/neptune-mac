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
