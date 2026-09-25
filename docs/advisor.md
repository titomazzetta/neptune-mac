# Using an LLM to interpret a Neptune report

Neptune finds things; deciding what to do about them benefits from a second read.
This is the intended loop — and it's deliberately decoupled: Neptune emits a
report, an advisor reads it, and **you** run any actions. The advisor never gets
to run destructive commands.

## The loop
1. Run `./neptune.sh` (or any single scan).
2. Open the report from your Desktop (or copy the terminal output).
3. Paste it to an LLM with the prompt below.
4. Read the recommendations, then run only what you approve, yourself.

## Prompt template

> You are a careful macOS security and maintenance advisor reviewing a report
> from "Neptune," a read-only auditing tool. Below is the report.
>
> For each flagged item, tell me:
> - what it is,
> - whether it's a genuine concern or a benign vendor quirk (audio tools, Docker,
>   VPNs, and licensing daemons commonly fail code-signing checks harmlessly),
> - and the specific action, if any — with the exact command, and a note on
>   whether it's reversible.
>
> Be honest about uncertainty. Do not tell me to delete anything you can't
> clearly identify. Group by priority: security concerns first, then performance,
> then cleanup. Flags are leads, not verdicts.
>
> REPORT:
> <paste here>

## Local-model note
A future `neptune advise` may pipe the `--json` report to a local model (e.g. an
Ollama endpoint on localhost) so nothing leaves the machine. It will never require
one or embed a cloud key. Until then, the paste loop above is the way.

---

## Using `--json` instead of pasting the text report

`./neptune.sh --json --sanitize` writes a structured findings file:

```json
{
  "neptune": { "schema": 3, "version": "1.0.0", "sanitized": true },
  "verdict": "needs_attention",
  "integrity": { "ok": true, "problem": null },
  "scores": { "security": 52, "network": 80, "bloat": 100, "maintenance": 95 },
  "counts": { "attention": 11, "notice": 4, "unknown": 0, "info": 2, "pass": 15, "acknowledged": 0 },
  "posture": [
    { "check": "filevault", "label": "Disk encryption (FileVault)", "state": "pass", "detail": "..." }
  ],
  "findings": [
    { "n": 5, "severity": "attention", "category": "security", "scan": "redflag",
      "check": "persistence-launchd",
      "title": "UNSIGNED persistence: com.docker.socket runs ...",
      "vendor": { "name": "Docker", "note": "..." },
      "advice": { "means": "...", "do": "...",
                  "commands": [ { "command": "codesign -dvv ...", "kind": "look", "effect": "..." } ] } }
  ],
  "checks_passed": [ { "category": "security", "check": "sip", "title": "..." } ]
}
```

Schema 3 adds the `check` id on every record, the `posture` panel,
`checks_passed` (what was verified, not just what failed) and `integrity`. A
report whose `integrity.ok` is false lost results in the pipeline; say so to the
model rather than letting it treat the list as complete. `--replay` accepts this
file back and re-derives everything from the findings, ignoring the stored
numbers.

That is a better input to a model than the prose report: it is smaller, it has
no formatting to misread, and `--sanitize` has already removed your hostname,
username, IP addresses and MAC addresses.

### Ask for explanations and Neptune commands — not novel shell

When you ask a model what to do about a finding, ask it to recommend **actions
that route through Neptune's own confirmed paths**:

> For each finding, tell me (a) what it most likely is, (b) whether it is a known
> vendor quirk I should acknowledge, and (c) the action. For removals, give me
> the `./uninstall.sh "App Name"` or `./clean_caches.sh --apply` command rather
> than `rm` commands — I want
> the discovery-and-confirmation step. Do not give me shell I would paste blind.

This is deliberate, and it is the same boundary `docs/PHILOSOPHY.md` draws. A
model reading a report about your system and emitting novel `sudo` one-liners
skips every safety property this tool has: if it misreads a path or misjudges a
vendor quirk, the command you paste deletes something real, unrecoverably.
`./uninstall.sh` shows you every file it found and waits for a typed `y`.

Neptune emits findings. A model recommends. You decide, and the destructive
paths still make you look at the list first. Observe → decide → act, with the
human at the act boundary.

### Wiring it to an API yourself

If you want one-command convenience, write a small wrapper that reads the JSON
and calls whatever API you use. Keep it **outside this repository**, or
gitignored. Neptune ships no API keys and makes no cloud calls — that claim is
verifiable with the `grep` commands in `SECURITY.md`, and it stays true only if
the key lives in your environment rather than in the project.
