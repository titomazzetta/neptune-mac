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
