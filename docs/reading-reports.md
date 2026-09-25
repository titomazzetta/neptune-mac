# Reading Neptune reports

## Flags are leads, not verdicts
The single most important habit: a `[FLAG]` means "worth a look," not "compromised."

## The usual benign vendor quirks
These commonly fail code-signing checks for harmless reasons (vendors modifying
their own bundles post-install, self-built binaries, etc.):
- Audio/production tools (Sonarworks/SoundID, Waves, Elektron Overbridge)
- Docker's socket helper
- PACE/iLok licensing daemons
Seeing these is normal. Establish your machine's set of expected quirks once; then
anything *beyond* that set is the real signal.

## What actually deserves attention
- Persistence pointing at a binary in `/tmp`, `~/Downloads`, `/Users/Shared`
- Processes running from those same locations
- Traffic interception you didn't set up: system proxies, network/endpoint
  extensions, configuration profiles, non-stock `/etc/hosts`
- Unsigned launch items you can't attribute to software you installed
- Login/startup hooks and legacy StartupItems (rare on modern macOS)

## sentry baselines
First run creates a baseline; later runs show what *changed*. If a change is
something you did (installed/removed software), re-baseline with
`./sentry.sh --rebaseline`. Then any future change is meaningful again.

## Ephemeral-port noise
Listener ports in the dynamic range (49152–65535) are reassigned every boot, so
processes like `rapportd` (Handoff/Continuity) and Splice used to re-flag on every
run — at one point 7 of 10 flags on a clean machine. The baseline now records
those as `:ephemeral`, so only a genuinely new listening process, or one that
moves from loopback to all interfaces, is flagged.

The first run after this change **replaces your baseline** and says so. That run
diffs nothing; the one after it resumes normally.

## "Could not be checked"
Distinct from a finding, and listed in its own group. It means Neptune could not determine something — a
command returned nothing, a path was unreadable, TCC blocked access. Treat the
summary as incomplete for that area rather than clean. An example you may see:
the application-firewall state, if neither `socketfilterfw` nor the legacy
preference is readable.

This matters more than it looks. "No red flags found" should mean *every check
ran and found nothing*, never *the checks that ran found nothing* — so where
Neptune can't see, it is supposed to say so rather than pass quietly.

## Signing: the five answers
Every binary behind a launch item, helper, listener or networked process gets
one of five answers:

| Class | Means |
|---|---|
| Apple | signed by Apple |
| `signed:<developer>` | a verified developer identity, e.g. `Developer ID Application: Acme Inc (AB12CD34EF)` |
| **AD-HOC SIGNED** | a valid signature that names **nobody**. Anyone can make one with one command, and on Apple silicon every binary must have at least this. It proves the file has not changed since signing; it says nothing about who wrote it |
| **UNSIGNED** | no valid signature at all |
| missing | the file the item points at does not exist (an orphan) |

Ad-hoc is where your judgement matters most. Homebrew's own binaries are ad
hoc, so `brew services` items show up this way and are labelled `known Homebrew
pattern`. An ad-hoc binary *you cannot attribute* — especially one in
`~/Library`, `/Users/Shared` or `/tmp` — is exactly what commodity Mac malware
looks like, which is why Neptune stopped treating it as "signed" (DEVLOG Bug 16).

If *every* item comes back unclassified rather than the occasional one, that is
a bug, not a finding — please report it. It was one, once (DEVLOG Bug 7).

## The posture panel (HTML report)
The top of `--html` lists ten controls — FileVault, SIP, Gatekeeper, firewall,
automatic security updates, auto-login, guest account, remote access,
interception, profiles — each as **passed**, **failed**, **warn**,
**could not check**, or **acknowledged**. "Not checked" should never appear on a
real run; if it does, a scan did not reach that check, and CI treats it as a
failure of the tool.

## Two scans, one machine
Run standalone, `sentry.sh` and `redflag_scan.sh` overlap deliberately —
different angles on the same persistence and listener data. In the full suite
each shared check is done once, by the scan that owns it, so one problem is one
finding and one deduction (DEVLOG Bug 17). If the two ever disagree about the
same file, that is a bug worth reporting. It was one, once (DEVLOG Bug 8).

## What the connection census can't see
`network_check.sh` lists connections without elevating, so it shows only your own
processes — root-owned daemons are absent, and it says so in its output.
`sentry.sh` and `redflag_scan.sh` do elevate and cover those.
