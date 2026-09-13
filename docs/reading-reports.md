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

## Apple ephemeral-port noise
`rapportd` (Handoff/Continuity) grabs new ports each boot and may re-flag. Benign;
a roadmap item will suppress it.
