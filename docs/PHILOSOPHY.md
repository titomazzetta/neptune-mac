# Neptune — Philosophy & Vision

## The name

**Neptune** — Roman god of the sea, keeper of the deep, trident in hand. The tool
watches over the depths of your system (the launch daemons, the persistence
points, the network's dark corners that most people never look at) and carries a
trident for the things that don't belong. The "**tune**" is the other half: this
is a system and network *tuner* as much as a defender — optimize, maintain, tune,
protect. No-BS, no fear-marketing, no resident bloat.

## Why it exists

Neptune was born by removing its opposite.

Commercial macOS "cleaners" and "antivirus" products — the MacKeeper / CleanMyMac /
"Antivirus One" category — sell themselves through fear ("YOUR MAC IS INFECTED"),
then install resident daemons, kernel and endpoint-security extensions, and
traffic-filtering layers that quietly tax the very machine they claim to speed up.
They are hard to fully remove, they phone home, and several have FTC settlements to
their name for deceptive practices.

While tearing one of these out of a real machine — six background daemons, an
Endpoint Security system extension intercepting every file operation, three Safari
traffic filters, a VPN hook into the network stack — a simple realization: the
*legitimate* jobs these products pretend to do are real and worth doing. Spotting
unwanted persistence. Finding stale software. Checking for outdated packages.
Sanity-checking the network. Verifying code signatures. Those are good hygiene.

The problem was never the goal — it was the *implementation*: opaque, resident,
adversarial. So Neptune does the same legitimate jobs the honest way.

## Design principles

These aren't features; they're the ethos. Every decision serves them.

1. **On-demand, never resident.** No launch agents, no cron, no menu-bar process.
   The tool that promises to reduce background load must not *be* background load.
2. **Read-only by default.** Of the nine scripts, only two delete anything, and
   both show you everything first and require typed confirmation. (`sentry.sh`
   writes its own baseline files; `check_updates.sh` installs only with an
   explicit `--upgrade`. The other five touch nothing at all.) A cleaner that
   deletes silently is how you lose data; Neptune never does.
3. **Human-in-the-loop for destructive actions.** The safety of the tool is that a
   person is at the keyboard when files are removed as root. This is deliberately
   *not* automated away — not even for an AI agent (see "Vision" below).
4. **Transparent.** It's readable bash. No compiled blobs, no obfuscation, no API
   keys, no telemetry. You can audit every line — which is the whole point of a
   security tool you're meant to trust.
5. **Flags are leads, not verdicts.** Legitimate vendor software (audio tools,
   Docker, VPNs, licensing daemons) routinely fails code-signing checks for benign
   reasons. A scanner that cries wolf trains you to ignore it. Neptune calibrates:
   it distinguishes the vendor quirk from the real threat, and says so.

## What it deliberately will NOT do

Knowing what to leave out is half the design:

- **No "optimization" theater** — no RAM purging, no cache-clearing on a schedule,
  no "speed boost" that actually slows a modern Mac by dumping caches it rebuilds.
- **No resident scanning.** Real-time protection is macOS's job (XProtect,
  Gatekeeper, the app sandbox). Neptune complements those; it doesn't duplicate
  them badly.
- **No fear-marketing.** No red badges, no "threats found!" inflation.
- **No auto-deletion, ever.** It identifies; you decide.
- **No embedded cloud AI with your keys.** The advisor layer is decoupled (below).

## Vision: the observe → decide → act lifecycle

Neptune is built in three tiers that mirror how a security analyst actually works:

- **Observe** (`sentry`, `redflag_scan`, `audit_system`, `network_check`,
  `netcheck_plus`) — read-only collection. Persistence with signature
  verification, process→network correlation, traffic-interception detection,
  network health, host-based change detection (tripwire-style baselining).
- **Decide** — interpretation. Currently a human reading the consolidated report,
  optionally with an LLM advisor. The report is deliberately the *interface*.
- **Act** (`uninstall`, `check_updates`, `remove_mackeeper`) — mutation, always
  confirmed.

The roadmap unifies these behind one orchestrator with an interactive
keep/delete/skip flow and structured (`--json`) output. That JSON is the spine of
the AI-advisor loop: a model can *read the findings and recommend*, but it never
gets to *run the destructive commands*. Observe → decide → act keeps the human (or
a supervised step) at the act boundary by design. That decoupling — AI-friendly,
not AI-controlled — is the correct security posture for a tool that deletes files
as root, and it's a deliberate architectural stance, not a limitation.

## What this project demonstrates (the security-engineering résumé, in code)

Neptune is a working portfolio of applied security and systems skills:

- **Threat modeling & persistence analysis** — enumerating every macOS persistence
  vector (LaunchAgents/Daemons, privileged helpers, system/kernel extensions,
  cron, login hooks, StartupItems) and verifying each against code signatures.
- **Host-based intrusion detection concepts** — tripwire-style baseline diffing;
  the discipline that a *false "all clear" is worse than a false alarm* (a real bug
  caught during development: a scan reported clean while flagging items — fixed,
  because in security a false negative is the cardinal sin).
- **Network security** — NAT topology analysis (double-NAT / CGNAT detection),
  listener/attack-surface enumeration, traffic-interception detection (rogue
  proxies, content filters, config profiles, `/etc/hosts` hijacks), Wi-Fi/RF
  diagnostics, and router-hardening auditing.
- **Malware/PUP removal methodology** — staged, verified, complete removal
  (system extension → launchd → files → verify), built from real forensic
  inventory rather than guesswork.
- **Secure tooling design** — least privilege (sudo cached once, never run-as-root
  wholesale), fail-safe defaults (read-only), defense against the tool's own
  footguns (confirmation gates, empty-array/argument guards), and portability
  discipline (targets bash 3.2, the version macOS actually ships).
- **Software engineering rigor** — modular architecture, CI that enforces
  shellcheck + syntax + a bash-3.2-compatibility gate + a guard that verifies the
  destructive scripts still contain their confirmation prompts, and an agent-ready
  repo (CLAUDE.md, ROADMAP) for supervised AI-assisted development.

The meta-point: it's not just that the tool works — it's that it was built with the
judgment of someone who thinks about failure modes, blast radius, and trust. That
judgment is the actual deliverable.

## For collaborators (human or AI)

Read `CLAUDE.md` for the operating rules and `ROADMAP.md` for what's next. The
guiding heuristic for any ambiguous decision: **choose the option a
privacy-respecting, no-BS security engineer would choose — never the option a
"cleaner" product would.** That single test resolves most design questions.
