#!/usr/bin/env python3
"""neptune_render.py — turn Neptune's scored records into JSON or HTML.

neptune.sh does the collection and the scoring in bash and awk, because those
must work on a stock Mac with nothing installed. This file does the two
optional outputs, which need real escaping and are only reached with --json,
--html or --replay. Standard library only; Python 3.6+.

It is a module rather than a heredoc inside neptune.sh so it can be imported
and unit-tested directly (tests/test_render.py). The tests used to extract
this code from between marker strings in a shell script and exec() it — a test
that depended on a comment staying put.

Everything here renders from records. Nothing re-derives a finding by reading
printed prose; that is DEVLOG Bug 8.
"""

import argparse
import datetime
import html
import json
import os
import re
import shlex
import subprocess
import sys

SEVERITIES = ("attention", "unknown", "notice", "info", "pass")
CATEGORIES = ("security", "network", "bloat", "maintenance")
KINDS = {
    "look": "reads only",
    "setting": "changes a setting",
    "software": "installs or removes software",
    "neptune": "Neptune command",
}

# The controls a security posture is judged on, in the order a reviewer would
# ask about them. Each is a check id the scans record under — pass or fail — so
# the panel shows what was CHECKED, not merely what went wrong.
POSTURE = (
    ("filevault", "Disk encryption (FileVault)"),
    ("sip", "System Integrity Protection"),
    ("gatekeeper", "Gatekeeper"),
    ("firewall", "Application firewall"),
    ("auto-security-updates", "Automatic security updates"),
    ("auto-login", "Automatic login disabled"),
    ("guest-account", "Guest account"),
    ("remote-access", "Remote access services"),
    ("proxy", "No traffic interception"),
    ("config-profiles", "Configuration profiles"),
)


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------
def _lines(path):
    """Read a text file as lines. errors="replace": a corrupt byte costs one
    garbled character in one field, never the whole report (DEVLOG Bug 10)."""
    if not path or not os.path.exists(path):
        return []
    with open(path, encoding="utf-8", errors="replace") as fh:
        return [line.rstrip("\n") for line in fh]


def load_scored(path):
    """severity|category|scan|check|title|key|acked|vendor"""
    out = []
    for line in _lines(path):
        f = line.split("|")
        if len(f) < 8:
            continue
        out.append({
            "severity": f[0], "category": f[1], "scan": f[2], "check": f[3],
            "title": f[4], "key": f[5], "acknowledged": f[6] == "1",
            "vendor": f[7],
        })
    return out


def load_scores(path):
    scores, acks, passes, counts = {}, {}, {}, {}
    for line in _lines(path):
        f = line.split("|")
        if f[0] == "score" and len(f) >= 5:
            scores[f[1]] = int(f[2]); acks[f[1]] = int(f[3]); passes[f[1]] = int(f[4])
        elif f[0] == "count" and len(f) >= 3:
            counts[f[1]] = int(f[2])
    return scores, acks, passes, counts


def load_listing(path):
    """n<TAB>severity<TAB>category<TAB>key<TAB>title — the numbers the terminal
    printed and --acknowledge resolves. Returned as {(key, title): n}."""
    numbers = {}
    for line in _lines(path):
        if not line or line.startswith("#"):
            continue
        f = line.split("\t")
        if len(f) >= 5 and f[0].isdigit():
            numbers[(f[3], f[4])] = int(f[0])
    return numbers


def load_seen(path):
    seen = {}
    for line in _lines(path):
        if not line or line.startswith("#"):
            continue
        f = line.split("\t")
        if len(f) >= 4:
            try:
                seen[f[0]] = {"first_seen": f[1], "last_seen": f[2], "runs": int(f[3])}
            except ValueError:
                continue
    return seen


def load_quirk_notes(path):
    notes = {}
    for line in _lines(path):
        if not line or line.startswith("#"):
            continue
        f = line.split("\t")
        if len(f) >= 3 and f[1] not in notes:
            notes[f[1]] = f[2]
    return notes


def load_previous_run(path):
    rows = [l.split("\t") for l in _lines(path) if l and not l.startswith("#")]
    rows = [r for r in rows if len(r) >= 6]
    if not rows:
        return None, 0
    return rows[-1], len(rows)


# ---------------------------------------------------------------------------
# Sanitising
# ---------------------------------------------------------------------------
def shell_out(*args):
    """A missing command degrades to "" rather than taking the report down —
    which also lets this run on the Linux CI runner, where sw_vers does not
    exist."""
    try:
        # stdout=PIPE rather than capture_output: the latter is 3.7+, and the
        # stated floor is 3.6 (tests/test_render.py parses this file as 3.6).
        return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              universal_newlines=True).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def make_sanitizer(enabled, host="", user=""):
    """Return a function that strips identifying detail from a string.

    Does not rely on $USER alone: a finding can name a path under a DIFFERENT
    account — another user on the machine, or a daemon running as one — and
    "the variable happened to match" is not a sanitiser. Every /Users/<name>
    path is replaced, whoever it belongs to.
    """
    if not enabled:
        return lambda text: text
    short = host.split(".")[0] if host else ""

    def clean(text):
        # Case-insensitive throughout: acknowledge keys are lowercased copies
        # of titles, and "/users/tito" is as identifying as "/Users/tito".
        if host:
            text = re.sub(re.escape(host), "example-mac", text, flags=re.I)
        if short:
            text = re.sub(re.escape(short), "example-mac", text, flags=re.I)
        if user:
            text = re.sub(r"\b%s\b" % re.escape(user), "exampleuser", text, flags=re.I)
        text = re.sub(r"/Users/[^/\s\"']+", "/Users/exampleuser", text, flags=re.I)
        text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "0.0.0.0", text)
        text = re.sub(r"\b(?:[0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2}\b",
                      "xx:xx:xx:xx:xx:xx", text)
        return text
    return clean


# ---------------------------------------------------------------------------
# Remediation table
#
# For each check: what it means in plain words, what to do about it, and — only
# where a well-known, single-purpose command exists — that command, labelled
# with what it actually does.
#
# The rules, which are the reason this is a table and not a model call:
#   * Nothing is generated. Every command can be looked up in `man`, Apple's
#     documentation, or is Neptune's own.
#   * No command is a pipeline, a chain, or a substitution. tests/test_render.py
#     asserts that against this table.
#   * Everything that changes the machine is labelled; so is everything that
#     only reads, so "look first" is always the obvious path.
#   * Where there is no honest one-command answer — double NAT is a router
#     setting, Wi-Fi latency is physics — the entry says so rather than
#     inventing one. A tool that fabricates a fix for what it cannot fix is a
#     tool you stop believing about what it can.
#
# Entries are keyed by CHECK ID. Titles get reworded; ids do not. A few entries
# also carry a title pattern so records from Neptune 0.x (no check id) can
# still be replayed with advice.
# ---------------------------------------------------------------------------
def path_in(title):
    """The binary a finding is about. "X runs <BINARY> (<PLIST>)": the binary
    is what has a signature to check; codesign against the plist tells you
    nothing."""
    for pat in (r"\bruns (/.+?)(?: \(/|$)", r"\bbinary:(/.+?)$", r"\((/[^)]+)\)\s*$",
                r"(/(?:Library|Applications|Users|opt|private)/\S.*?)(?:\s+\(|\s+—|$)"):
        m = re.search(pat, title)
        if m:
            return m.group(1).strip()
    return None


def app_in(title):
    m = re.search(r"/Applications/([^/]+)\.app", title)
    return m.group(1) if m else None


def _codesign(t):
    p = path_in(t)
    return [("codesign -dvv " + shlex.quote(p), "look",
             "Prints the signature macOS can verify, or says there is none. Changes nothing.")] if p else []


def _uninstall(t):
    a = app_in(t)
    return [("./uninstall.sh " + shlex.quote(a) + " --dry-run", "neptune",
             "Lists every file Neptune would remove for this app, and stops. Run it again "
             "without --dry-run to be asked for confirmation.")] if a else []


def _plist(t):
    m = re.search(r"\((/[^)]+\.plist)\)", t)
    return [("plutil -p " + shlex.quote(m.group(1)), "look",
             "Prints the launch item's configuration, including what it runs and when. Changes nothing.")] if m else []


def _none(_t):
    return []


REMEDIATION = [
    # --- security posture ---------------------------------------------------
    (("filevault",), None,
     "The startup disk is not encrypted. Anyone who gets the machine — stolen, lost, "
     "or sent for repair — can read every file on it without your password.",
     "Turn on FileVault in System Settings > Privacy & Security > FileVault. It "
     "encrypts in the background while you keep working; save the recovery key "
     "somewhere that is not this Mac.",
     lambda t: [("fdesetup status", "look", "Reports whether FileVault is on. Changes nothing.")]),
    (("sip",), None,
     "System Integrity Protection stops even root from modifying macOS itself. With it "
     "off, anything that gets admin rights can rewrite the operating system.",
     "Re-enable it from Recovery: restart holding the power button (Apple silicon) or "
     "Cmd-R (Intel), open Terminal there, run `csrutil enable`, and restart. Only "
     "leave it off if you know exactly which tool required that.",
     lambda t: [("csrutil status", "look", "Reports SIP status. Changes nothing.")]),
    (("gatekeeper",), None,
     "Gatekeeper is what stops unsigned and unnotarised apps from opening without a "
     "warning. With it off, anything downloaded runs silently.",
     "Turn it back on. Individual apps can still be allowed one at a time in "
     "System Settings > Privacy & Security.",
     lambda t: [("sudo spctl --global-enable", "setting",
                 "Re-enables Gatekeeper assessments. Reversible."),
                ("spctl --status", "look", "Reports Gatekeeper status. Changes nothing.")]),
    (("firewall",), None,
     "macOS has a per-application firewall that controls which programs may accept "
     "incoming connections. It ships off. That is fine on a network you control and a "
     "bad default the moment the machine joins public Wi-Fi.",
     "Turn it on. It asks per application, so the cost is a handful of prompts the "
     "first time something that listens starts up.",
     lambda t: [("sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on", "setting",
                 "Turns the application firewall on. Reversible in System Settings > Network > Firewall."),
                ("/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate", "look",
                 "Reports whether it is on. Changes nothing.")]),
    (("auto-security-updates",), None,
     "macOS can install security responses and XProtect malware definitions on its "
     "own, without a full OS update. With that switched off, the built-in malware "
     "scanner's definitions go stale until someone updates by hand.",
     "System Settings > General > Software Update > Automatic Updates: turn on "
     "\"Install Security Responses and system files\".",
     lambda t: [("defaults read /Library/Preferences/com.apple.SoftwareUpdate", "look",
                 "Shows the software-update settings Neptune read. Changes nothing.")]),
    (("auto-update-check",), None,
     "macOS is not checking for updates on its own, so you only find out about "
     "security fixes when you go looking.",
     "System Settings > General > Software Update > Automatic Updates: turn on "
     "\"Check for updates\".",
     _none),
    (("auto-login",), None,
     "The Mac logs a user in at startup without a password, so anyone who can press "
     "the power button is at your desktop. (FileVault disables this; seeing it means "
     "one of the two is off.)",
     "System Settings > Users & Groups > Automatically log in as: Off.",
     _none),
    (("guest-account",), None,
     "The guest account lets anyone log in without a password. Its data is wiped at "
     "logout, but it is still a login you did not have to give anyone.",
     "System Settings > Users & Groups > Guest User: turn it off unless you use it.",
     _none),
    (("remote-access",), None,
     "A remote-access service is on and reachable from every network this Mac joins, "
     "not just this machine. That is fine if you use it, and an open door if you "
     "turned it on once and forgot.",
     "System Settings > General > Sharing: turn off anything you do not use. For "
     "Remote Login specifically, restrict it to your own account there too.",
     lambda t: [("sudo lsof -i -P -n -sTCP:LISTEN", "look",
                 "Lists every listening port and the process holding it. Changes nothing.")]),

    # --- persistence ----------------------------------------------------------
    (("persistence-launchd",), r"^(UNSIGNED|AD-HOC SIGNED) persistence",
     "Something starts itself at login or boot, and macOS cannot tie it to a verified "
     "developer. That is how persistent malware behaves — and also how a lot of "
     "legitimate pro-audio, licensing and virtualisation software behaves, because "
     "those vendors ship helpers they never properly signed. On Apple silicon an "
     "ad-hoc signature is not an identity: anyone can produce one, and most "
     "commodity Mac malware carries exactly that.",
     "Identify the vendor from the path. If it belongs to software you installed on "
     "purpose, acknowledge it so it stops costing points but stays listed. If you do "
     "not recognise it, look at it before deleting anything.",
     lambda t: _codesign(t) + _plist(t) + _uninstall(t)),
    (("persistence-orphan",), r"^ORPHANED persistence",
     "A launch agent or daemon points at a program that is no longer on disk. Usually "
     "an uninstall that left the trigger behind; macOS just fails to start it.",
     "Harmless in itself, but worth removing so the list stays meaningful. If the "
     "vendor is gone, Neptune's uninstaller will find the leftover plist.",
     lambda t: _plist(t) + _uninstall(t)),
    (("persistence-unresolved",), r"could not resolve (its )?target",
     "Neptune could not read what this launch item runs, so it could not check the "
     "signature. That is a check that did not run, not a check that passed.",
     "Open the plist and read ProgramArguments by hand.",
     _plist),
    (("privileged-helpers",), r"^(UNSIGNED|AD-HOC SIGNED) privileged helper",
     "A background program that runs as root, which macOS cannot tie to a verified "
     "developer. Root means it can read and change anything on the machine. Docker "
     "and PACE/iLok both legitimately install helpers in this state.",
     "Confirm the vendor, then decide. This is the category most worth ten minutes: "
     "\"probably fine, runs as root\" deserves confirming rather than acknowledging away.",
     _codesign),
    (("cron-user",), None,
     "Your user account has a crontab — scheduled commands that run on a timer. "
     "Modern macOS software uses launchd instead, so a crontab is either something "
     "you set up yourself or something worth a look.",
     "Read it. If you did not write it, find out what it runs before removing it.",
     lambda t: [("crontab -l", "look", "Prints your crontab. Changes nothing.")]),
    (("cron-root", "etc-crontab"), None,
     "Commands are scheduled to run as root by cron. Nothing on a current Mac needs "
     "this, which makes it a classic place for something to hide.",
     "Read the entries. Anything you cannot account for is worth investigating before "
     "you remove it, so you understand what put it there.",
     lambda t: [("sudo crontab -l", "look", "Prints root's crontab. Changes nothing.")]),
    (("login-hook",), None,
     "A login hook runs a script as root every time anyone logs in. The mechanism has "
     "been deprecated for over a decade; malware still likes it for that reason.",
     "Find out what the script is. Remove the hook only once you know.",
     lambda t: [("sudo defaults read com.apple.loginwindow LoginHook", "look",
                 "Prints the configured hook. Changes nothing.")]),
    (("startup-items",), None,
     "/Library/StartupItems is a pre-2012 boot mechanism. Legitimate current software "
     "does not use it.",
     "List it and identify each item.",
     lambda t: [("ls -la /Library/StartupItems", "look", "Lists startup items. Changes nothing.")]),

    # --- processes -------------------------------------------------------------
    (("process-location",), r"running from suspicious location",
     "A program is running from a temporary folder, your Downloads, or /Users/Shared — "
     "the places malware tends to launch from, because they are writable and "
     "rarely looked at.",
     "Identify it. An installer you just opened is normal; anything else deserves "
     "an answer.",
     _codesign),
    (("process-hidden",), None,
     "A program that macOS cannot tie to a verified developer is running from a hidden "
     "folder (one whose name starts with a dot). Hiding the binary and skipping the "
     "signature is a combination legitimate software rarely needs.",
     "Identify it. Developer tools do live in hidden folders (~/.cargo, ~/.nvm) — if "
     "it is one of yours, acknowledge it.",
     _codesign),
    (("process-deleted",), None,
     "A running program's file is no longer on disk. Almost always an app updated "
     "itself while running and needs a restart to finish. Occasionally it is "
     "software that deleted itself after starting, which is worth knowing about.",
     "Quit and reopen the app named in the path. If it keeps happening after a "
     "restart, investigate.",
     _none),
    (("process-root",), None,
     "A third-party program is running as root, and macOS cannot tie it to a verified "
     "developer. It can read and change anything on the machine.",
     "Identify the vendor. Licence daemons and virtualisation helpers commonly do "
     "this; anything you cannot place is the finding worth chasing first.",
     _codesign),

    # --- network exposure ------------------------------------------------------
    (("listeners",), r"^Listener with unverifiable signature",
     "A program is accepting network connections and macOS cannot tie it to a verified "
     "developer. [localhost-only] means only this Mac can reach it; [ALL INTERFACES] "
     "means anything on your network can.",
     "Localhost-only listeners from software you installed are usually that software "
     "talking to itself. An unverifiable listener on all interfaces deserves an "
     "answer before you acknowledge it.",
     lambda t: [("sudo lsof -i -P -n -sTCP:LISTEN", "look",
                 "Lists every listening port with the process holding it. Changes nothing.")] + _codesign(t)),
    (("network-signing",), r"^(Unsigned|Ad-hoc signed) process with network access",
     "A running program that macOS cannot tie to a verified developer is sending or "
     "receiving network traffic right now.",
     "Match it to software you installed. If you cannot, that is the finding to chase first.",
     _codesign),
    (("baseline-diff:info",), r"^Baseline (created|re-established|format changed)",
     "Neptune set up or replaced its change-detection baseline on this run, so there "
     "was nothing to compare against yet.",
     "Nothing to do, and it costs no points. From the next run on, anything that "
     "appears or disappears is reported against this snapshot.",
     _none),
    (("connections-view",), r"^Unprivileged view",
     "The per-app connection count in the network check ran without root, so it only "
     "saw your own processes. Root-owned daemons were not in its view.",
     "Nothing to do. The sentry and red-flag scans elevate and do cover them, and "
     "both ran in this suite.",
     _none),
    (("baseline-diff",), r"^NEW( since baseline)?:",
     "Something appeared since the last known-good snapshot: a launch item, a helper, "
     "a system extension, an app, or a listening service.",
     "If you installed it, accept the new state so future runs compare against it. "
     "If you did not, identify it before doing anything else.",
     lambda t: [("./sentry.sh --rebaseline", "neptune",
                 "Accepts the current state as known-good. Only after you have identified the change.")]),

    # --- interception ------------------------------------------------------------
    (("proxy",), r"^System proxy is ACTIVE",
     "Web traffic is being routed through a proxy. Corporate networks and some VPNs do "
     "this deliberately; adware does it to read and rewrite your browsing.",
     "Confirm who set it. If it is not your employer's or your VPN's, remove it in "
     "System Settings > Network > (your connection) > Details > Proxies.",
     lambda t: [("scutil --proxy", "look", "Prints the active proxy configuration. Changes nothing.")]),
    (("net-extensions",), None,
     "A network or endpoint-security system extension is installed. These can see — "
     "and some can filter or rewrite — every connection on the machine. VPNs, "
     "firewalls and security tools use them legitimately; this is also exactly the "
     "category MacKeeper used.",
     "Check each one is software you chose. Remove unwanted ones in System Settings > "
     "General > Login Items & Extensions.",
     lambda t: [("systemextensionsctl list", "look", "Lists system extensions. Changes nothing.")]),
    (("config-profiles",), r"^Configuration profiles installed",
     "A configuration profile can enforce proxies, DNS servers, trusted certificates "
     "and restrictions. Normal on a work-managed Mac; a serious red flag on a personal one.",
     "Review each in System Settings > General > Device Management. Remove any you did "
     "not install on purpose.",
     lambda t: [("sudo profiles list", "look", "Lists installed profiles. Changes nothing.")]),
    (("etc-hosts",), None,
     "/etc/hosts has custom entries. They override DNS for the names listed, which is "
     "useful for blocking or development — and a way to silently redirect a site.",
     "Read the entries. Keep the ones you added; remove any you cannot account for.",
     lambda t: [("cat /etc/hosts", "look", "Prints the hosts file. Changes nothing.")]),
    (("browser-extensions",), None,
     "A browser extension holds a permission that lets it reroute all of your browsing "
     "(proxy) or attach a debugger to any tab you open (debugger). Very few "
     "legitimate extensions need either.",
     "Open the browser's extensions page and check it is one you installed on purpose. "
     "Remove it if not.",
     _none),

    # --- network health ---------------------------------------------------------
    (("double-nat",), r"(SECOND PRIVATE ROUTER|double NAT)",
     "Two routers are doing address translation between this Mac and the internet — "
     "usually an ISP box in router mode in front of your own. It breaks inbound "
     "connections, port forwarding and some VPN and game traffic.",
     "This cannot be fixed from the Mac; it is a router setting. Check your own "
     "router's WAN address: if it shows your public IP, the ISP box is already in "
     "passthrough and there is nothing to fix. If it shows 192.168.x or 10.x, enable "
     "bridge or IP-passthrough mode on the ISP gateway.",
     lambda t: [("traceroute -n -m 4 1.1.1.1", "look",
                 "Shows the first few hops so you can see both routers. Changes nothing.")]),
    (("cgnat",), r"^CGNAT",
     "Your ISP translates addresses on their side, so you have no public IP of your own.",
     "Nothing to fix on this Mac. It only matters for inbound connections; ask the ISP "
     "for a public IP if you need them.",
     _none),
    (("dns",), r"^DNS is unreliable",
     "Some name lookups failed. Every connection starts with one, so this shows up as "
     "pages that hang before loading, or apps that intermittently say they are offline.",
     "Check System Settings > Network > (your connection) > Details > DNS for servers you "
     "did not set. If the router hands out a slow or failing resolver, set 1.1.1.1 or "
     "9.9.9.9 there instead.",
     lambda t: [("scutil --dns", "look", "Prints the resolvers this Mac is using. Changes nothing.")]),
    (("lan-latency", "gateway-latency"), r"(LAN latency high|Gateway latency over)",
     "Round trips to your own router are slower than a local network should be. On "
     "Wi-Fi that is usually distance or mesh backhaul; on Ethernet it is unusual.",
     "Compare the average with the worst ping on the same line: a high worst with a "
     "low average is an intermittent link, not a slow one. No command fixes this — "
     "move closer, move the node, or use a cable, then re-run.",
     _none),

    # --- bloat ----------------------------------------------------------------
    (("stale-apps",), None,
     "Apps you have not opened in over six months, by macOS's own last-used date. "
     "Unused apps are not just disk space: several may still run helpers or updaters.",
     "Remove the ones you do not need with Neptune's uninstaller, which also finds "
     "their leftovers. Keep drivers and editors for hardware you own.",
     lambda t: [("./uninstall.sh 'App Name' --dry-run", "neptune",
                 "Shows everything an app left on disk, and stops. Substitute the app's name.")]),
    (("caches",), None,
     "Application caches have grown large. Caches are safe to clear in principle — apps "
     "rebuild them — but some (audio sample libraries, plugin scans) are slow to "
     "rebuild, which is why Neptune never clears them without asking.",
     "See what is there and choose what to clear. Nothing is deleted until you pick "
     "items and confirm.",
     lambda t: [("./clean_caches.sh", "neptune",
                 "Lists your caches by size and changes nothing."),
                ("./clean_caches.sh --apply", "neptune",
                 "Lets you pick caches to clear, shows exactly what goes, and asks first.")]),
    (("brew-cache",), None,
     "Homebrew keeps every package it has downloaded, and old versions of what it has "
     "upgraded. None of it is needed to run what is installed.",
     "Let Homebrew remove it.",
     lambda t: [("brew cleanup --prune=all -n", "look",
                 "Lists what Homebrew would remove. Changes nothing."),
                ("brew cleanup --prune=all", "software",
                 "Removes old versions and cached downloads. Installed software is untouched.")]),
    (("dev-junk",), None,
     "Developer tools leave large regenerable data behind: Xcode build products, "
     "device support files for old iOS versions, simulator caches.",
     "Delete it from inside the tool where one exists (Xcode > Settings > Locations, "
     "or Platforms for simulators). Everything listed regenerates on the next build.",
     _none),
    (("logs",), None,
     "Log folders have grown large. Usually one app logging too much.",
     "Find which app, and fix or reinstall it; deleting logs alone just resets the clock.",
     lambda t: [("du -sh ~/Library/Logs/*", "look", "Lists log folder sizes. Changes nothing.")]),
    (("kexts",), None,
     "A third-party kernel extension is loaded. Kexts run inside the kernel with no "
     "isolation; Apple has deprecated them in favour of system extensions.",
     "Identify the vendor and check for a current version that no longer needs one.",
     lambda t: [("kextstat", "look", "Lists loaded kernel extensions. Changes nothing.")]),

    # --- maintenance ------------------------------------------------------------
    (("macos-updates",), r"(Apple software update|macOS update)",
     "Apple updates are waiting. Point releases and Safari updates carry most of the "
     "security fixes Apple ships, often for flaws already being exploited.",
     "Install them in System Settings > General > Software Update.",
     lambda t: [("softwareupdate -l", "look", "Lists pending updates. Changes nothing.")]),
    (("macos-upgrade",), None,
     "A new major version of macOS is available. That is a decision, not maintenance: "
     "Apple keeps shipping security fixes for the release you are on for about two "
     "more years, and a major upgrade can break drivers and plug-ins.",
     "Upgrade when the software you depend on supports it. Neptune never installs a "
     "major upgrade, even with --upgrade.",
     _none),
    (("macos-updates:unknown", "brew-outdated:unknown", "brew-doctor:unknown",
      "mas-outdated:unknown"), None,
     "The update check could not finish — usually no network, or the update server "
     "was slow — so Neptune cannot say whether anything is out of date.",
     "Re-run when online. Until then, treat this source as unchecked, not up to date.",
     _none),
    (("brew-outdated",), r"(Homebrew formula|Homebrew cask|Outdated formulae|Outdated casks)",
     "Homebrew-managed software has updates available. Out-of-date browsers and chat "
     "clients are the most commonly exploited software on a desktop.",
     "Review the list in the full report, then upgrade. Keep licence-managed "
     "software (plug-in managers, iLok-protected tools) on its vendor's own updater.",
     lambda t: [("brew outdated", "look", "Lists what would be upgraded. Changes nothing."),
                ("brew upgrade", "software", "Upgrades Homebrew formulae and casks.")]),
    (("app-updates",), r"self-updating apps are behind",
     "Apps that update themselves are behind the version Homebrew's catalog lists. "
     "They are not managed by Homebrew, so nothing updates them unless you open them.",
     "Use each app's own Check for Updates, or hand it to Homebrew once so brew upgrade "
     "keeps it current. Leave licence-managed software on its vendor's updater.",
     lambda t: [("brew install --cask --adopt cask-name", "software",
                 "Lets Homebrew take over an app already installed by hand. Substitute the cask named in the report.")]),
    (("mas-outdated",), None,
     "App Store apps have updates available.",
     "Update them in the App Store app, or with mas.",
     lambda t: [("mas outdated", "look", "Lists outdated App Store apps. Changes nothing."),
                ("mas upgrade", "software", "Installs the App Store updates listed.")]),
    (("brew-doctor",), None,
     "Homebrew's own health check found problems with the installation.",
     "Read the warnings; each one says how to fix itself.",
     lambda t: [("brew doctor", "look", "Prints Homebrew's warnings. Changes nothing.")]),

    # --- about the run itself ------------------------------------------------------
    (("scan-failed", "scan-missing", "scan-silent", "record-format"), None,
     "Part of the scan did not complete, so some checks are missing from this report. "
     "Missing is not the same as passed, which is why this costs points and why the "
     "verdict cannot read as fully healthy.",
     "Re-run. If it fails again, run the named script on its own to see the error.",
     _none),
]


# Checks whose normal finding IS an unknown, so their own entry already says
# the right thing for that severity.
UNKNOWN_NATIVE = ("persistence-unresolved", "scan-failed", "scan-missing",
                  "scan-silent", "record-format")

UNKNOWN_ADVICE = (
    "Neptune could not complete this check, so it does not know either way. A check "
    "that did not run is not a check that passed, which is why it costs points.",
    "Re-run Neptune. If this keeps appearing, run the scan named in the finding on its "
    "own; its output says what it could not read.",
    _none)


def advise(check, title, severity=None):
    """Remediation for a record: by check id first, then by title pattern (for
    replayed 0.x records that carry no id)."""
    # "check:severity" beats "check": the same check can mean different things at
    # different severities (a baseline that CHANGED versus one just created).
    wanted = ([check + ":" + severity] if check and severity else []) + ([check] if check else [])
    for want in wanted:
        # An unknown is not a failure. "FileVault is off — turn it on" is the
        # wrong advice for "FileVault's state could not be read", so a check
        # whose entry describes the FAILED state falls through to the generic
        # could-not-check advice instead of borrowing it.
        if severity == "unknown" and want == check and check not in UNKNOWN_NATIVE:
            return _advice(*UNKNOWN_ADVICE, title=title)
        for ids, _pattern, means, do, cmdf in REMEDIATION:
            if want in ids:
                return _advice(means, do, cmdf, title)
    if not check:
        for ids, pattern, means, do, cmdf in REMEDIATION:
            if severity == "unknown" and ids[0] not in UNKNOWN_NATIVE:
                continue
            if pattern and re.search(pattern, title, re.I):
                return _advice(means, do, cmdf, title)
        if severity == "unknown":
            return _advice(*UNKNOWN_ADVICE, title=title)
    return {"means": "", "do": "", "commands": [], "unmapped": True}


def _advice(means, do, cmdf, title):
    cmds = [{"command": c, "kind": k, "effect": e} for c, k, e in cmdf(title)]
    return {"means": means, "do": do, "commands": cmds}


def remediation_command_problems():
    """Every command in the table must be one command: no pipeline, chain or
    substitution, and a known kind. Returns a list of problems (empty = clean).
    Characters are built rather than written, so this file stays quotable."""
    forbidden = ("|", ";", "&&", ">", chr(96), "$" + "(")
    sample = ("UNSIGNED persistence: com.example.thing runs /Library/Foo/bar "
              "(/Library/LaunchDaemons/com.example.thing.plist)")
    problems = []
    for ids, _pat, _means, _do, cmdf in REMEDIATION:
        for command, kind, _effect in cmdf(sample):
            for ch in forbidden:
                if ch in command:
                    problems.append("%s: %r contains %r" % (ids[0], command, ch))
            if kind not in KINDS:
                problems.append("%s: %r has unknown kind %r" % (ids[0], command, kind))
    return problems


# ---------------------------------------------------------------------------
# Building the report model — one dict that both JSON and HTML render from
# ---------------------------------------------------------------------------
def build_report(args):
    host = shell_out("hostname")
    clean = make_sanitizer(args.sanitize, host, os.environ.get("USER", ""))
    records = load_scored(args.scored)
    scores, acks, passes, counts = load_scores(args.scores)
    numbers = load_listing(args.listing)
    seen = load_seen(args.seen)
    notes = load_quirk_notes(args.quirks)
    prev, runs_on_record = load_previous_run(args.history)

    findings, checks = [], []
    for r in records:
        item = {
            "severity": r["severity"], "category": r["category"], "scan": r["scan"],
            "check": r["check"], "title": clean(r["title"]),
        }
        if r["severity"] == "pass":
            checks.append(item)
            continue
        item["key"] = clean(r["key"])
        item["acknowledged"] = r["acknowledged"]
        n = numbers.get((r["key"], r["title"]))
        if n is not None:
            item["n"] = n
        if r["vendor"]:
            item["vendor"] = {"name": r["vendor"], "note": notes.get(r["vendor"], "")}
        if r["key"] in seen:
            item["first_seen"] = seen[r["key"]]["first_seen"]
            item["runs"] = seen[r["key"]]["runs"]
        advice = advise(r["check"], r["title"], r["severity"])
        if args.sanitize:
            for c in advice["commands"]:
                c["command"] = clean(c["command"])
        item["advice"] = advice
        findings.append(item)

    # Posture: the worst state recorded under each control's check id.
    rank = {"attention": 4, "unknown": 3, "notice": 2, "info": 1, "pass": 0}
    posture = []
    for cid, label in POSTURE:
        mine = [r for r in records if r["check"] == cid]
        if not mine:
            state = "not-checked"
        else:
            worst = max(mine, key=lambda r: rank.get(r["severity"], 0))
            state = {"attention": "fail", "notice": "warn", "unknown": "unknown",
                     "info": "pass", "pass": "pass"}[worst["severity"]]
            if worst["acknowledged"] and state in ("fail", "warn"):
                state = "acknowledged"
        detail = ""
        if mine:
            detail = clean(max(mine, key=lambda r: rank.get(r["severity"], 0))["title"])
        posture.append({"check": cid, "label": label, "state": state, "detail": detail})

    previous = None
    if prev:
        try:
            previous = {"date": prev[0], "verdict": prev[1],
                        "scores": {"security": int(prev[2]), "network": int(prev[3]),
                                   "bloat": int(prev[4]), "maintenance": int(prev[5])}}
        except (ValueError, IndexError):
            previous = None

    return {
        "neptune": {
            "schema": 3,
            "version": args.version,
            "generated": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
            "host": clean(host) if host else "",
            "macos": shell_out("sw_vers", "-productVersion"),
            "sanitized": bool(args.sanitize),
            "replay_of": args.replay_source or None,
        },
        "verdict": args.verdict_key,
        "verdict_text": args.verdict,
        "integrity": {"ok": args.integrity == "1", "problem": args.integrity_why or None},
        "scores": scores,
        "acknowledged_by_category": acks,
        "passed_by_category": passes,
        "counts": counts,
        "posture": posture,
        "findings": findings,
        "checks_passed": checks,
        "previous_run": previous,
        "runs_on_record": runs_on_record,
    }


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------
def render_json(report):
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


# ---------------------------------------------------------------------------
# HTML
#
# No JavaScript, no external stylesheet, no webfont, no image request — the
# file makes no network connections when opened, which is a claim a security
# report should be able to make about itself. Collapsible sections are
# <details> elements, which need no script. CI asserts all of that.
# ---------------------------------------------------------------------------
CSS = """
:root{--bg:#fbfbfa;--card:#fff;--ink:#1a1a1a;--mute:#5d5d5d;--line:#e3e1dd;
--good:#2f7d4f;--warn:#a8721a;--bad:#a63232;--accent:#2d4f7c;--code:#f4f3f0}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif}
.wrap{max-width:860px;margin:0 auto;padding:32px 20px 80px}
h1{font-size:26px;margin:0 0 4px;letter-spacing:-.2px}
h2{font-size:19px;margin:40px 0 6px;letter-spacing:-.1px}
.sub{color:var(--mute);font-size:14px;margin:0 0 28px}
.verdict{padding:18px 20px;border-radius:8px;border:1px solid var(--line);
background:var(--card);margin:0 0 20px;border-left-width:5px}
.verdict.good{border-left-color:var(--good)}.verdict.warn{border-left-color:var(--warn)}
.verdict.bad{border-left-color:var(--bad)}
.verdict strong{font-size:20px;display:block;margin-bottom:2px}
.verdict .tally{color:var(--mute);font-size:14px}
.integrity{background:#fff4f2;border:1px solid var(--bad);color:var(--bad);border-radius:8px;
padding:12px 16px;margin:0 0 20px;font-size:15px}
.scores{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:0 0 8px}
.score{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px 16px}
.score .n{font-size:28px;font-weight:600;letter-spacing:-1px}
.score .n small{font-size:14px;font-weight:400;color:var(--mute);letter-spacing:0}
.score .cat{text-transform:uppercase;font-size:11px;letter-spacing:.09em;color:var(--mute)}
.score .pc{font-size:12px;color:var(--mute)}
.bar{display:block;height:6px;background:var(--line);border-radius:3px;overflow:hidden;margin:8px 0 6px}
.fill{display:block;height:100%}
.f0{background:var(--bad)}.f1{background:var(--warn)}.f2{background:var(--good)}
.d{font-size:12px}.d.up{color:var(--good)}.d.down{color:var(--bad)}.d.flat{color:var(--mute)}
.note{color:var(--mute);font-size:14px;margin:0 0 20px}
.posture{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:8px;margin:0 0 8px}
.ctl{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px;
display:flex;gap:10px;align-items:flex-start;font-size:14px}
.ctl .st{flex:0 0 auto;font-size:11px;text-transform:uppercase;letter-spacing:.07em;
padding:2px 6px;border-radius:3px;border:1px solid var(--line);margin-top:2px;min-width:74px;text-align:center}
.st.pass{color:var(--good);border-color:var(--good)}.st.fail{color:var(--bad);border-color:var(--bad)}
.st.warn{color:var(--warn);border-color:var(--warn)}.st.unknown{color:var(--warn)}
.st.not-checked,.st.acknowledged{color:var(--mute)}
.ctl .lb{font-weight:600}.ctl .dt{color:var(--mute);font-size:13px;display:block}
details.f{background:var(--card);border:1px solid var(--line);border-radius:8px;margin:0 0 8px}
details.f>summary{padding:12px 16px;cursor:pointer;list-style:none;display:flex;gap:10px}
details.f>summary::-webkit-details-marker{display:none}
details.f>summary::before{content:"\\25B8";color:var(--mute);flex:0 0 auto}
details.f[open]>summary::before{content:"\\25BE"}
.num{color:var(--mute);flex:0 0 auto;font-variant-numeric:tabular-nums;min-width:1.6em}
.tag,.vendor{display:inline-block;font-size:10px;text-transform:uppercase;letter-spacing:.08em;
padding:2px 6px;border-radius:3px;vertical-align:2px;margin-right:6px}
.tag{background:var(--code);color:var(--mute)}
.vendor{border:1px solid var(--line);color:var(--accent)}
.body{padding:2px 16px 16px 40px;border-top:1px solid var(--line)}
.body p{margin:12px 0 0}
.lbl{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--mute);margin:16px 0 2px;font-weight:600}
.streak{font-size:12px;color:var(--mute);margin:10px 0 0}
.vnote{background:var(--code);border-left:3px solid var(--accent);padding:10px 12px;
border-radius:0 5px 5px 0;margin:12px 0 0;font-size:14px}
pre{background:var(--code);border:1px solid var(--line);border-radius:6px;padding:10px 12px;
overflow-x:auto;margin:4px 0 2px;font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap}
code{font:13px ui-monospace,SFMono-Regular,Menlo,monospace}
.eff{font-size:13px;color:var(--mute);margin:0 0 10px}
.kind{display:inline-block;font-size:10px;text-transform:uppercase;letter-spacing:.07em;
padding:1px 5px;border-radius:3px;margin-right:6px;border:1px solid var(--line)}
.kind.look{color:var(--accent)}.kind.setting{color:var(--warn)}
.kind.software{color:var(--bad)}.kind.neptune{color:var(--good)}
.box{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:18px 20px;margin:0 0 16px}
.box p:first-child{margin-top:0}
ul.passed{margin:6px 0 0;padding-left:20px;font-size:14px}ul.passed li{margin:0 0 4px}
ol.steps{margin:8px 0 0;padding-left:22px}ol.steps li{margin:0 0 10px}
footer{margin-top:52px;padding-top:20px;border-top:1px solid var(--line);color:var(--mute);font-size:13px}
@media print{body{background:#fff}details.f{break-inside:avoid}details.f>summary::before{content:""}}
@media (prefers-color-scheme:dark){
:root{--bg:#16161a;--card:#1d1d22;--ink:#e8e6e3;--mute:#9b9892;--line:#31313a;
--good:#6bbf87;--warn:#d9a441;--bad:#e07a7a;--accent:#8ab0e0;--code:#24242b}
.integrity{background:#2a1a1a}}
"""

SECTIONS = (
    ("attention", "Needs attention", "Work through these first."),
    ("unknown", "Could not be checked", "Treated as unknown, not as clean. A check that did not run is not a pass."),
    ("notice", "Minor", "Worth knowing. Not urgent."),
    ("info", "For information", "About this run, not about your machine. These cost no points."),
)


def plural(n, one, many):
    return "%d %s" % (n, one if n == 1 else many)


def render_html(report):
    e = html.escape
    meta = report["neptune"]
    counts = report["counts"]
    scores = report["scores"]
    prev = report["previous_run"]
    W = []
    add = W.append

    vclass = {"needs_attention": "bad", "incomplete": "warn",
              "healthy_minor": "good", "healthy": "good"}.get(report["verdict"], "warn")

    add("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
        "<title>Neptune report &mdash; " + e(meta["host"] or "Mac") + "</title>\n"
        "<style>" + CSS + "</style></head><body><div class=\"wrap\">")
    add("<h1>Neptune report</h1>")
    sub = [e(meta["host"] or "this Mac")]
    if meta["macos"]:
        sub.append("macOS " + e(meta["macos"]))
    sub.append(e(datetime.datetime.now().strftime("%d %B %Y, %H:%M")))
    if meta["replay_of"]:
        sub.append("replayed from " + e(meta["replay_of"]))
    add("<p class=\"sub\">" + " &middot; ".join(sub) + "</p>")

    add("<div class=\"verdict %s\"><strong>%s</strong><span class=\"tally\">"
        "%d checks passed &middot; %d needing attention &middot; %d minor &middot; "
        "%d could not be checked &middot; %d acknowledged</span></div>"
        % (vclass, e(report["verdict_text"] or report["verdict"]),
           counts.get("pass", 0), counts.get("attention", 0), counts.get("notice", 0),
           counts.get("unknown", 0), counts.get("acknowledged", 0)))

    if not report["integrity"]["ok"]:
        add("<div class=\"integrity\"><strong>Report integrity failure.</strong> %s. "
            "Some results are missing, so nothing in this report proves the machine is "
            "clean.</div>" % e(report["integrity"]["problem"] or "Results were lost"))

    # Scores
    add("<div class=\"scores\">")
    for cat in CATEGORIES:
        n = scores.get(cat, 100)
        fill = 0 if n < 50 else 1 if n < 80 else 2
        delta = ""
        if prev and cat in prev["scores"]:
            d = n - prev["scores"][cat]
            delta = ('<span class="d flat">no change since last run</span>' if d == 0 else
                     '<span class="d %s">%+d since last run</span>' % ("up" if d > 0 else "down", d))
        add("<div class=\"score\"><div class=\"cat\">%s</div><div class=\"n\">%d<small>/100</small></div>"
            "<span class=\"bar\"><span class=\"fill f%d\" style=\"width:%d%%\"></span></span>"
            "<span class=\"pc\">%s</span><br>%s</div>"
            % (e(cat), n, fill, n, plural(report["passed_by_category"].get(cat, 0), "check passed",
                                          "checks passed"), delta))
    add("</div>")
    if prev:
        add("<p class=\"note\">Compared with the run on %s. %d earlier run%s on record.</p>"
            % (e(prev["date"]), report["runs_on_record"], "" if report["runs_on_record"] == 1 else "s"))
    elif not meta["replay_of"]:
        add("<p class=\"note\">First recorded run. Work through the list below and run Neptune "
            "again: this section will then show what each score did.</p>")

    # Posture
    unchecked = sum(1 for p in report["posture"] if p["state"] == "not-checked")
    add("<h2>Security posture</h2><p class=\"note\">The controls a reviewer asks about first. "
        "Each state comes from the check itself, not from the absence of a complaint.%s</p>"
        "<div class=\"posture\">"
        % ("" if not unchecked else
           " <strong>%s recorded no result on this run</strong> — %s"
           % (plural(unchecked, "control", "controls"),
              "the run this report was replayed from did not record them (runs before 1.0 recorded no passes)."
              if meta["replay_of"] else "a scan did not reach it, which is a fault in the run.")))
    labels = {"pass": "on / ok", "fail": "problem", "warn": "review", "unknown": "unknown",
              "not-checked": "not checked", "acknowledged": "acknowledged"}
    for p in report["posture"]:
        add("<div class=\"ctl\"><span class=\"st %s\">%s</span><span><span class=\"lb\">%s</span>"
            "<span class=\"dt\">%s</span></span></div>"
            % (p["state"], labels[p["state"]], e(p["label"]), e(p["detail"])))
    add("</div>")

    # Findings
    findings = report["findings"]
    kind_label = KINDS
    for sev, heading, blurb in SECTIONS:
        group = [f for f in findings if f["severity"] == sev and not f["acknowledged"]]
        if not group:
            continue
        group.sort(key=lambda f: f.get("n", 10 ** 6))
        add("<h2>%s</h2><p class=\"note\">%s</p>" % (e(heading), e(blurb)))
        for f in group:
            label = "%d." % f["n"] if "n" in f else "&middot;"
            ven = f.get("vendor")
            add("<details class=\"f\"%s><summary><span class=\"num\">%s</span><span>"
                "<span class=\"tag\">%s</span>%s%s</span></summary><div class=\"body\">"
                % (" open" if sev == "attention" else "", label, e(f["category"]),
                   ("<span class=\"vendor\">known %s pattern</span>" % e(ven["name"])) if ven else "",
                   e(f["title"])))
            if ven and ven.get("note"):
                add("<div class=\"vnote\"><strong>%s.</strong> %s This is a label, not a "
                    "dismissal: the finding is still counted and still costs points. "
                    "Acknowledging it is a decision about your machine, and stays yours "
                    "to make.</div>" % (e(ven["name"]), e(ven["note"])))
            runs = f.get("runs", 0)
            if runs > 1:
                add("<p class=\"streak\">Seen in %d runs, first on %s.%s</p>"
                    % (runs, e(f.get("first_seen", "?")),
                       " Still here after everything done since." if runs >= 4 else ""))
            elif runs == 1:
                add("<p class=\"streak\">First seen in this run.</p>")
            a = f["advice"]
            if a.get("unmapped"):
                add("<p>No stock explanation for this one yet. The full text report has the "
                    "surrounding output from the scan that raised it.</p>")
            else:
                add("<div class=\"lbl\">What this means</div><p>%s</p>" % e(a["means"]))
                add("<div class=\"lbl\">What to do</div><p>%s</p>" % e(a["do"]))
            cmds = list(a["commands"])
            if "n" in f:
                cmds.append({"command": "./neptune.sh --acknowledge %d" % f["n"], "kind": "neptune",
                             "effect": "Marks this a known-good quirk on this machine. It stays "
                                       "listed and counted; it only stops deducting. Undo by "
                                       "deleting its line from ~/.neptune/allow."})
            if cmds:
                add("<div class=\"lbl\">Commands</div>")
                for c in cmds:
                    add("<pre>%s</pre><p class=\"eff\"><span class=\"kind %s\">%s</span>%s</p>"
                        % (e(c["command"]), c["kind"], e(kind_label[c["kind"]]), e(c["effect"])))
            add("</div></details>")

    acked = [f for f in findings if f["acknowledged"]]
    if acked:
        add("<h2>Acknowledged</h2><p class=\"note\">Known-good on this machine. Still found, "
            "still listed, still counted &mdash; they only stop deducting. Nothing is ever "
            "silently hidden.</p>")
        for f in acked:
            add("<details class=\"f\"><summary><span class=\"num\">&middot;</span><span>"
                "<span class=\"tag\">%s</span>%s</span></summary><div class=\"body\"><p>"
                "Acknowledged in <code>~/.neptune/allow</code>. Delete that line to start "
                "counting it again.</p></div></details>" % (e(f["category"]), e(f["title"])))

    # What was checked
    passed = report["checks_passed"]
    if passed:
        add("<h2>What was checked and passed</h2><p class=\"note\">%d checks ran and found "
            "nothing wrong. A report that only lists problems cannot prove anything about "
            "the rest; this section is the proof.</p>" % len(passed))
        for cat in CATEGORIES:
            mine = [p for p in passed if p["category"] == cat]
            if not mine:
                continue
            add("<details class=\"f\"><summary><span class=\"num\">%d</span><span>"
                "<span class=\"tag\">%s</span>checks passed</span></summary><div class=\"body\">"
                "<ul class=\"passed\">" % (len(mine), e(cat)))
            for p in mine:
                add("<li>%s</li>" % e(p["title"]))
            add("</ul></div></details>")

    add("<h2>Hand this to an AI assistant</h2><div class=\"box\">"
        "<p>The same findings export as structured JSON, which a model reads far more "
        "reliably than a screenshot of a terminal. The sanitised version replaces your "
        "hostname, username, home-folder paths, IP and MAC addresses first.</p><ol class=\"steps\">"
        "<li><div class=\"lbl\">Export it</div><pre>./neptune.sh --json --sanitize</pre>"
        "<p class=\"eff\"><span class=\"kind look\">reads only</span>Every finding carries its "
        "severity, category, check id and the same explanation and commands shown here.</p></li>"
        "<li><div class=\"lbl\">Attach the file and ask for a plan</div><pre>"
        "Here is a Neptune security audit of my Mac as JSON.\n\n"
        "Walk me through it in priority order. For each finding tell me what it is,\n"
        "whether it looks like a known vendor quirk or something worth chasing, and\n"
        "what I should do about it.\n\n"
        "Constraints: recommend Neptune&#x27;s own commands (./uninstall.sh &lt;app&gt; --dry-run,\n"
        "./neptune.sh --acknowledge N) or documented single-purpose macOS commands.\n"
        "Do not give me shell to paste that I cannot look up. If you are unsure about\n"
        "a finding, say so rather than guessing.</pre>"
        "<p class=\"eff\">That last paragraph is the important one. A model asked for "
        "&ldquo;the fix&rdquo; will happily invent a <code>sudo</code> one-liner, and a "
        "command you cannot verify is exactly the thing this tool exists to argue against.</p></li>"
        "<li><div class=\"lbl\">Do the work, then run Neptune again</div><pre>./neptune.sh --html</pre>"
        "<p class=\"eff\"><span class=\"kind look\">reads only</span>The next report compares "
        "against this one. That is the loop: audit, understand, act, re-measure.</p></li>"
        "</ol></div>")

    add("<h2>How to read the scores</h2><div class=\"box\"><p>Each category starts at 100 "
        "and loses points per finding. The first issue of a kind in a category costs full "
        "weight; repeats cost about a third, because nine unsigned launch items are usually "
        "one vendor habit rather than nine independent problems. A check that could not run "
        "costs points too: missing is not the same as passed. Every deduction traces to a "
        "finding listed above &mdash; a score whose arithmetic you cannot follow is "
        "decoration, not information.</p><p>A low security score is not the same as "
        "&ldquo;compromised&rdquo;. On a working Mac with pro-audio or virtualisation "
        "software, most of what lands here is vendor sloppiness. That is worth knowing and "
        "worth acknowledging deliberately &mdash; which is different from a tool quietly "
        "deciding for you that it does not matter.</p></div>")

    add("<footer><p><strong>This file contains no JavaScript</strong>, no external "
        "stylesheet, no webfont and no image request. Opening it makes no network "
        "connections; you can read the whole thing in a text editor.</p>"
        "<p>Neptune is read-only apart from its own notes in <code>~/.neptune/</code> and "
        "<code>~/.sentry/</code>. No daemon, nothing scheduled, nothing sent anywhere. "
        "<code>SECURITY.md</code> in the repository lists the complete footprint, why each "
        "script asks for <code>sudo</code>, and how to verify all of it yourself.</p>"
        "<p>Neptune %s &middot; generated %s%s</p></footer></div></body></html>"
        % (e(meta["version"] or "?"), e(meta["generated"]),
           " &middot; sanitised" if meta["sanitized"] else ""))
    return "\n".join(W) + "\n"


# ---------------------------------------------------------------------------
# Replay: JSON back into records
# ---------------------------------------------------------------------------
def json_to_records(path):
    """Turn a saved --json file back into scan records, so --replay can run the
    real pipeline on it rather than trusting the numbers stored inside."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    records, allow = [], []

    def esc(text):
        return str(text).replace("|", "/").replace("\n", " ").replace("\t", " ")

    for f in data.get("findings", []):
        records.append("|".join([esc(f.get("severity", "")), esc(f.get("category", "")),
                                 esc(f.get("scan", "replay")), esc(f.get("check", "")),
                                 esc(f.get("title", ""))]))
        if f.get("acknowledged") and f.get("key"):
            allow.append(f["key"])
    for c in data.get("checks_passed", []):
        records.append("|".join(["pass", esc(c.get("category", "")), esc(c.get("scan", "replay")),
                                 esc(c.get("check", "")), esc(c.get("title", ""))]))
    return records, allow


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--format", choices=("json", "html"))
    ap.add_argument("--scored"); ap.add_argument("--scores"); ap.add_argument("--listing")
    ap.add_argument("--verdict-key", default="incomplete"); ap.add_argument("--verdict", default="")
    ap.add_argument("--integrity", default="1"); ap.add_argument("--integrity-why", default="")
    ap.add_argument("--quirks", default=""); ap.add_argument("--version", default="")
    ap.add_argument("--history", default=""); ap.add_argument("--seen", default="")
    ap.add_argument("--replay-source", default="")
    ap.add_argument("--sanitize", action="store_true")
    ap.add_argument("--json-to-records"); ap.add_argument("--records-out"); ap.add_argument("--allow-out")
    args = ap.parse_args(argv)

    if args.json_to_records:
        try:
            records, allow = json_to_records(args.json_to_records)
        except (OSError, ValueError) as exc:
            sys.stderr.write("Cannot read %s as Neptune JSON: %s\n" % (args.json_to_records, exc))
            return 64
        with open(args.records_out, "w", encoding="utf-8") as fh:
            fh.write("\n".join(records) + ("\n" if records else ""))
        with open(args.allow_out, "w", encoding="utf-8") as fh:
            fh.write("\n".join(allow) + ("\n" if allow else ""))
        return 0

    if not (args.format and args.scored and args.scores):
        ap.error("--format, --scored and --scores are required")
    report = build_report(args)
    sys.stdout.write(render_json(report) if args.format == "json" else render_html(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
