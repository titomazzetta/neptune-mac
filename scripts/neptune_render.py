#!/usr/bin/env python3
"""neptune_render.py — turn Neptune's scored records into HTML, JSON or an AI brief.

neptune.sh does the collection and the scoring in bash and awk, because those
must work on a stock Mac with nothing installed. This file does the richer
outputs — the HTML report, the JSON, and the AI brief — which need real
escaping and are skipped when python3 is missing. Standard library only;
Python 3.6+.

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
    """severity|category|scan|check|title|key|acked|vendor|headline|context

    The last two are the plain-words phrasing from scripts/phrases.tsv; a
    record from before they existed reads as headline = title."""
    out = []
    for line in _lines(path):
        f = line.split("|")
        if len(f) < 8:
            continue
        out.append({
            "severity": f[0], "category": f[1], "scan": f[2], "check": f[3],
            "title": f[4], "key": f[5], "acknowledged": f[6] == "1",
            "vendor": f[7],
            "headline": (f[8] if len(f) > 8 else "") or f[4],
            "context": f[9] if len(f) > 9 else "",
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


def _mask_ip(m):
    """Hide the address but keep what it MEANS. 127.0.0.1 versus 0.0.0.0 is
    "only this Mac" versus "anything on the network", and private versus
    public is the whole double-NAT question; a sanitized report that erases
    those has erased the finding. The numbers that identify a network go."""
    ip = m.group(0)
    o = [int(x) for x in ip.split(".")]
    if ip in ("0.0.0.0", "255.255.255.255") or o[0] == 127:
        return ip
    if o[0] == 10:
        return "10.x.x.x"
    if o[0] == 192 and o[1] == 168:
        return "192.168.x.x"
    if o[0] == 172 and 16 <= o[1] <= 31:
        return "172.16.x.x"
    if o[0] == 100 and 64 <= o[1] <= 127:
        return "100.64.x.x (carrier NAT)"
    if o[0] == 169 and o[1] == 254:
        return "169.254.x.x"
    return "x.x.x.x"


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
        # /Users/Shared is a fixed system folder, not anyone's name.
        text = re.sub(r"/Users/(?!Shared\b)[^/\s\"']+", "/Users/exampleuser", text, flags=re.I)
        text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", _mask_ip, text)
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
    (("baseline-gone",), r"baseline item\(s\) are gone",
     "Things that were in the last known-good snapshot are no longer there: software "
     "you removed, or an app whose listener only exists while it is running.",
     "Nothing to do if you uninstalled something or closed an app. It costs no points. "
     "Accept the new state once you recognize the list in the text report.",
     lambda t: [("./sentry.sh --rebaseline", "neptune",
                 "Records what is there now as the new known-good snapshot.")]),
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
# The explanation ladder
#
# Every finding is explained at three depths, and the HTML report lets the
# reader pick one (Simple / Detailed / Technical):
#   In short       SHORT below — one plain sentence, no jargon
#   Why it matters the remediation table's `means` and `do`
#   Under the hood the evidence: check id, scan, the record as written, paths
# A fix is explained the same way: what it does in a line, then every part of
# the command (explain_command), then how to undo it (UNDO).
#
# Like the remediation table these are keyed by check id, so rewording a title
# never orphans an explanation, and tests/test_render.py asserts the coverage.
# ---------------------------------------------------------------------------
SHORT = {
    "filevault": "The startup disk isn't encrypted, so anyone holding this Mac can read its files.",
    "sip": "macOS's self-protection is off, so software with admin rights can change the system itself.",
    "gatekeeper": "macOS isn't checking where apps come from before they open.",
    "firewall": "Your Mac answers connection attempts from anything on the same network. The firewall stops that, and the apps you use keep working.",
    "auto-security-updates": "Apple's background security fixes aren't set to install on their own.",
    "auto-update-check": "This Mac has stopped checking for updates by itself.",
    "auto-login": "This Mac starts straight into your account without asking for a password.",
    "guest-account": "Anyone can sit down and use this Mac through the Guest login, no password needed.",
    "remote-access": "A way to log in to or control this Mac over the network is switched on.",
    "persistence-launchd": "Something starts automatically and isn't signed by its maker, so macOS can't confirm who built it. Usually a vendor habit, sometimes not.",
    "persistence-orphan": "A login item points at a program that's gone. Usually left behind by an uninstall.",
    "persistence-unresolved": "A login item couldn't be read, so Neptune can't say what it runs.",
    "privileged-helpers": "A helper that runs with full admin rights isn't signed by its maker.",
    "cron-user": "A scheduled job runs in the background under your account.",
    "cron-root": "A scheduled job runs in the background with admin rights.",
    "etc-crontab": "A system-wide scheduled job is set up.",
    "login-hook": "An old-style script runs every time someone logs in.",
    "startup-items": "A legacy startup item is installed, a mechanism macOS retired years ago.",
    "process-location": "A program is running from a folder where installed software doesn't normally live.",
    "process-hidden": "A running program has a hidden name or location.",
    "process-deleted": "A program is still running although its file has been deleted.",
    "process-root": "A program running with full admin rights isn't signed by its maker.",
    "listeners": "Some programs are waiting for connections from other machines.",
    "network-signing": "A program that's online isn't signed by its maker.",
    "baseline-diff": "Something appeared since your last known-good snapshot.",
    "baseline-gone": "Some things from your last snapshot are no longer there.",
    "proxy": "Your web traffic is being routed through a proxy.",
    "net-extensions": "A network extension can see or filter your traffic.",
    "config-profiles": "A configuration profile is installed. Profiles can change settings and what the Mac trusts.",
    "etc-hosts": "The hosts file redirects some web addresses.",
    "browser-extensions": "Browser extensions were found that can read the pages you visit.",
    "double-nat": "Your traffic passes through two routers. Often harmless, but it can break calls, gaming and port forwarding.",
    "cgnat": "Your internet provider shares one public address across many customers.",
    "dns": "Looking up web addresses was slow or failed.",
    "lan-latency": "Your own network is slower to answer than it should be.",
    "gateway-latency": "Your router is slower to answer than it should be.",
    "stale-apps": "Some apps haven't been opened in a long time.",
    "caches": "Apps are holding disk space in caches they can rebuild.",
    "brew-cache": "Homebrew is keeping installers for versions you've already moved past.",
    "dev-junk": "Developer build leftovers are taking disk space. They regenerate on their own.",
    "logs": "Log files have grown large, usually because one app writes too much.",
    "kexts": "Kernel extensions are loaded: old-style drivers with deep access to the system.",
    "macos-updates": "Apple has updates waiting for this Mac.",
    "macos-upgrade": "A newer major version of macOS is available. When to move is your call.",
    "brew-outdated": "Homebrew has newer versions of tools you installed.",
    "app-updates": "Some apps that update themselves are behind their latest release.",
    "mas-outdated": "App Store apps have updates waiting.",
    "brew-doctor": "Homebrew reports a problem with its own setup.",
    "scan-failed": "One of Neptune's scans stopped early, so its checks are missing from this report.",
    "scan-missing": "One of Neptune's scans didn't run, so its checks are missing from this report.",
    "scan-silent": "One of Neptune's scans finished without recording anything, so it can't count as passed.",
    "record-format": "Some scan results couldn't be read, so those checks are missing.",
}

UNKNOWN_SHORT = "Neptune couldn't finish this check, so it doesn't know either way. That's not the same as fine."

ACK_UNDO = "Delete its line from ~/.neptune/allow and it counts again."

UNDO = {
    "firewall": "System Settings > Network > Firewall, or: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off",
    "guest-account": "System Settings > Users & Groups > Guest User.",
    "auto-login": "System Settings > Users & Groups > Automatically log in as.",
    "auto-update-check": "sudo softwareupdate --schedule off",
    "auto-security-updates": "The same switch in System Settings > General > Software Update.",
    "gatekeeper": "Not recommended, but: System Settings > Privacy & Security.",
    "brew-cache": "Nothing to undo. Homebrew downloads an installer again if it ever needs one.",
    "caches": "Nothing to undo. Apps rebuild their caches as they run; the first launch can be a little slower.",
    "stale-apps": "Reinstall from the App Store or the developer. uninstall.sh prints every path it removed.",
    "macos-updates": "Apple's minor updates can't be rolled back. That's why it asks before each one.",
    "brew-outdated": "brew pin <name> holds a formula at its version from now on. Homebrew has no one-step downgrade.",
    "mas-outdated": "App Store updates can't be rolled back.",
    "baseline-diff": "Run ./sentry.sh --rebaseline again whenever you want a new snapshot.",
}
for _c in ("persistence-launchd", "privileged-helpers", "network-signing", "process-root",
           "process-hidden", "listeners", "double-nat"):
    UNDO.setdefault(_c, ACK_UNDO)

# What each program in a suggested command is, and what each flag does. A
# command the report shows has every part explained, or the test fails.
PROGRAMS = {
    "sudo": "runs just this one command with administrator rights; macOS asks for your password",
    "fdesetup": "Apple's FileVault (disk encryption) tool",
    "csrutil": "Apple's System Integrity Protection tool",
    "spctl": "Apple's Gatekeeper tool, the check that stops unidentified apps",
    "socketfilterfw": "Apple's control for the built-in application firewall",
    "defaults": "reads or writes a macOS preference file",
    "lsof": "lists open files; here, network connections",
    "codesign": "Apple's code-signing tool",
    "plutil": "Apple's property-list tool, which reads launch-item files",
    "crontab": "the table of scheduled jobs",
    "ls": "lists a folder",
    "scutil": "reads the live network configuration",
    "systemextensionsctl": "lists system extensions: network filters, drivers, security tools",
    "profiles": "lists configuration profiles (device management)",
    "cat": "prints a file",
    "traceroute": "shows each router your traffic passes through",
    "brew": "Homebrew, the package manager",
    "du": "measures how much disk something uses",
    "kextstat": "lists loaded kernel extensions",
    "softwareupdate": "Apple's software-update tool",
    "mas": "a command-line client for the Mac App Store",
    "sysadminctl": "Apple's user-account administration tool",
    "open": "opens an app, a file or a System Settings pane",
    "uninstall.sh": "Neptune's guided uninstaller",
    "clean_caches.sh": "Neptune's cache cleaner",
    "check_updates.sh": "Neptune's update checker",
    "sentry.sh": "Neptune's change-detection scan",
    "neptune.sh": "Neptune itself",
}

FLAGS = {
    ("socketfilterfw", "--setglobalstate"): "switches the firewall on or off; per-app rules you already have are kept",
    ("socketfilterfw", "--getglobalstate"): "prints whether the firewall is on",
    ("fdesetup", "status"): "prints whether FileVault is on",
    ("csrutil", "status"): "prints whether System Integrity Protection is on",
    ("spctl", "--global-enable"): "turns Gatekeeper back on",
    ("spctl", "--status"): "prints whether Gatekeeper is on",
    ("defaults", "read"): "prints the preference file",
    ("lsof", "-i"): "only network connections",
    ("lsof", "-P"): "show port numbers, not service names",
    ("lsof", "-n"): "show addresses, skip name lookups",
    ("lsof", "-sTCP:LISTEN"): "only ports waiting for incoming connections",
    ("codesign", "-dvv"): "display the signature in detail: who signed it, and how",
    ("plutil", "-p"): "print the file in readable form",
    ("crontab", "-l"): "list the jobs",
    ("ls", "-la"): "include hidden files, with owners and dates",
    ("scutil", "--proxy"): "print the proxy settings in use",
    ("scutil", "--dns"): "print the DNS servers in use",
    ("systemextensionsctl", "list"): "list them",
    ("profiles", "list"): "list installed profiles",
    ("traceroute", "-n"): "show addresses, skip name lookups",
    ("traceroute", "-m"): "stop after this many hops; the first few are your own network",
    ("brew", "cleanup"): "removes old versions and cached downloads",
    ("brew", "--prune=all"): "every cached download, not only ones older than 120 days",
    ("brew", "-n"): "dry run: list what would go, remove nothing",
    ("brew", "outdated"): "lists installed packages that have newer versions",
    ("brew", "upgrade"): "installs those newer versions",
    ("brew", "doctor"): "checks Homebrew's own setup and prints warnings",
    ("brew", "install"): "installs a package",
    ("brew", "--cask"): "the package is a Mac app rather than a command-line tool",
    ("brew", "--adopt"): "take over the copy already in /Applications instead of installing a second one",
    ("du", "-sh"): "one total per item, in readable units (K, M, G)",
    ("softwareupdate", "-l"): "list available updates; installs nothing",
    ("softwareupdate", "--schedule"): "turns automatic checking on or off",
    ("mas", "outdated"): "lists App Store apps with updates",
    ("mas", "upgrade"): "installs those updates",
    ("sysadminctl", "-guestAccount"): "turns the Guest login on or off",
    ("sysadminctl", "-autologin"): "turns automatic login on or off",
    ("open", "-a"): "open an app by its name",
    ("uninstall.sh", "--dry-run"): "list every file it would remove, then stop; nothing is deleted",
    ("clean_caches.sh", "--apply"): "after the list, lets you pick caches by number and type yes; without it, it only lists",
    ("check_updates.sh", "--upgrade"): "after checking, offers to install, asking per source; never a major macOS upgrade",
    ("sentry.sh", "--rebaseline"): "record what's there now as the new known-good snapshot",
    ("neptune.sh", "--fix"): "go through your last run's items one at a time; nothing changes without a y",
    ("neptune.sh", "--only"): "just these item numbers, in this order",
    ("neptune.sh", "--acknowledge"): "mark these items as known; they stay listed and stop costing points",
}


def _program(token):
    return os.path.basename(token)


def explain_command(command):
    """[(part, what it does)] for a suggested command, or [] when any part of
    it is not in the tables above — the test asserts that never happens for a
    command the report can show."""
    try:
        words = shlex.split(command)
    except ValueError:
        return []
    rows = []
    if words and words[0] == "sudo":
        rows.append(("sudo", PROGRAMS["sudo"]))
        words = words[1:]
    if not words or _program(words[0]) not in PROGRAMS:
        return []
    prog = _program(words[0])
    rows.append((prog, PROGRAMS[prog]))
    i = 1
    while i < len(words):
        w = words[i]
        if (prog, w) in FLAGS:
            part = w
            # A flag's value travels with it: "--setglobalstate on", "-m 4".
            while i + 1 < len(words) and (prog, words[i + 1]) not in FLAGS \
                    and not words[i + 1].startswith("-") and len(words[i + 1]) <= 12 \
                    and "/" not in words[i + 1]:
                i += 1
                part += " " + words[i]
            rows.append((part, FLAGS[(prog, w)]))
        elif w.startswith("-"):
            return []
        else:
            rows.append((w, "what it acts on"))
        i += 1
    return rows


def short_for(check, severity, means):
    """The "In short" rung: the hand-written sentence, or the first sentence of
    the longer explanation when a check has none."""
    if severity == "unknown" and check not in UNKNOWN_NATIVE:
        return UNKNOWN_SHORT
    if check in SHORT:
        return SHORT[check]
    m = re.match(r"(.+?[.!?])(\s|$)", means or "")
    return m.group(1) if m else (means or "")


# ---------------------------------------------------------------------------
# What fixing something is worth
#
# The same arithmetic as nep_compute_scores in neptune.sh, so "Do these next"
# can say what each item is worth. Two implementations of one formula is a
# risk; tests/test_render.py runs both on the fixture and requires the same
# scores, so they cannot drift apart silently.
# ---------------------------------------------------------------------------
def simulate_scores(records, drop=()):
    score = {c: 100 for c in CATEGORIES}
    seen = {}
    for i, r in enumerate(records):
        if i in drop:
            continue
        sev, cat = r["severity"], r["category"]
        score.setdefault(cat, 100)
        if sev == "pass" or r["acknowledged"] or sev == "info":
            continue
        seen[(cat, sev)] = seen.get((cat, sev), 0) + 1
        if seen[(cat, sev)] == 1:
            w = 12 if sev == "attention" else 8 if sev == "unknown" else 4
        else:
            w = 4 if sev == "attention" else 3 if sev == "unknown" else 1
        score[cat] -= w
    return {c: max(0, s) for c, s in score.items()}


CAT_LABEL = {"security": "Security", "network": "Network", "bloat": "Tidiness",
             "maintenance": "Updates"}

UPDATE_CHECKS = ("macos-updates", "brew-outdated", "mas-outdated")
KEEP_CHECKS = ("persistence-launchd", "privileged-helpers", "network-signing", "process-root",
               "process-hidden", "listeners")


def next_steps(records, findings, limit=6):
    """Rows for "Do these next": findings that share one action are one row
    (a vendor's helpers, the update run), ranked by what doing it is worth."""
    open_items = [f for f in findings if "n" in f and not f["acknowledged"]
                  and f["severity"] in ("attention", "unknown", "notice")]
    groups, order = {}, []
    for f in open_items:
        if f["severity"] == "unknown":
            gid, label, how = "u:%d" % f["n"], "Re-check: " + f["headline"], "run again"
        elif f.get("vendor") and f["check"] in KEEP_CHECKS:
            v = f["vendor"]["name"]
            gid, label, how = "v:" + v, "Keep or remove %s's background items" % v, "your call"
        elif f["check"] in UPDATE_CHECKS:
            gid, label, how = "updates", "Install the waiting updates", "asks first"
        else:
            gid, label, how = "f:%d" % f["n"], f["headline"], "1 step"
        if gid not in groups:
            groups[gid] = {"label": label, "how": how, "numbers": [], "drop": set(),
                           "severity": f["severity"]}
            order.append(gid)
        groups[gid]["numbers"].append(f["n"])
        groups[gid]["drop"].add(f["_i"])
    base = simulate_scores(records)
    rank = {"attention": 0, "notice": 1, "unknown": 2}
    rows = []
    for gid in order:
        g = groups[gid]
        after = simulate_scores(records, g["drop"])
        gains = [(CAT_LABEL.get(c, c), after[c] - base.get(c, 100))
                 for c in after if after[c] - base.get(c, 100) > 0]
        g["gains"] = gains
        g["worth"] = sum(n for _c, n in gains)
        if len(g["numbers"]) > 1 and gid.startswith("v:"):
            g["how"] = "%d items, your call" % len(g["numbers"])
        rows.append(g)
    rows.sort(key=lambda g: (-g["worth"], rank.get(g["severity"], 3), g["numbers"][0]))
    return rows[:limit]


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
    for i, r in enumerate(records):
        item = {
            "severity": r["severity"], "category": r["category"], "scan": r["scan"],
            "check": r["check"], "title": clean(r["title"]),
            "headline": clean(r["headline"]), "context": clean(r["context"]),
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
        item["_i"] = i          # position in records: for "what is fixing it worth"
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
        # Underscored keys are for rendering only and never reach the JSON.
        "_records": records,
        "_brief_name": getattr(args, "brief_name", ""),
        "_json_name": getattr(args, "json_name", ""),
    }


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------
def public(report):
    """The report without its render-only keys: _records holds the raw,
    unsanitized titles and must never be written out."""
    out = {k: v for k, v in report.items() if not k.startswith("_")}
    out["findings"] = [{k: v for k, v in f.items() if not k.startswith("_")}
                       for f in report["findings"]]
    return out


def render_json(report):
    return json.dumps(public(report), indent=2, ensure_ascii=False) + "\n"


def plural(n, one, many):
    return "%d %s" % (n, one if n == 1 else many)


# ---------------------------------------------------------------------------
# Recommended commands
#
# A short, curated playbook for THIS run: only the commands that apply to what
# was found, each with what it does, what kind of change it is, every part of
# it explained, and how to undo it. No command appears here that is not also
# in the remediation table's rules: one command, no pipes, a known kind.
# ---------------------------------------------------------------------------
PANE_LOGIN = "x-apple.systempreferences:com.apple.LoginItems-Settings.extension"
PERSIST_CHECKS = KEEP_CHECKS + ("persistence-orphan", "persistence-unresolved", "process-location",
                                "process-deleted")


def playbook(report):
    open_f = [f for f in report["findings"] if not f["acknowledged"] and f["severity"] != "info"]
    checks = {f["check"] for f in open_f}
    out = []

    def add(title, command, kind, short, detail, undo=""):
        out.append({"title": title, "command": command, "kind": kind, "short": short,
                    "detail": detail, "undo": undo})

    if any("n" in f for f in open_f):
        add("Fix things one at a time", "./neptune.sh --fix", "neptune",
            "Goes through every numbered item: shows the fix and its exact command, then waits "
            "for y, n or q. Nothing changes without a y.",
            "Settings are changed with Apple's own documented command; removals are handed to "
            "Neptune's confirmed scripts, which show everything first. Each applied fix is logged "
            "in ~/.neptune/fix-log.tsv, and at the end it offers to scan again so the next "
            "report shows before and after. Add --only 3,7 to queue just those numbers, in "
            "that order.")
    if checks & set(UPDATE_CHECKS + ("app-updates",)):
        add("Install updates", "./check_updates.sh --upgrade", "software",
            "Checks macOS, Homebrew and the App Store, then asks before installing from each one. "
            "Never starts a major macOS upgrade.",
            "Apple minor updates may need a restart; it says so before asking. Apps that "
            "update themselves are listed with their latest version so you can update them "
            "from their own menu.",
            UNDO["macos-updates"])
    if "brew-cache" in checks:
        add("Clear Homebrew's old downloads", "brew cleanup --prune=all", "software",
            "Deletes installers and old versions Homebrew no longer needs. Installed software "
            "is untouched.",
            "Add -n first to see the list without removing anything.", UNDO["brew-cache"])
    if "caches" in checks:
        add("Clear caches you choose", "./clean_caches.sh --apply", "neptune",
            "Lists the biggest caches in your Library. You pick by number and type yes; "
            "nothing else is touched.",
            "Only folders inside your own ~/Library/Caches, never as root. Apps rebuild what "
            "they need.", UNDO["caches"])
    apps = [app_in(f["title"]) for f in open_f
            if f["check"] in PERSIST_CHECKS + ("stale-apps",) and app_in(f["title"])]
    if apps or "stale-apps" in checks:
        add("Remove an app completely", "./uninstall.sh %s --dry-run" % shlex.quote(apps[0] if apps
                                                                               else "App Name"),
            "neptune",
            "Lists every file an app left across the system, then stops. Run it again without "
            "--dry-run to remove them; it asks before deleting anything.",
            "Finds the app's support files, launch items, helpers and caches by whole-word name "
            "match, so a search for Mail never touches MailMate.", UNDO["stale-apps"])
    if checks & set(PERSIST_CHECKS):
        add("Stop something starting at login", "open " + PANE_LOGIN, "look",
            "Opens Login Items & Extensions. Switch an item off under Allow in the Background "
            "to stop it launching, without uninstalling anything.",
            "This is the reversible middle ground between keeping and removing: the software "
            "stays installed and simply stops starting by itself.",
            "Switch it back on in the same place.")
        add("Look at a running program", "open -a 'Activity Monitor'", "look",
            "To stop a program, quit it normally: Cmd-Q, or Quit in Activity Monitor. Neptune "
            "never force-kills anything.",
            "A process that comes straight back is being launched by something, usually a "
            "login item. Find and switch off that first; killing the process only resets the "
            "clock.")
    if checks & {"listeners", "remote-access", "network-signing"}:
        add("See what's listening", "sudo lsof -i -P -n -sTCP:LISTEN", "look",
            "Lists every program waiting for incoming connections, with its port. Reads only.",
            "Ports on 127.0.0.1 are only reachable from this Mac. Ports on * or 0.0.0.0 are "
            "reachable from your network, which is what the firewall is for.")
    keepable = [f["n"] for f in open_f if "n" in f and f["check"] in KEEP_CHECKS]
    if keepable:
        add("Keep something you recognize", "./neptune.sh --acknowledge %d" % keepable[0], "neptune",
            "Marks an item as known on this Mac. It stays in the report and stops costing points.",
            "Use it for software you chose (audio drivers, licence managers, Docker). It is a "
            "statement about your Mac, so Neptune never does it for you.", ACK_UNDO)
    add("Measure again", "./neptune.sh", "look",
        "Runs the scan again and compares it with this report.",
        "Every run is kept in ~/.neptune/history.tsv, so the scores show what moved.")
    return out


def ai_reasons(report):
    open_f = [f for f in report["findings"] if not f["acknowledged"]]
    bg = sum(1 for f in open_f if f["check"] in PERSIST_CHECKS)
    unk = sum(1 for f in open_f if f["severity"] == "unknown")
    old = sum(1 for f in open_f if f["check"] in UPDATE_CHECKS + ("app-updates", "stale-apps"))
    out = []
    if bg:
        out.append(plural(bg, "background item Neptune can't vouch for",
                          "background items Neptune can't vouch for"))
    if unk:
        out.append(plural(unk, "check that couldn't finish", "checks that couldn't finish"))
    if old:
        out.append(plural(old, "finding about old or unused software",
                          "findings about old or unused software"))
    return out


# ---------------------------------------------------------------------------
# HTML
#
# No JavaScript, no external stylesheet, no webfont, no image request — the
# file makes no network connections when opened, which is a claim a security
# report should be able to make about itself. Collapsible sections are
# <details> elements and the reading-level switch is three radio inputs and
# CSS, so none of it needs script. CI asserts all of that.
# ---------------------------------------------------------------------------
CSS = """
:root{--bg:#f7f6f3;--card:#fff;--ink:#1d1d1f;--muted:#6e6e73;--faint:#8e8e93;--line:#e7e5e0;
--accent:#1f5d7a;--good:#2f7d4f;--warn:#a86500;--bad:#b3261e;--unk:#6b5ca5;--code:#f2f1ee;
--shadow:0 1px 2px rgba(0,0,0,.04),0 4px 16px rgba(0,0,0,.04)}
@media (prefers-color-scheme:dark){:root{--bg:#141416;--card:#1c1c1f;--ink:#f2f2f4;--muted:#a1a1a6;
--faint:#8a8a90;--line:#2c2c30;--accent:#7fb7d4;--good:#6fcf97;--warn:#f2b35b;--bad:#ff8a80;
--unk:#b3a7f0;--code:#232327;--shadow:none}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.55 -apple-system,BlinkMacSystemFont,"SF Pro Text","Helvetica Neue",Arial,sans-serif}
.wrap{max-width:880px;margin:0 auto;padding:40px 20px 80px}
h1,h2,h3,h4{font-weight:600;letter-spacing:-.01em;margin:0}
code,pre{font:13px/1.5 ui-monospace,"SF Mono",Menlo,monospace}
.muted{color:var(--muted)}.faint{color:var(--faint)}
.lvl{position:absolute;opacity:0;pointer-events:none}
.switch{display:inline-flex;background:var(--card);border:1px solid var(--line);border-radius:999px;padding:3px}
.switch label{padding:5px 14px;border-radius:999px;cursor:pointer;color:var(--muted);font-size:13px}
#lv1:checked~.wrap .switch label[for=lv1],#lv2:checked~.wrap .switch label[for=lv2],
#lv3:checked~.wrap .switch label[for=lv3]{background:var(--ink);color:var(--bg)}
#lv1:focus-visible~.wrap .switch label[for=lv1],#lv2:focus-visible~.wrap .switch label[for=lv2],
#lv3:focus-visible~.wrap .switch label[for=lv3]{outline:2px solid var(--accent);outline-offset:2px}
.r2,.r3{display:none}
#lv2:checked~.wrap .r2,#lv3:checked~.wrap .r2,#lv3:checked~.wrap .r3{display:block}
#lv2:checked~.wrap span.r2,#lv3:checked~.wrap span.r2,#lv3:checked~.wrap span.r3{display:inline}
#lv2:checked~.wrap .r1only,#lv3:checked~.wrap .r1only{display:none}
.top{display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap;margin-bottom:28px}
.brand{font-weight:600;letter-spacing:.02em}.meta{color:var(--muted);font-size:13px}
.hero{background:var(--card);border-radius:18px;padding:28px;box-shadow:var(--shadow);border:1px solid var(--line)}
.verdict{font-size:26px;font-weight:600;letter-spacing:-.02em;margin-bottom:6px}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:10px;vertical-align:middle}
.dot.good{background:var(--good)}.dot.warn{background:var(--warn)}.dot.bad{background:var(--bad)}
.synopsis{color:var(--muted);max-width:660px;margin:0 0 22px}
.integrity{border:1px solid var(--bad);color:var(--bad);border-radius:12px;padding:12px 16px;margin:0 0 20px}
.scores{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}
@media (max-width:640px){.scores{grid-template-columns:repeat(2,1fr)}}
.score .n{font-size:30px;font-weight:600;letter-spacing:-.02em}
.score .n small{font-size:13px;color:var(--faint);font-weight:400}
.score .lab{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}
.bar{display:block;height:5px;background:var(--line);border-radius:3px;margin:6px 0 4px;overflow:hidden}
.bar i{display:block;height:100%;border-radius:3px}
.b0{background:var(--bad)}.b1{background:var(--warn)}.b2{background:var(--good)}
.delta{font-size:12px;color:var(--faint)}.delta.up{color:var(--good)}.delta.down{color:var(--bad)}
.tally{display:flex;gap:18px;flex-wrap:wrap;margin-top:20px;padding-top:16px;border-top:1px solid var(--line);font-size:13px;color:var(--muted)}
.tally b{color:var(--ink);font-weight:600}
section{margin-top:40px}
section>h2{font-size:18px;margin-bottom:4px}
section>p.sub,p.sub{color:var(--muted);margin:0 0 16px;font-size:14px}
h3.grp{font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin:22px 0 10px}
.chips{display:flex;flex-wrap:wrap;gap:8px}
.chip{background:var(--card);border:1px solid var(--line);border-radius:999px;padding:6px 12px;font-size:13px}
.chip b{font-weight:700;margin-right:4px}
.chip.ok b{color:var(--good)}.chip.bad b{color:var(--bad)}.chip.warn b{color:var(--warn)}
.chip.unk b{color:var(--unk)}.chip.muted{color:var(--muted)}
.chipnote{font-size:13px;color:var(--muted);margin:10px 0 0}
.panel{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:6px 20px;box-shadow:var(--shadow)}
.next ol{margin:0;padding:0;list-style:none}
.next ol{counter-reset:step}
.next li{counter-increment:step;display:grid;grid-template-columns:22px 1fr auto 130px;gap:12px;align-items:baseline;padding:12px 0;border-bottom:1px solid var(--line)}
.next li::before{content:counter(step);color:var(--faint);font-weight:600}
.next li:last-child{border-bottom:0}
.next .nums{display:block;color:var(--faint);font-size:12px;font-variant-numeric:tabular-nums}
@media (max-width:640px){.next li{grid-template-columns:22px 1fr}.next .how,.next .gain{grid-column:2;text-align:left}}
.gain{font-size:12px;color:var(--good);white-space:nowrap;text-align:right}
.gain.none{color:var(--faint)}
.queue{margin:12px 0 0;font-size:14px;color:var(--muted)}
.cmd{display:flex;justify-content:space-between;align-items:center;gap:12px;background:var(--code);border-radius:10px;padding:10px 14px;margin:8px 0}
.cmd code{overflow-wrap:anywhere;min-width:0}
.kind{font-size:11px;text-transform:uppercase;letter-spacing:.06em;padding:2px 8px;border-radius:999px;white-space:nowrap}
.k-look{background:rgba(47,125,79,.12);color:var(--good)}
.k-setting{background:rgba(178,107,0,.12);color:var(--warn)}
.k-software{background:rgba(179,38,30,.10);color:var(--bad)}
.k-neptune{background:rgba(31,93,122,.12);color:var(--accent)}
details.f{background:var(--card);border:1px solid var(--line);border-radius:14px;margin-bottom:10px;box-shadow:var(--shadow)}
.plays{padding:0}
details.play{border-bottom:1px solid var(--line)}details.play:last-child{border-bottom:0}
details>summary{list-style:none;cursor:pointer}
details>summary::-webkit-details-marker{display:none}
details.f>summary{padding:16px 20px;display:grid;grid-template-columns:12px 1fr auto;gap:14px;align-items:baseline}
details.play>summary{padding:14px 20px;display:grid;grid-template-columns:1fr auto;gap:12px;align-items:baseline}
details.play>summary code{overflow-wrap:anywhere}
details>summary:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:14px}
.sev{width:10px;height:10px;border-radius:50%;display:inline-block}
.sev.attention{background:var(--bad)}.sev.notice{background:var(--warn)}.sev.unknown{background:var(--unk)}
.ttl{font-weight:600}
.ctx{display:block;font-weight:400;color:var(--muted);font-size:14px;margin-top:2px}
.num{color:var(--faint);font-size:13px;font-variant-numeric:tabular-nums}
.tag{display:inline-block;font-size:11px;letter-spacing:.04em;text-transform:uppercase;color:var(--muted);border:1px solid var(--line);border-radius:6px;padding:1px 6px;margin-left:8px;vertical-align:2px;font-weight:400}
.body{padding:0 20px 20px 46px}
details.play .body{padding:0 20px 18px}
.rung{margin-top:14px}
.rung h4{margin:0 0 4px;font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}
.rung p{margin:0 0 6px}
dl.evidence{background:var(--code);border-radius:10px;padding:12px 14px;margin:6px 0 0;overflow-x:auto}
dl.evidence dt{color:var(--muted);font-size:12px}
dl.evidence dd{margin:0 0 8px;font:13px/1.5 ui-monospace,"SF Mono",Menlo,monospace;word-break:break-all}
.fix{border-top:1px solid var(--line);margin-top:18px;padding-top:6px}
.eff{margin:0 0 8px;color:var(--muted);font-size:14px}
table.flags{width:100%;border-collapse:collapse;font-size:13px;margin:4px 0 10px}
table.flags td{padding:6px 8px;border-top:1px solid var(--line);vertical-align:top}
table.flags td:first-child{font-family:ui-monospace,"SF Mono",Menlo,monospace;width:40%;overflow-wrap:anywhere}
.undo{font-size:13px;color:var(--muted);margin:8px 0 0}.undo b{color:var(--ink)}
.vnote{background:var(--code);border-left:3px solid var(--accent);padding:10px 12px;border-radius:0 8px 8px 0;margin:12px 0 0;font-size:14px}
.box{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:20px;box-shadow:var(--shadow)}
.box p{margin:0 0 10px}.box ol{margin:8px 0 0;padding-left:20px}.box li{margin:0 0 8px}
details.quiet{border-top:1px solid var(--line)}
details.quiet>summary{color:var(--muted);padding:12px 0}
details.quiet>summary::before{content:"+ ";color:var(--faint)}
details.quiet[open]>summary::before{content:"- "}
.passlist{columns:2;font-size:13px;color:var(--muted);padding-left:18px;margin:0 0 14px}
@media (max-width:640px){.passlist{columns:1}}
.passlist li{break-inside:avoid;margin:0 0 4px}
footer{margin-top:48px;font-size:12px;color:var(--faint);line-height:1.7}
@media print{body{background:#fff}.switch{display:none}.r2,.r3{display:block!important}
details.f,details.play{break-inside:avoid;box-shadow:none}}
"""

GROUPS = (
    ("attention", "Look at these"),
    ("unknown", "Couldn't check"),
    ("notice", "Small things"),
)

CHIP = {"pass": ("ok", "&#10003;"), "fail": ("bad", "!"), "warn": ("warn", "!"),
        "unknown": ("unk", "?"), "not-checked": ("muted", "&ndash;"), "acknowledged": ("muted", "&#10003;")}

# Short chip labels and the phrase the synopsis uses when the control passed.
POSTURE_WORDS = {
    "filevault": ("Disk encryption", "your disk is encrypted"),
    "sip": ("System Integrity Protection", "System Integrity Protection is on"),
    "gatekeeper": ("Gatekeeper", "Gatekeeper is checking apps"),
    "firewall": ("Firewall", "the firewall is on"),
    "auto-security-updates": ("Security updates", "security updates install themselves"),
    "auto-login": ("Auto-login off", ""),
    "guest-account": ("Guest account off", ""),
    "remote-access": ("No remote access", ""),
    "proxy": ("No traffic interception", "nothing is intercepting your traffic"),
    "config-profiles": ("No unexpected profiles", ""),
}

PLAIN_STATE = {"pass": "checked and fine", "fail": "needs a look", "warn": "worth a look",
               "unknown": "couldn't check", "not-checked": "no result this run",
               "acknowledged": "kept on purpose"}

LEAD_WORDS = ("The", "A", "An", "Your", "Some", "Two", "One", "No", "This", "Apple's")


def _lower_lead(text):
    first = text.split(" ", 1)[0]
    return text[0].lower() + text[1:] if first in LEAD_WORDS else text


def synopsis(report):
    """Two or three plain sentences: what is solid, then what is left."""
    good = [POSTURE_WORDS[p["check"]][1] for p in report["posture"]
            if p["state"] == "pass" and POSTURE_WORDS.get(p["check"], ("", ""))[1]]
    open_f = sorted([f for f in report["findings"] if not f["acknowledged"]],
                    key=lambda f: f.get("n", 10 ** 6))
    att = [f for f in open_f if f["severity"] == "attention"]
    unk = [f for f in open_f if f["severity"] == "unknown"]
    small = [f for f in open_f if f["severity"] == "notice"]
    parts = []
    if not report["integrity"]["ok"]:
        parts.append("Some results were lost on the way to this report, so it can't vouch for "
                     "the parts it didn't see. Run it again before relying on it.")
    if good:
        lead = good[:4]
        said = lead[0] if len(lead) == 1 else ", ".join(lead[:-1]) + " and " + lead[-1]
        parts.append(("The fundamentals are solid: " if len(good) >= 3 else "On the plus side, ")
                     + said + ".")
    if att:
        heads = [_lower_lead(f["headline"]).rstrip(".") for f in att[:3]]
        more = len(att) - len(heads)
        said = heads[0] if len(heads) == 1 else ", ".join(heads[:-1]) + " and " + heads[-1]
        parts.append("What needs you: %s%s." % (said, (", plus %d more" % more) if more > 0 else ""))
    elif small:
        parts.append("Nothing urgent. %s small %s to tidy when you have a minute."
                     % (len(small), "thing" if len(small) == 1 else "things"))
    elif not unk:
        parts.append("Nothing needs you.")
    if unk:
        parts.append("%s couldn't run, so %s counted as fine."
                     % (plural(len(unk), "check", "checks"), "it isn't" if len(unk) == 1 else "they aren't"))
    return " ".join(parts)


def _cmd_html(e, command, kind, effect="", flags=True):
    out = ["<div class=\"cmd\"><code>%s</code><span class=\"kind k-%s\">%s</span></div>"
           % (e(command), kind, e(KINDS[kind]))]
    if effect:
        out.append("<p class=\"eff\">%s</p>" % e(effect))
    rows = explain_command(command) if flags else []
    if rows:
        out.append("<table class=\"flags r3\">" + "".join(
            "<tr><td>%s</td><td>%s</td></tr>" % (e(a), e(b)) for a, b in rows) + "</table>")
    return "".join(out)


def render_html(report):
    e = html.escape
    meta = report["neptune"]
    counts = report["counts"]
    scores = report["scores"]
    prev = report["previous_run"]
    findings = report["findings"]
    W = []
    add = W.append

    vclass = {"needs_attention": "bad", "incomplete": "warn",
              "healthy_minor": "good", "healthy": "good"}.get(report["verdict"], "warn")
    steps = next_steps(report["_records"], findings)

    add("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
        "<title>Neptune &mdash; " + e(meta["host"] or "Mac") + "</title>\n"
        "<style>" + CSS + "</style></head><body>")
    add("<input type=\"radio\" name=\"lvl\" id=\"lv1\" class=\"lvl\" checked>"
        "<input type=\"radio\" name=\"lvl\" id=\"lv2\" class=\"lvl\">"
        "<input type=\"radio\" name=\"lvl\" id=\"lv3\" class=\"lvl\"><div class=\"wrap\">")

    # Header
    sub = [e(meta["host"] or "This Mac")]
    if meta["macos"]:
        sub.append("macOS " + e(meta["macos"]))
    sub.append(e(datetime.datetime.now().strftime("%d %b %Y, %H:%M")))
    if meta["replay_of"]:
        sub.append("replayed from " + e(meta["replay_of"]))
    add("<div class=\"top\"><div><div class=\"brand\">Neptune</div><div class=\"meta\">%s</div></div>"
        "<div class=\"switch\" role=\"group\" aria-label=\"How much detail\">"
        "<label for=\"lv1\">Simple</label><label for=\"lv2\">Detailed</label>"
        "<label for=\"lv3\">Technical</label></div></div>" % " &middot; ".join(sub))

    # 1. First view
    if not report["integrity"]["ok"]:
        add("<div class=\"integrity\"><strong>This report is incomplete.</strong> %s, so nothing "
            "here proves the Mac is clean. Run Neptune again.</div>"
            % e((report["integrity"]["problem"] or "Results were lost").capitalize()))
    add("<div class=\"hero\"><div class=\"verdict\"><span class=\"dot %s\"></span>%s</div>"
        "<p class=\"synopsis\">%s</p><div class=\"scores\">"
        % (vclass, e((report["verdict_text"] or report["verdict"]).rstrip(".")), e(synopsis(report))))
    for cat in CATEGORIES:
        n = scores.get(cat, 100)
        if prev and cat in prev["scores"]:
            d = n - prev["scores"][cat]
            delta = ('<span class="delta">no change</span>' if d == 0 else
                     '<span class="delta %s">%+d since last run</span>' % ("up" if d > 0 else "down", d))
        else:
            delta = '<span class="delta">first measured</span>'
        add("<div class=\"score\"><div class=\"lab\">%s</div><div class=\"n\">%d<small>/100</small></div>"
            "<span class=\"bar\"><i class=\"b%d\" style=\"width:%d%%\"></i></span>%s</div>"
            % (e(CAT_LABEL.get(cat, cat)), n, 0 if n < 50 else 1 if n < 80 else 2, n, delta))
    exit_code = {"needs_attention": 1, "incomplete": 2}.get(report["verdict"], 0)
    add("</div><div class=\"tally\"><span><b>%d</b> to look at</span><span><b>%d</b> small</span>"
        "<span><b>%d</b> couldn&#x27;t check</span><span><b>%d</b> passed</span>"
        "<span><b>%d</b> kept on purpose</span>"
        "<span class=\"r3\">integrity %s &middot; exit code %d</span></div></div>"
        % (counts.get("attention", 0), counts.get("notice", 0), counts.get("unknown", 0),
           counts.get("pass", 0), counts.get("acknowledged", 0),
           "ok" if report["integrity"]["ok"] else "FAILED", exit_code))
    if prev:
        add("<p class=\"sub r2\" style=\"margin-top:10px\">Compared with the run on %s &middot; "
            "%s on record.</p>" % (e(prev["date"]), plural(report["runs_on_record"], "earlier run",
                                                             "earlier runs")))

    # 2. Protection at a glance
    add("<section><h2>Protection at a glance</h2><p class=\"sub\">The ten controls a security "
        "reviewer asks about first. Each state comes from a check that ran, not from the absence "
        "of a complaint.</p><div class=\"chips\">")
    for p in report["posture"]:
        cls, mark = CHIP[p["state"]]
        label = POSTURE_WORDS.get(p["check"], (p["label"], ""))[0]
        add("<span class=\"chip %s\" title=\"%s\"><b>%s</b>%s<span class=\"r2 faint\"> &middot; %s</span></span>"
            % (cls, e(p["detail"] or PLAIN_STATE[p["state"]]), mark, e(label), e(PLAIN_STATE[p["state"]])))
    add("</div>")
    unchecked = sum(1 for p in report["posture"] if p["state"] == "not-checked")
    if unchecked:
        add("<p class=\"chipnote\">%s recorded no result on this run &mdash; %s</p>"
            % (plural(unchecked, "control", "controls"),
               "the run this was replayed from didn't record them." if meta["replay_of"]
               else "a scan didn't reach it, which is a fault in the run, not a pass."))
    add("</section>")

    # 3. Do these next
    if steps:
        add("<section><h2>Do these next</h2><p class=\"sub\">Ordered by what they're worth. "
            "Nothing changes without your yes.</p><div class=\"panel next\"><ol>")
        for s in steps:
            nums = ", ".join("#%d" % n for n in s["numbers"][:4]) + ("&hellip;" if len(s["numbers"]) > 4 else "")
            gain = (" &middot; ".join("&asymp; %s +%d" % (e(c), g) for c, g in s["gains"])
                    if s["gains"] else "")
            add("<li><span>%s<span class=\"nums\">%s</span></span><span class=\"how faint\">%s</span>"
                "<span class=\"gain%s\">%s</span></li>"
                % (e(s["label"]), nums, e(s["how"]), "" if gain else " none",
                   gain or "keeps the report honest"))
        queue = ",".join(str(n) for s in steps for n in s["numbers"])
        add("</ol></div><p class=\"queue\">Queue them, in this order:</p>")
        add(_cmd_html(e, "./neptune.sh --fix --only " + queue, "neptune",
                      "Like queuing tracks: Neptune plays these items one at a time and waits for "
                      "your y on each. Change the numbers to build your own queue; every item below "
                      "shows its number."))
        add("</section>")

    # 4. Recommended commands
    plays = playbook(report)
    add("<section><h2>Recommended commands</h2><p class=\"sub\">The handful of commands that "
        "apply to this Mac right now. Open one to see what it does; switch to Technical for "
        "every part of it. Run them from the Neptune <code>scripts</code> folder.</p>"
        "<div class=\"panel plays\">")
    for pl in plays:
        add("<details class=\"play\"><summary><span><span class=\"ttl\">%s</span>"
            "<span class=\"ctx\"><code>%s</code></span></span><span class=\"kind k-%s\">%s</span>"
            "</summary><div class=\"body\"><p>%s</p><p class=\"r2 muted\">%s</p>%s%s</div></details>"
            % (e(pl["title"]), e(pl["command"]), pl["kind"], e(KINDS[pl["kind"]]), e(pl["short"]),
               e(pl["detail"]), "<div class=\"r3\">" + _cmd_html(e, pl["command"], pl["kind"]) + "</div>",
               ("<p class=\"undo\"><b>Undo:</b> %s</p>" % e(pl["undo"])) if pl["undo"] else ""))
    add("</div></section>")

    # 5. The details, with the explanation ladder
    open_f = [f for f in findings if not f["acknowledged"] and f["severity"] in ("attention", "unknown", "notice")]
    if open_f:
        add("<section><h2>The details</h2>"
            "<p class=\"sub r1only\">Open any item. Switch to <b>Detailed</b> or <b>Technical</b> "
            "above for more of the why and how.</p>"
            "<p class=\"sub r2\">Each item explains itself in plain terms first; the evidence "
            "follows for anyone who wants to verify it.</p>")
        opened = 0
        for sev, heading in GROUPS:
            group = sorted([f for f in open_f if f["severity"] == sev], key=lambda f: f.get("n", 10 ** 6))
            if not group:
                continue
            add("<h3 class=\"grp\">%s</h3>" % e(heading))
            for f in group:
                is_open = sev == "attention" and opened < 3
                opened += 1 if is_open else 0
                add(_finding_html(e, f, is_open))
        add("</section>")

    # 6. Second opinion
    reasons = ai_reasons(report)
    brief = report.get("_brief_name") or "neptune_ai_brief_<date>.md"
    add("<section><h2>Get a second opinion</h2><div class=\"box\">")
    if reasons:
        add("<p><b>Worth doing on this run:</b> %s. A model can help you identify a helper by "
            "its name and path, or tell you which old app actually matters.</p>" % e("; ".join(reasons)))
    else:
        add("<p>Nothing on this run really needs one, but the brief is there if you want it.</p>")
    add("<p>Neptune wrote <code>%s</code> next to this report. It is the findings with a prompt "
        "on top, already sanitized: your computer name, username, home folder, IP and MAC "
        "addresses are replaced. Read it before you share it; it's plain text.</p><ol>"
        "<li>Open the brief and paste all of it into an AI assistant (or attach the file).</li>"
        "<li>Ask follow-ups about anything you don't recognize.</li>"
        "<li>Act through the commands in this report. Prefer <code>--dry-run</code> and "
        "<code>--fix</code>, which show you everything before they change anything.</li></ol>"
        "<p class=\"r2 muted\">The prompt asks the model not to invent shell commands. A "
        "made-up <code>sudo</code> one-liner is exactly what this tool exists to argue against: "
        "if it misreads a path, the damage is real.</p>"
        "<p class=\"r3 muted\">For tools rather than people, the same data is in <code>%s</code> "
        "(schema %d). <code>./neptune.sh --replay</code> re-scores that file without scanning.</p>"
        "</div></section>"
        % (e(brief), e(report.get("_json_name") or "neptune_findings_<date>.json"), meta["schema"]))

    # 7. Quiet sections
    add("<section>")
    acked = [f for f in findings if f["acknowledged"]]
    add("<details class=\"quiet\"><summary>Kept on purpose (%d)</summary>" % len(acked))
    if acked:
        add("<p class=\"sub\">Still found and listed every run; they just don't cost points. "
            "Delete a line from <code>~/.neptune/allow</code> to count one again.</p><ul class=\"passlist\">")
        for f in acked:
            add("<li>%s</li>" % e(f["headline"]))
        add("</ul>")
    else:
        add("<p class=\"sub\">Nothing yet. When something on the list is software you chose, "
            "<code>./neptune.sh --acknowledge N</code> keeps it here instead.</p>")
    add("</details>")
    info = [f for f in findings if f["severity"] == "info"]
    if info:
        add("<details class=\"quiet\"><summary>About this run (%d)</summary><ul class=\"passlist\">"
            % len(info))
        for f in info:
            add("<li>%s</li>" % e(f["headline"]))
        add("</ul></details>")
    passed = report["checks_passed"]
    add("<details class=\"quiet\"><summary>%s &mdash; show them</summary>"
        % plural(len(passed), "check passed", "checks passed"))
    if passed:
        add("<p class=\"sub\">A report that only lists problems proves nothing about the rest. "
            "This is the rest.</p>")
        for cat in CATEGORIES:
            mine = [p for p in passed if p["category"] == cat]
            if mine:
                add("<h3 class=\"grp\">%s</h3><ul class=\"passlist\">" % e(CAT_LABEL[cat]))
                for p in mine:
                    add("<li>%s</li>" % e(p["title"]))
                add("</ul>")
    add("</details>")
    add("<details class=\"quiet\"><summary>How the scores work</summary><p class=\"sub\">Each "
        "area starts at 100. The first problem of a kind in an area costs the most (12 for "
        "something to look at, 8 for a check that couldn't run, 4 for something small); "
        "repeats cost less, because nine unsigned helpers are usually one vendor's habit, not "
        "nine problems. A check that couldn't run costs points too: missing is not passed. "
        "Every point lost traces to an item above.</p><p class=\"sub\">A low security score "
        "is not the same as compromised. On a working Mac with pro-audio or virtualization "
        "software, most of what lands here is vendor sloppiness &mdash; worth knowing, and "
        "worth keeping on purpose rather than having a tool decide for you.</p></details>")
    add("</section>")

    add("<footer>Read-only scan &middot; nothing was changed &middot; this page runs no "
        "JavaScript and makes no network requests; you can read all of it in a text editor."
        "<br>Neptune %s &middot; report schema %d &middot; generated %s%s</footer></div></body></html>"
        % (e(meta["version"] or "?"), meta["schema"], e(meta["generated"]),
           " &middot; sanitized" if meta["sanitized"] else ""))
    return "\n".join(W) + "\n"


def _finding_html(e, f, is_open):
    a = f["advice"]
    ven = f.get("vendor")
    num = "#%d" % f["n"] if "n" in f else ""
    out = ["<details class=\"f\"%s><summary><span class=\"sev %s\"></span><span class=\"ttl\">%s%s"
           "%s</span><span class=\"num\">%s</span></summary><div class=\"body\">"
           % (" open" if is_open else "", f["severity"], e(f["headline"]),
              ("<span class=\"tag\">%s</span>" % e(ven["name"])) if ven else "",
              ("<span class=\"ctx\">%s</span>" % e(f["context"])) if f.get("context") else "", num)]
    add = out.append
    add("<div class=\"rung\"><h4>In short</h4><p>%s</p></div>"
        % e(short_for(f["check"], f["severity"], a.get("means", ""))))
    if a.get("unmapped"):
        add("<div class=\"rung r2\"><h4>Why it matters</h4><p>No stock explanation for this one yet. "
            "The text report has the scan's full output around it.</p></div>")
    else:
        add("<div class=\"rung r2\"><h4>Why it matters</h4><p>%s</p><p>%s</p></div>"
            % (e(a["means"]), e(a["do"])))
    if ven and ven.get("note"):
        add("<div class=\"vnote r2\"><strong>%s.</strong> %s It's a label, not a pass: the item "
            "still counts until you decide to keep it.</div>" % (e(ven["name"]), e(ven["note"])))
    ev = [("check", "%s &middot; %s" % (e(f["check"] or "(none)"), e(f["scan"]))),
          ("recorded as", e(f["title"]))]
    p = path_in(f["title"])
    if p:
        ev.append(("path", e(p)))
    runs = f.get("runs", 0)
    if runs:
        ev.append(("seen", "first on %s, in %s" % (e(f.get("first_seen", "?")),
                                                  plural(runs, "run", "runs"))))
    ev.append(("keep key", e(f["key"])))
    add("<div class=\"rung r3\"><h4>Under the hood</h4><dl class=\"evidence\">%s</dl></div>"
        % "".join("<dt>%s</dt><dd>%s</dd>" % (k, v) for k, v in ev))

    add("<div class=\"fix\"><div class=\"rung\"><h4>What you can run</h4></div>")
    if "n" in f:
        add(_cmd_html(e, "./neptune.sh --fix --only %d" % f["n"], "neptune",
                      "Neptune's guided fix for just this item: it shows the exact change and "
                      "waits for your y.", flags=False))
    for c in a.get("commands", []):
        add(_cmd_html(e, c["command"], c["kind"], c["effect"]))
    if "n" in f and f["check"] in KEEP_CHECKS:
        add(_cmd_html(e, "./neptune.sh --acknowledge %d" % f["n"], "neptune",
                      "If you know what this is and use it: keep it. It stays listed and stops "
                      "costing points."))
    undo = UNDO.get(f["check"])
    if undo:
        add("<p class=\"undo\"><b>Undo:</b> %s</p>" % e(undo))
    add("</div></div></details>")
    return "".join(out)


# ---------------------------------------------------------------------------
# The AI brief — the findings and a prompt in one sanitized markdown file, so
# a second opinion is a paste, not a project. Always rendered with --sanitize.
# ---------------------------------------------------------------------------
BRIEF_PROMPT = """You are a careful macOS security and maintenance advisor. Below is a report
from Neptune, a read-only audit tool, run on my Mac. Identifying details have
been replaced (example-mac, exampleuser, x.x.x.x; private ranges keep
their prefix, e.g. 192.168.x.x, and 127.0.0.1 is left as is).

Go through it in priority order. For each numbered item:
1. What it most likely is, in plain words. For background items, use the name
   and path to identify the vendor and what the component does.
2. Whether it looks like a known vendor habit (audio drivers, licence managers,
   Docker and VM helpers often run unsigned) or something worth chasing.
3. What I should do, using Neptune's own commands where they apply:
   ./neptune.sh --fix --only N, ./uninstall.sh "App Name" --dry-run,
   ./neptune.sh --acknowledge N, ./check_updates.sh --upgrade,
   or a single documented macOS command.

Rules: do not give me shell I can't look up, no pipelines, no rm, no sudo
one-liners. If you are not sure what something is, say so and tell me how to
find out, rather than guessing. "Couldn't check" items are unknown, not fine.
For out-of-date software, tell me which updates matter for security."""


def render_brief(report):
    meta = report["neptune"]
    L = []
    add = L.append
    add("# Neptune findings, for a second opinion\n")
    add("Sanitized: computer name, username, home folder, IP and MAC addresses are replaced. "
        "Read it before you share it.\n")
    add("Paste everything below the line into an AI assistant, or attach this file.\n")
    add("---\n")
    add(BRIEF_PROMPT + "\n")
    add("## The Mac\n")
    add("- macOS %s, Neptune %s" % (meta["macos"] or "?", meta["version"] or "?"))
    add("- Verdict: %s" % (report["verdict_text"] or report["verdict"]))
    add("- Scores (out of 100): " + ", ".join("%s %d" % (CAT_LABEL.get(c, c), report["scores"].get(c, 100))
                                               for c in CATEGORIES))
    if not report["integrity"]["ok"]:
        add("- WARNING: the report is incomplete (%s). Treat the list as partial."
            % (report["integrity"]["problem"] or "results were lost"))
    posture = ", ".join("%s: %s" % (p["label"], PLAIN_STATE[p["state"]]) for p in report["posture"])
    add("- Protection: " + posture + "\n")
    open_f = sorted([f for f in report["findings"] if not f["acknowledged"] and f["severity"] != "info"],
                    key=lambda f: f.get("n", 10 ** 6))
    names = {"attention": "Needs attention", "unknown": "Couldn't check", "notice": "Small things"}
    for sev in ("attention", "unknown", "notice"):
        group = [f for f in open_f if f["severity"] == sev]
        if not group:
            continue
        add("## %s (%d)\n" % (names[sev], len(group)))
        for f in group:
            add("### %s%s" % (("#%d " % f["n"]) if "n" in f else "", f["headline"]))
            add("- area: %s; check: %s; scan: %s" % (CAT_LABEL.get(f["category"], f["category"]),
                                                    f["check"] or "-", f["scan"]))
            add("- as recorded: `%s`" % f["title"].replace("`", "'"))
            if f.get("vendor"):
                add("- matches a known vendor pattern: %s" % f["vendor"]["name"])
            if f.get("runs", 0) > 1:
                add("- seen in %d runs since %s" % (f["runs"], f.get("first_seen", "?")))
            if f["advice"].get("means"):
                add("- Neptune's note: %s" % f["advice"]["means"])
            add("")
    acked = [f for f in report["findings"] if f["acknowledged"]]
    if acked:
        add("## Kept on purpose by me (%d)\n" % len(acked))
        for f in acked:
            add("- " + f["headline"])
        add("")
    add("## Passed (%d checks)\n" % len(report["checks_passed"]))
    for cat in CATEGORIES:
        mine = [p["title"] for p in report["checks_passed"] if p["category"] == cat]
        if mine:
            add("- %s: %s" % (CAT_LABEL[cat], "; ".join(mine)))
    add("")
    return "\n".join(L) + "\n"


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
    ap.add_argument("--format", choices=("json", "html", "brief"))
    ap.add_argument("--scored"); ap.add_argument("--scores"); ap.add_argument("--listing")
    ap.add_argument("--verdict-key", default="incomplete"); ap.add_argument("--verdict", default="")
    ap.add_argument("--integrity", default="1"); ap.add_argument("--integrity-why", default="")
    ap.add_argument("--quirks", default=""); ap.add_argument("--version", default="")
    ap.add_argument("--history", default=""); ap.add_argument("--seen", default="")
    ap.add_argument("--replay-source", default="")
    ap.add_argument("--brief-name", default=""); ap.add_argument("--json-name", default="")
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
    render = {"json": render_json, "html": render_html, "brief": render_brief}[args.format]
    sys.stdout.write(render(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
