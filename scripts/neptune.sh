#!/bin/bash
#
# neptune.sh — Run the full Neptune scan suite and produce ONE combined report
#
# Runs, in order:  sentry.sh  ->  redflag_scan.sh  ->  network_check.sh
#                  ->  audit_system.sh  ->  check_updates.sh (scan only)
#
# Output: a verdict and per-category health scores on screen, plus one combined
# plain-text report on the Desktop with ANSI colors stripped, ready to read or
# share. Optionally structured findings as JSON.
#
# Usage:
#   ./neptune.sh                  run the suite; print a verdict and scores
#   ./neptune.sh --json           also write structured findings as JSON
#   ./neptune.sh --json --sanitize  ...with host/user/IPs/MACs replaced, so the
#                                 file can be shared or pasted into an LLM
#                                 without handing over a map of your machine
#   ./neptune.sh --acknowledge N  mark finding N a known-good vendor quirk; it
#                                 stays listed and counted but stops deducting
#
# Note:    read-only throughout (no --upgrade, no deletions).
#          uninstall.sh and remove_mackeeper.sh are never run by this script.

set -u

BOLD=$(tput bold 2>/dev/null || true)
CYN=$(tput setaf 6 2>/dev/null || true)
GRN=$(tput setaf 2 2>/dev/null || true)
YEL=$(tput setaf 3 2>/dev/null || true)
RED=$(tput setaf 1 2>/dev/null || true)
RST=$(tput sgr0 2>/dev/null || true)

JSON_OUT=false
HTML_OUT=false
SANITIZE_OUT=false
ACK_ARG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --json)        JSON_OUT=true ;;
    --html)        HTML_OUT=true ;;
    --sanitize)    SANITIZE_OUT=true ;;
    --acknowledge) shift; ACK_ARG="${1:-}" ;;
    -h|--help)
      cat <<'USAGE'
neptune.sh — run the Neptune scan suite, then report a verdict and scores.

  ./neptune.sh                    run the suite (read-only; nothing is deleted)
  ./neptune.sh --html             also write a readable HTML report: every
                                  finding with what it means, what to do, and
                                  the command to do it. No JavaScript, no
                                  external anything — it opens offline.
  ./neptune.sh --json             also write structured findings as JSON
  ./neptune.sh --json --sanitize  ...with host, user, IPs and MACs replaced,
                                  for sharing or pasting into a model
                                  (--sanitize applies to --html too)
  ./neptune.sh --acknowledge N    mark finding N a known-good vendor quirk
  ./neptune.sh --acknowledge 2,5  several at once, resolved before any write

Acknowledged findings stay listed and stay counted — they only stop deducting
from the score. Nothing is ever silently hidden. Edit ~/.neptune/allow to undo.

Every run appends its scores to ~/.neptune/history.tsv, so the next report can
show what moved. Delete that file to forget; nothing leaves the machine either
way.

Exit codes, so this is scriptable across machines:
  0  healthy — nothing needs attention and every check ran
  1  one or more findings need attention
  2  no attention items, but some check could not run (unknown is not a pass)
A usage error exits 64. Acknowledged findings do not affect the exit code:
acknowledging is a statement about a known vendor quirk, not about severity.

Reports go to ~/Desktop. See SECURITY.md for the full footprint and how to
verify what this does before running it.
USAGE
      exit 0 ;;
    *)             echo "Unknown option: $1" >&2; exit 64 ;;
  esac
  shift
done
case "$ACK_ARG" in
  ''|*[!0-9,]*) [ -z "$ACK_ARG" ] || { echo "--acknowledge takes finding numbers, e.g. 5 or 5,6,7" >&2; exit 64; } ;;
esac
if $SANITIZE_OUT && ! $JSON_OUT && ! $HTML_OUT; then
  echo "--sanitize only applies with --json or --html" >&2; exit 64
fi

DIR="$(cd "$(dirname "$0")" && pwd)"
STAMP=$(date '+%Y-%m-%d_%H%M')
REPORT="$HOME/Desktop/neptune_full_report_${STAMP}.txt"
JSON_PATH="$HOME/Desktop/neptune_findings_${STAMP}.json"
HTML_PATH="$HOME/Desktop/neptune_report_${STAMP}.html"
NEPTUNE_HOME="$HOME/.neptune"
mkdir -p "$NEPTUNE_HOME"
# One tab-separated line per run: date, verdict, the four scores, the four
# counts. Local, plain text, readable in any editor, and deletable with one rm —
# this is a machine keeping notes for its owner, not telemetry. It exists so a
# second run can answer "did what I did help?", which is the question a findings
# list on its own cannot.
HISTORY="$NEPTUNE_HOME/history.tsv"
TMP=$(mktemp -d /tmp/neptune.XXXXXX)
trap 'rm -rf "$TMP"' EXIT

# Scans append structured records here. Exported so each child sees it; unset
# in a standalone run, where record() is a no-op.
FINDINGS="$TMP/findings.txt"
: > "$FINDINGS"
export NEPTUNE_FINDINGS="$FINDINGS"

if [ "$(id -u)" -eq 0 ]; then
  echo "Run as your normal user, not with sudo."; exit 64
fi

echo "${BOLD}Neptune full suite — $(hostname) — $(date '+%Y-%m-%d %H:%M')${RST}"
echo "Combined report will be saved to:"
echo "  $REPORT"
echo

# One sudo session up front; child scripts inherit the cached timestamp
sudo -v || exit 1
( while true; do sudo -n true 2>/dev/null; sleep 50; done ) & KA=$!
trap 'kill $KA 2>/dev/null; rm -rf "$TMP"' EXIT

# Strip ANSI escape sequences for the plain-text report
strip_ansi() { sed -E $'s/\x1b\\[[0-9;]*[a-zA-Z]//g; s/\x1b\\(B//g'; }

run_script() {
  local NAME=$1 LABEL=$2
  if [ ! -x "$DIR/$NAME" ]; then
    echo "  (skipping $NAME — not found or not executable in $DIR)"
    return
  fi
  echo "${BOLD}${CYN}>>> Running $LABEL...${RST}"
  # Run it, show live output, capture a stripped copy
  "$DIR/$NAME" 2>&1 | tee "$TMP/$NAME.raw"
  strip_ansi < "$TMP/$NAME.raw" > "$TMP/$NAME.txt"
  {
    echo
    echo "################################################################"
    echo "##  $LABEL — $(date '+%H:%M')"
    echo "################################################################"
    cat "$TMP/$NAME.txt"
  } >> "$REPORT"
  echo
}

: > "$REPORT"
{
  echo "NEPTUNE FULL REPORT"
  echo "Host:  $(hostname)"
  echo "macOS: $(sw_vers -productVersion) ($(sw_vers -buildVersion))"
  echo "Date:  $(date '+%Y-%m-%d %H:%M')"
} >> "$REPORT"

run_script "sentry.sh"        "SENTRY (change detection, process->network, staleness)"
run_script "redflag_scan.sh"  "RED-FLAG SCAN (persistence, listeners, interception)"
run_script "network_check.sh" "NETWORK CHECK (NAT, DNS, latency, connections)"
run_script "audit_system.sh"  "SYSTEM AUDIT (resources, persistence, disk)"
run_script "check_updates.sh" "UPDATE SCAN (macOS, brew, App Store, self-updaters)"

############################################################
# Score, verdict, and findings
############################################################
#
# Scans append structured records to $NEPTUNE_FINDINGS as:
#     severity|category|scan|title
# severity ∈ attention | notice | unknown | info (see each scan's record())
#   info is shown and exported but never scored: it reports something Neptune
#   did (a baseline migration, a mode it ran in), not something wrong with the
#   machine. Scoring those made a clean Mac lose 4 security points for Neptune's
#   own format upgrade.
# category ∈ security | network | bloat | maintenance
#
# Everything below renders from those records. Nothing here re-parses the
# scans' prose — that text-grepping step is what made the old digest count one
# problem seven times and every finding twice (DEVLOG Bug 8).

ALLOW="$NEPTUNE_HOME/allow"
[ -f "$ALLOW" ] || : > "$ALLOW"

# Attach a stable key to each finding and mark the acknowledged ones.
# The key is the title with digits collapsed to '#', so it survives the PIDs,
# ports and version numbers that change every run — otherwise acknowledging a
# finding once would not match it again tomorrow.
SCORED="$TMP/scored.txt"
awk -F'|' -v allowfile="$ALLOW" '
  BEGIN { while ((getline l < allowfile) > 0) if (l != "" && l !~ /^#/) allow[l] = 1 }
  NF >= 4 {
    sev = $1; cat = $2; scan = $3; title = $4
    for (i = 5; i <= NF; i++) title = title "|" $i
    key = tolower(title)
    gsub(/[0-9]+/, "#", key); gsub(/[ \t]+/, " ", key)
    sub(/^ /, "", key); sub(/ $/, "", key)
    # Truncate at a SPACE, never at byte 90. substr in awk counts bytes, and
    # these titles are full of em-dashes: cutting one of those in half leaves a
    # lone \xe2\x80 and the record is no longer valid UTF-8, which crashed
    # --json outright on the real machine (DEVLOG Bug 10). A space is ASCII, so
    # a cut there cannot land inside a character.
    if (length(key) > 90) { key = substr(key, 1, 90); sub(/[^ ]*$/, "", key); sub(/ +$/, "", key) }
    printf "%s|%s|%s|%s|%s|%s\n", sev, cat, scan, title, key, (key in allow) ? 1 : 0
  }
' "$FINDINGS" 2>/dev/null | awk -F'|' '!seen[$1 "|" $2 "|" $4]++' > "$TMP/deduped.txt"

# Attach the vendor label, if any. Computed ONCE here and carried as a seventh
# field, so the terminal listing, the HTML report and the JSON all read the same
# answer from the same record instead of each matching the catalogue themselves.
# That is the rule the whole findings model exists to enforce.
#
# This is a LABEL, never a suppression. A labelled finding is still found, still
# listed, still counted and still deducts. See the header of vendor-quirks.tsv
# for why that line is where it is.
QUIRKS="$DIR/vendor-quirks.tsv"
awk -F'\t' -v quirks="$QUIRKS" '
  BEGIN {
    n = 0
    while ((getline line < quirks) > 0) {
      if (line ~ /^#/ || line ~ /^[ \t]*$/) continue
      split(line, f, "\t")
      if (f[1] == "" || f[2] == "") continue
      n++; pat[n] = f[1]; ven[n] = f[2]
    }
    FS = "|"
  }
  {
    label = ""
    lt = tolower($0)
    for (i = 1; i <= n; i++) {
      if (index(lt, pat[i]) > 0) { label = ven[i]; break }
    }
    print $0 "|" label
  }
' "$TMP/deduped.txt" > "$SCORED"

# Per-category score: start at 100, deduct per unacknowledged finding, floor at 0.
# Every deduction traces to a finding printed below — a score whose arithmetic
# the reader cannot follow is decoration, not information.
SCORES="$TMP/scores.txt"
awk -F'|' '
  BEGIN { n = split("security network bloat maintenance", C, " ")
          for (i = 1; i <= n; i++) score[C[i]] = 100 }
  {
    sev = $1; cat = $2; acked = $6
    if (!(cat in score)) { score[cat] = 100; C[++n] = cat }
    if (acked == 1) { acks[cat]++; total_ack++; next }
    counts[sev]++
    if (sev == "info") next        # shown and exported, never deducted
    # First issue of a severity in a category costs full weight; each repeat
    # costs about a third. Nine unsigned launch items are usually one habit
    # (a vendor that ships unsigned helpers), not nine independent problems —
    # and a flat per-finding deduction floors the score at 0, which stops
    # distinguishing "several vendor quirks" from "actually compromised".
    seen[cat "|" sev]++
    if (seen[cat "|" sev] == 1)
      w = (sev == "attention") ? 12 : (sev == "unknown") ? 8 : 4
    else
      w = (sev == "attention") ?  4 : (sev == "unknown") ? 3 : 1
    score[cat] -= w
  }
  END {
    for (i = 1; i <= n; i++) {
      c = C[i]; if (score[c] < 0) score[c] = 0
      printf "score|%s|%d|%d\n", c, score[c], acks[c] + 0
    }
    printf "count|attention|%d\n", counts["attention"] + 0
    printf "count|notice|%d\n",    counts["notice"] + 0
    printf "count|unknown|%d\n",   counts["unknown"] + 0
    printf "count|info|%d\n",      counts["info"] + 0
    printf "count|acknowledged|%d\n", total_ack + 0
  }
' "$SCORED" > "$SCORES"

getcount() { awk -F'|' -v k="$1" '$1=="count" && $2==k {print $3}' "$SCORES"; }
N_ATTENTION=$(getcount attention); N_NOTICE=$(getcount notice)
N_UNKNOWN=$(getcount unknown);     N_ACK=$(getcount acknowledged)
N_INFO=$(getcount info)

# Verdict. Ordered worst-first, and "couldn't check" outranks "minor" on
# purpose: an un-run check is an unknown, not a pass.
if   [ "${N_ATTENTION:-0}" -gt 0 ]; then VERDICT="NEEDS ATTENTION"; VKEY=needs_attention; VCOL="$RED"
elif [ "${N_UNKNOWN:-0}"   -gt 0 ]; then VERDICT="HEALTHY — but some checks could not run"; VKEY=incomplete; VCOL="$YEL"
elif [ "${N_NOTICE:-0}"    -gt 0 ]; then VERDICT="HEALTHY — minor items"; VKEY=healthy_minor; VCOL="$GRN"
else                                     VERDICT="HEALTHY"; VKEY=healthy; VCOL="$GRN"
fi

render_verdict() {
  echo "================================================================"
  echo "  $VERDICT"
  echo "================================================================"
  echo
  awk -F'|' '$1=="score" {
    bar = ""
    filled = int($3 / 10)
    for (i = 0; i < 10; i++) bar = bar (i < filled ? "#" : ".")
    printf "  %-12s %3d/100  [%s]%s\n", $2, $3, bar,
           ($4 > 0 ? "  (" $4 " acknowledged)" : "")
  }' "$SCORES"
  echo
  printf '  %s attention · %s minor · %s could not run · %s acknowledged' \
    "${N_ATTENTION:-0}" "${N_NOTICE:-0}" "${N_UNKNOWN:-0}" "${N_ACK:-0}"
  [ "${N_INFO:-0}" -gt 0 ] && printf ' · %s informational' "$N_INFO"
  echo

  # ONE number sequence across all three sections. Numbering per section made
  # `--acknowledge 3` ambiguous, and the lookup indexed a different list than
  # the one on screen — so the number you typed was not the finding you read.
  NUM=0
  for SEV in attention unknown notice; do
    case "$SEV" in
      attention) HEAD="NEEDS ATTENTION" ;;
      unknown)   HEAD="COULD NOT BE CHECKED  (treat as unknown, not clean)" ;;
      notice)    HEAD="MINOR" ;;
    esac
    if awk -F'|' -v s="$SEV" '$1==s && $6==0 {found=1} END{exit !found}' "$SCORED"; then
      echo; echo "  $HEAD"
      while IFS='|' read -r _sev _cat _scan _title _key _ack _vendor; do
        NUM=$((NUM + 1))
        printf '   %2d. [%s] %s\n' "$NUM" "$_cat" "$_title"
        [ -n "${_vendor:-}" ] && printf '       known %s pattern — see the HTML report for what it is\n' "$_vendor"
      done <<EOF_F
$(awk -F'|' -v s="$SEV" '$1==s && $6==0' "$SCORED")
EOF_F
    fi
  done

  # Unnumbered on purpose: the numbers above are the argument to --acknowledge,
  # and there is nothing to acknowledge here. These are notes about the run.
  if [ "${N_INFO:-0}" -gt 0 ]; then
    echo; echo "  FOR INFORMATION — about this run, not about your machine (no score impact)"
    awk -F'|' '$1=="info" && $6==0 {printf "    · [%s] %s\n", $2, $4}' "$SCORED"
  fi

  if [ "${N_ACK:-0}" -gt 0 ]; then
    echo; echo "  ACKNOWLEDGED — known-good on this machine, still counted"
    awk -F'|' '$6==1 {printf "   · [%s] %s\n", $2, $4}' "$SCORED" | head -8
    [ "${N_ACK:-0}" -gt 8 ] && echo "   · ... and $(( N_ACK - 8 )) more"
    echo "   (edit $ALLOW to change)"
  fi

  if [ "${N_ATTENTION:-0}" -gt 0 ] || [ "${N_NOTICE:-0}" -gt 0 ]; then
    echo
    echo "  Recurring vendor quirk rather than a problem? Acknowledge it:"
    echo "      ./neptune.sh --acknowledge <n>      (number from the list above)"
  fi
  echo "================================================================"
}

# JSON. python3 ships with macOS, so no brew dependency (ROADMAP #1), and it
# handles escaping correctly — hand-rolled JSON from shell is how you emit a
# file that silently fails to parse.
########################################################################
# Structured output: JSON and HTML, from ONE renderer
########################################################################
#
# Both formats render from $SCORED — the same records the on-screen verdict
# renders from. They are generated by a single python block on purpose: the
# remediation table below is the only place in Neptune that says "here is what
# to do about X", and two copies of that would drift the way the scoring awk
# drifted from its copy in tests/unit.sh.
#
# python3 ships with macOS, so no brew dependency, and it escapes HTML and JSON
# correctly — hand-rolled escaping from shell is how you emit a file that
# silently fails to parse, or an HTML report that a path with an ampersand in it
# can rewrite.
#
# render <json|html> <sanitize 0|1>
render() {
  NEP_MODE=$1 NEP_SANITIZE=$2 NEP_HISTORY="$HISTORY" NEP_VERDICT="$VERDICT" \
  NEP_SEEN="$SEEN" NEP_QUIRKS="$QUIRKS" \
  python3 - "$SCORED" "$SCORES" "$VKEY" <<'PY'
import html, json, os, re, shlex, subprocess, sys, datetime

scored, scores, vkey = sys.argv[1], sys.argv[2], sys.argv[3]
mode     = os.environ.get("NEP_MODE", "json")
san      = os.environ.get("NEP_SANITIZE") == "1"
histfile = os.environ.get("NEP_HISTORY", "")
seenfile = os.environ.get("NEP_SEEN", "")
quirkfile = os.environ.get("NEP_QUIRKS", "")
verdict  = os.environ.get("NEP_VERDICT", "")
# A missing command must degrade to "?" rather than take the report down with
# it. This also lets the renderer be exercised on the Linux CI runner, where
# sw_vers does not exist, which is where its regression tests run.
def shell_out(*args):
    try:
        return subprocess.run(args, capture_output=True, text=True).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""

host = shell_out("hostname")
user = os.environ.get("USER", "")

def clean(t):
    if not san: return t
    if host: t = t.replace(host, "example-mac").replace(host.split(".")[0], "example-mac")
    if user: t = t.replace(user, "exampleuser")
    # Do not rely on $USER alone. A finding can name a path under a DIFFERENT
    # account — another user on the machine, or a daemon running as one — and
    # "the variable happened to match" is not a sanitiser. Any home directory in
    # a path is replaced, whoever it belongs to.
    t = re.sub(r"/Users/[^/\s\"']+", "/Users/exampleuser", t)
    t = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "0.0.0.0", t)
    t = re.sub(r"\b(?:[0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2}\b", "xx:xx:xx:xx:xx:xx", t)
    return t

# ---------------------------------------------------------------------------
# Remediation table.
#
# Each entry answers, for one shape of finding: what it means in plain words,
# what to do about it, and — only where a well-known single-purpose command
# exists — that command, labelled with what it actually does.
#
# The rules this table follows, which are the whole reason it is a table and not
# a model call:
#   * Nothing here is generated. Every command is one a person can look up in
#     `man` or Apple's own documentation, or is Neptune's own.
#   * No command is a pipeline, and none composes several operations.
#   * Anything that changes the machine is labelled and explained. Anything
#     read-only is labelled too, so "just look at it first" is the obvious path.
#   * Where there is no honest one-command answer — double NAT, high latency —
#     the entry says so instead of inventing one. docs/advisor.md makes the same
#     argument about the AI workflow: recommend `./uninstall.sh <app>`, never
#     novel shell for a human to paste unread.
#
# ACTION KINDS
#   look     reads something, changes nothing
#   setting  changes a macOS setting, reversible in System Settings
#   software installs or removes software
#   neptune  Neptune's own command
# ---------------------------------------------------------------------------
def path_in(title):
    # "X runs <BINARY> (<PLIST>)" — the binary is what has a signature to check.
    # The trailing parenthesised path is the plist that launches it, and running
    # codesign against a plist tells you nothing.
    m = re.search(r"\bruns (/.+?)(?: \(/|$)", title)
    if m: return m.group(1).strip()
    m = re.search(r"\bbinary:(/.+?)$", title)
    if m: return m.group(1).strip()
    m = re.search(r"\((/[^)]+)\)\s*$", title)
    if m: return m.group(1).strip()
    m = re.search(r"(/(?:Library|Applications|Users)/\S.*?)(?:\s+\(|$)", title)
    return m.group(1).strip() if m else None

def app_in(title):
    m = re.search(r"/Applications/([^/]+)\.app", title)
    return m.group(1) if m else None

REMEDIATION = [
 (r"^UNSIGNED persistence",
  "Something starts itself at login or boot, and macOS cannot verify who wrote it. "
  "That is how persistent malware behaves — and also how a lot of legitimate "
  "pro-audio, licensing and virtualisation software behaves, because those vendors "
  "ship helpers they never re-signed.",
  "Identify the vendor from the path. If it belongs to software you installed on "
  "purpose, acknowledge it so it stops costing you points but stays on the list. "
  "If you do not recognise it, do not delete it yet — look at it first.",
  lambda t: ([("codesign -dvv " + shlex.quote(path_in(t)), "look",
               "Prints the signature Apple can verify, or says it cannot. Changes nothing.")]
             if path_in(t) else [])
            + ([("./uninstall.sh " + shlex.quote(app_in(t)), "software",
                 "Neptune's guided removal: shows every file it found and waits for you to type a confirmation.")]
               if app_in(t) else [])),

 (r"^UNSIGNED privileged helper",
  "A background program that runs as root, which macOS cannot verify. Root means "
  "it can read and change anything on the machine. Docker and PACE/iLok both "
  "legitimately install helpers in this state.",
  "Confirm the vendor, then decide. This is the category most worth spending ten "
  "minutes on — 'probably fine, runs as root' is worth confirming rather than "
  "acknowledging away.",
  lambda t: [("codesign -dvv " + shlex.quote(path_in(t)), "look",
              "Prints the signature, or says there is none. Changes nothing.")] if path_in(t) else []),

 (r"^Listener with unverifiable signature",
  "A program is accepting network connections, and its signature cannot be "
  "verified. Check the scope: [localhost-only] means only this Mac can reach it. "
  "[ALL INTERFACES] means anything on your network can.",
  "Localhost-only listeners from software you installed are usually the normal "
  "way that software talks to itself. An unverifiable listener on all interfaces "
  "deserves an answer before you acknowledge it.",
  lambda t: [("sudo lsof -i -P -n -sTCP:LISTEN", "look",
              "Lists every listening TCP port with the process holding it. Reads only; "
              "sudo is what makes root-owned daemons visible too.")]),

 (r"^Unsigned process with network access",
  "A running program that macOS cannot verify is sending or receiving network "
  "traffic right now.",
  "Match it to software you installed. If you cannot, that is the finding worth "
  "chasing first.",
  lambda t: []),

 (r"^Application firewall is OFF",
  "macOS has a per-application firewall that controls which programs may accept "
  "incoming connections. It ships off. That is fine on a wired network you "
  "control and a bad default the moment the machine joins airport or cafe Wi-Fi.",
  "Turn it on. It asks per application, so the cost is a handful of prompts the "
  "first time you run something that listens.",
  lambda t: [("sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on", "setting",
              "Turns the application firewall on. Reversible in System Settings > Network > Firewall."),
             ("/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate", "look",
              "Reports whether it is currently on. Changes nothing.")]),

 (r"^Application firewall state",
  "Neptune asked macOS twice whether the application firewall is on — through "
  "socketfilterfw and through the older alf preference — and neither answered. "
  "So the firewall may be on or off; this run does not know.",
  "Check it by hand. An unknown is not a pass, which is why this sits under "
  "'could not be checked' rather than quietly counting as fine.",
  lambda t: [("/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate", "look",
              "Reports the firewall state directly. Changes nothing."),
             ("open /System/Library/PreferencePanes/Security.prefPane", "look",
              "Opens the Security settings pane so you can read the state in the UI.")]),

 (r"(?:SECOND PRIVATE ROUTER|Possible double NAT)",
  "There are two routers doing address translation between this Mac and the "
  "internet — usually an ISP box in router mode in front of your own. It breaks "
  "inbound connections, port forwarding and some VPN and game traffic, and it "
  "adds a hop of latency.",
  "This cannot be fixed from the Mac; it is a router setting. Check your own "
  "router's WAN address first: if it shows your public IP, the ISP box is already "
  "in passthrough and there is nothing to fix. If it shows a 192.168.x or 10.x "
  "address, double NAT is real — enable bridge or IP-passthrough mode on the ISP "
  "gateway.",
  lambda t: [("traceroute -n -m 4 1.1.1.1", "look",
              "Shows the first few hops, so you can see both routers. Changes nothing.")]),

 (r"^CGNAT hop detected",
  "Your ISP is translating addresses on their side, so you do not have a public "
  "IP of your own. Common on mobile and some fibre providers.",
  "Nothing to fix on this machine. It only matters if you need inbound "
  "connections — port forwarding, self-hosting, some peer-to-peer. Ask the ISP "
  "for a static or public IP if you do.",
  lambda t: []),

 (r"^LAN latency high|Gateway latency over",
  "Round trips to your own router are slower than a local network should be. On "
  "Wi-Fi this is usually mesh backhaul or distance from the node; on Ethernet it "
  "is unusual and worth investigating.",
  "Compare the average against the worst ping in the same line. A high worst with "
  "a low average is an intermittent link, not a slow one. There is no command "
  "that fixes this — move the machine or the mesh node, or switch to Ethernet, "
  "and re-run to compare.",
  lambda t: []),

 (r"^Outdated formulae|^Outdated casks",
  "Homebrew-managed software has updates available. Out-of-date browsers and "
  "chat clients are the most commonly exploited software on a desktop.",
  "Review the list in the full report, then upgrade. Do not adopt "
  "licence-managed pro-audio software into Homebrew — keep Waves, Arturia, iLok, "
  "Sonarworks and Elektron on their vendor updaters.",
  lambda t: [("brew outdated", "look", "Lists what would be upgraded. Changes nothing."),
             ("brew upgrade", "software", "Upgrades all Homebrew formulae and casks.")]),

 (r"could not resolve target",
  "A launch agent or daemon points at a program that is not where its "
  "configuration says it is. Usually an incomplete uninstall that left the "
  "trigger behind; occasionally something that expects to be installed later.",
  "Harmless in itself — macOS just fails to start it. Worth cleaning up so the "
  "list stays meaningful.",
  lambda t: [("launchctl list", "look", "Lists loaded jobs and their exit status. Changes nothing.")]),

 (r"^Unprivileged view",
  "This particular scan ran without root, so it only saw your own processes. "
  "Root-owned daemons were not in its view.",
  "Nothing to do. sentry.sh and redflag_scan.sh do elevate and do cover them, and "
  "both ran in this suite.",
  lambda t: []),

 (r"^Baseline format changed",
  "Neptune changed how it records the baseline, so the old one was replaced "
  "rather than compared against. A cross-format comparison would have looked like "
  "dozens of new listeners appearing at once.",
  "Nothing to do, and it costs you no points. The next run compares against the "
  "new baseline normally.",
  lambda t: []),
]

def advise(title):
    for pat, means, do, cmdf in REMEDIATION:
        if re.search(pat, title, re.I):
            cmds = [{"command": c, "kind": k, "effect": e} for c, k, e in cmdf(title)]
            return {"means": means, "do": do, "commands": cmds}
    return {"means": "", "do": "", "commands": [], "unmapped": True}

# ---------------------------------------------------------------------------
sc, ack, counts = {}, {}, {}
# errors="replace" everywhere a record is read: a corrupt byte should cost
# one garbled character in one field, never the whole report (Bug 10).
def records(path):
    return open(path, encoding="utf-8", errors="replace")

for line in records(scores):
    f = line.rstrip("\n").split("|")
    if f[0] == "score": sc[f[1]] = int(f[2]); ack[f[1]] = int(f[3])
    elif f[0] == "count": counts[f[1]] = int(f[2])

# Vendor notes, keyed by the vendor name the shell already matched. The shell
# decided WHICH vendor (one matcher, one answer, carried in the record); this
# only looks up the sentence that goes with it.
vendor_note = {}
if quirkfile and os.path.exists(quirkfile):
    for line in records(quirkfile):
        if line.startswith("#") or not line.strip(): continue
        col = line.rstrip("\n").split("\t")
        if len(col) >= 3 and col[1] not in vendor_note:
            vendor_note[col[1]] = col[2]

seen = {}
if seenfile and os.path.exists(seenfile):
    for line in records(seenfile):
        if line.startswith("#") or not line.strip(): continue
        col = line.rstrip("\n").split("\t")
        if len(col) >= 4:
            try: runs = int(col[3])
            except ValueError: continue
            seen[col[0]] = {"first_seen": col[1], "last_seen": col[2], "runs": runs}

findings = []
for line in records(scored):
    f = line.rstrip("\n").split("|")
    if len(f) < 6: continue
    title = clean(f[3])
    rec = {"severity": f[0], "category": f[1], "scan": f[2], "title": title,
           "key": f[4], "acknowledged": f[5] == "1"}
    ven = f[6] if len(f) > 6 else ""
    if ven:
        rec["vendor"] = {"name": ven, "note": vendor_note.get(ven, "")}
    hist = seen.get(f[4])
    if hist:
        rec["first_seen"] = hist["first_seen"]
        rec["runs"] = hist["runs"]
    rec["advice"] = advise(f[3])
    if san:
        for c in rec["advice"]["commands"]:
            c["command"] = clean(c["command"])
    findings.append(rec)

# Previous run, for the delta. The shell appends THIS run after rendering, so
# whatever is in the file now is history.
prev = None
runs = 0
if histfile and os.path.exists(histfile):
    rows = [l.rstrip("\n").split("\t") for l in records(histfile) if l.strip()]
    rows = [r for r in rows if len(r) >= 6 and not r[0].startswith("#")]
    runs = len(rows)
    if rows: prev = rows[-1]

generated = datetime.datetime.now().astimezone().isoformat(timespec="seconds")

if mode == "json":
    out = {
        "neptune": {"schema": 2, "generated": generated,
                    "host": clean(host) if san else host, "sanitized": san},
        "verdict": vkey,
        "scores": sc,
        "acknowledged_by_category": ack,
        "counts": counts,
        "findings": findings,
    }
    if prev:
        out["previous_run"] = {"date": prev[0], "verdict": prev[1],
                               "scores": {"security": int(prev[2]), "network": int(prev[3]),
                                          "bloat": int(prev[4]), "maintenance": int(prev[5])}}
    print(json.dumps(out, indent=2))
    sys.exit(0)

# ---------------------------------------------------------------------------
# HTML. No JavaScript, no external stylesheet, no webfont, no image request —
# the file makes no network connections when opened, which is a claim a security
# report should be able to make about itself. Collapsible sections are <details>
# elements, which need no script.
# ---------------------------------------------------------------------------
e = html.escape
VCOLOR = {"needs_attention": "bad", "incomplete": "warn",
          "healthy_minor": "good", "healthy": "good"}.get(vkey, "warn")
SEV_ORDER = [("attention", "Needs attention", "These are the ones to work through first."),
             ("unknown", "Could not be checked", "Treated as unknown, not as clean. A check that did not run is not a pass."),
             ("notice", "Minor", "Worth knowing. Not urgent."),
             ("info", "For information", "About this run, not about your machine. These cost no points.")]
KIND_LABEL = {"look": "reads only", "setting": "changes a setting",
              "software": "installs or removes software", "neptune": "Neptune command"}

def bar(n):
    filled = int(n / 10)
    return '<span class="bar"><span class="fill f%d" style="width:%d%%"></span></span>' % (
        (0 if n < 50 else 1 if n < 80 else 2), n)

def delta(cat):
    if not prev: return ""
    idx = {"security": 2, "network": 3, "bloat": 4, "maintenance": 5}[cat]
    try: d = sc.get(cat, 0) - int(prev[idx])
    except (ValueError, IndexError): return ""
    if d == 0: return '<span class="d flat">no change</span>'
    return '<span class="d %s">%+d since last run</span>' % ("up" if d > 0 else "down", d)

parts = []
W = parts.append
W('''<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Neptune report &mdash; ''' + e(clean(host) or "Mac") + '''</title>
<style>
:root{--bg:#fbfbfa;--card:#fff;--ink:#1a1a1a;--mute:#5d5d5d;--line:#e3e1dd;
--good:#2f7d४f;--warn:#a8721a;--bad:#a63232;--accent:#2d4f7c;--code:#f4f3f0}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif}
.wrap{max-width:820px;margin:0 auto;padding:32px 20px 80px}
h1{font-size:26px;margin:0 0 4px;letter-spacing:-.2px}
h2{font-size:19px;margin:40px 0 6px;letter-spacing:-.1px}
h3{font-size:15px;margin:0 0 4px}
.sub{color:var(--mute);font-size:14px;margin:0 0 28px}
.verdict{padding:18px 20px;border-radius:8px;border:1px solid var(--line);
background:var(--card);margin:0 0 28px;border-left-width:5px}
.verdict.good{border-left-color:var(--good)}
.verdict.warn{border-left-color:var(--warn)}
.verdict.bad{border-left-color:var(--bad)}
.verdict strong{font-size:20px;display:block;margin-bottom:2px}
.verdict .tally{color:var(--mute);font-size:14px}
.scores{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:0 0 8px}
.score{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px 16px}
.score .n{font-size:28px;font-weight:600;letter-spacing:-1px}
.score .n small{font-size:14px;font-weight:400;color:var(--mute);letter-spacing:0}
.score .cat{text-transform:uppercase;font-size:11px;letter-spacing:.09em;color:var(--mute)}
.bar{display:block;height:6px;background:var(--line);border-radius:3px;overflow:hidden;margin:8px 0 6px}
.fill{display:block;height:100%}
.f0{background:var(--bad)}.f1{background:var(--warn)}.f2{background:var(--good)}
.d{font-size:12px}.d.up{color:var(--good)}.d.down{color:var(--bad)}.d.flat{color:var(--mute)}
.note{color:var(--mute);font-size:14px;margin:0 0 20px}
details.f{background:var(--card);border:1px solid var(--line);border-radius:8px;
margin:0 0 8px;padding:0}
details.f>summary{padding:12px 16px;cursor:pointer;list-style:none;display:flex;gap:10px}
details.f>summary::-webkit-details-marker{display:none}
details.f>summary::before{content:"\\25B8";color:var(--mute);flex:0 0 auto}
details.f[open]>summary::before{content:"\\25BE"}
.num{color:var(--mute);flex:0 0 auto;font-variant-numeric:tabular-nums}
.vendor{display:inline-block;font-size:10px;text-transform:uppercase;letter-spacing:.08em;
padding:2px 6px;border-radius:3px;border:1px solid var(--line);color:var(--accent);
vertical-align:2px;margin-right:6px}
.streak{font-size:12px;color:var(--mute);margin:10px 0 0}
.vnote{background:var(--code);border-left:3px solid var(--accent);padding:10px 12px;
border-radius:0 5px 5px 0;margin:12px 0 0;font-size:14px}
.tag{display:inline-block;font-size:10px;text-transform:uppercase;letter-spacing:.08em;
padding:2px 6px;border-radius:3px;background:var(--code);color:var(--mute);
vertical-align:2px;margin-right:6px}
.body{padding:2px 16px 16px 40px;border-top:1px solid var(--line);margin-top:0}
.body p{margin:12px 0 0}
.body .lbl{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--mute);
margin:16px 0 2px;font-weight:600}
pre{background:var(--code);border:1px solid var(--line);border-radius:6px;
padding:10px 12px;overflow-x:auto;margin:4px 0 2px;
font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}
.eff{font-size:13px;color:var(--mute);margin:0 0 10px}
.kind{display:inline-block;font-size:10px;text-transform:uppercase;letter-spacing:.07em;
padding:1px 5px;border-radius:3px;margin-right:6px;border:1px solid var(--line)}
.kind.look{color:var(--accent)}.kind.setting{color:var(--warn)}
.kind.software{color:var(--bad)}.kind.neptune{color:var(--good)}
.box{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:18px 20px;margin:0 0 16px}
.box p:first-child{margin-top:0}
ol.steps{margin:8px 0 0;padding-left:22px}ol.steps li{margin:0 0 10px}
footer{margin-top:52px;padding-top:20px;border-top:1px solid var(--line);
color:var(--mute);font-size:13px}
@media print{body{background:#fff}details.f{break-inside:avoid}details.f>summary::before{content:""}
details.f[open]>summary::before{content:""}}
@media (prefers-color-scheme:dark){
:root{--bg:#16161a;--card:#1d1d22;--ink:#e8e6e3;--mute:#9b9892;--line:#31313a;
--good:#6bbf87;--warn:#d9a441;--bad:#e07a7a;--accent:#8ab0e0;--code:#24242b}}
</style></head><body><div class="wrap">''')

W('<h1>Neptune report</h1>')
W('<p class="sub">%s &middot; macOS %s &middot; %s</p>' % (
    e(clean(host) or "this Mac"),
    e(shell_out("sw_vers", "-productVersion") or "?"),
    e(datetime.datetime.now().strftime("%d %B %Y, %H:%M"))))

W('<div class="verdict %s"><strong>%s</strong><span class="tally">%d needing attention &middot; %d minor &middot; %d could not be checked &middot; %d acknowledged</span></div>'
  % (VCOLOR, e(verdict or vkey.replace("_", " ").title()),
     counts.get("attention", 0), counts.get("notice", 0),
     counts.get("unknown", 0), counts.get("acknowledged", 0)))

W('<div class="scores">')
for cat in ("security", "network", "bloat", "maintenance"):
    n = sc.get(cat, 100)
    W('<div class="score"><div class="cat">%s</div><div class="n">%d<small>/100</small></div>%s%s</div>'
      % (e(cat), n, bar(n), delta(cat)))
W('</div>')
if prev:
    W('<p class="note">Compared with the run on %s. %d previous run%s on record.</p>'
      % (e(prev[0]), runs, "" if runs == 1 else "s"))
else:
    W('<p class="note">First recorded run, so there is nothing to compare against yet. '
      'Run Neptune again after working through the list below and this section will '
      'show what moved.</p>')

num = 0
for sev, heading, blurb in SEV_ORDER:
    group = [f for f in findings if f["severity"] == sev and not f["acknowledged"]]
    if not group: continue
    W('<h2>%s</h2><p class="note">%s</p>' % (e(heading), e(blurb)))
    for f in group:
        # info items are deliberately NOT numbered. The numbers here are the
        # argument to --acknowledge, and that command resolves against
        # attention/unknown/notice only — so numbering an info item would print
        # a number the tool then rejects.
        if sev == "info":
            label = "&middot;"
        else:
            num += 1
            label = "%d." % num
        a = f["advice"]
        ven = f.get("vendor", {})
        W('<details class="f"%s><summary><span class="num">%s</span><span>'
          '<span class="tag">%s</span>%s%s</span></summary><div class="body">'
          % (' open' if sev == "attention" else '', label, e(f["category"]),
             ('<span class="vendor">known %s pattern</span>' % e(ven["name"])) if ven else "",
             e(f["title"])))
        if ven and ven.get("note"):
            W('<div class="vnote"><strong>%s.</strong> %s This is a label, not a '
              'dismissal: the finding is still counted and still costs points. '
              'Acknowledging it is a decision about your machine, and stays yours '
              'to make.</div>' % (e(ven["name"]), e(ven["note"])))
        if f.get("runs", 0) > 1:
            W('<p class="streak">Seen in %d runs, first on %s. %s</p>'
              % (f["runs"], e(f.get("first_seen", "?")),
                 "Still here after everything you have done since."
                 if f["runs"] >= 4 else "Not new."))
        elif f.get("runs") == 1:
            W('<p class="streak">First seen in this run.</p>')
        if a.get("unmapped"):
            W('<p>No stock explanation for this one — it is a finding shape the '
              'remediation table does not cover yet. The full text report has the '
              'surrounding context from the scan that raised it.</p>')
        else:
            W('<div class="lbl">What this means</div><p>%s</p>' % e(a["means"]))
            W('<div class="lbl">What to do</div><p>%s</p>' % e(a["do"]))
        cmds = list(a["commands"])
        if sev in ("attention", "notice"):
            cmds.append(("./neptune.sh --acknowledge %d" % num, "neptune",
                         "Marks this a known-good quirk on this machine. It stays listed and "
                         "counted; it only stops deducting. Undo by deleting the line from "
                         "~/.neptune/allow."))
            cmds = [c if isinstance(c, dict) else {"command": c[0], "kind": c[1], "effect": c[2]} for c in cmds]
        if cmds:
            W('<div class="lbl">Commands</div>')
            for c in cmds:
                W('<pre>%s</pre><p class="eff"><span class="kind %s">%s</span>%s</p>'
                  % (e(c["command"]), c["kind"], e(KIND_LABEL[c["kind"]]), e(c["effect"])))
        W('</div></details>')

acked = [f for f in findings if f["acknowledged"]]
if acked:
    W('<h2>Acknowledged</h2><p class="note">Known-good on this machine. Still found, '
      'still listed, still counted &mdash; they only stop deducting from the score. '
      'Nothing is ever silently hidden.</p>')
    for f in acked:
        W('<details class="f"><summary><span class="num">&middot;</span><span>'
          '<span class="tag">%s</span>%s</span></summary><div class="body">'
          '<p>Acknowledged in <code>~/.neptune/allow</code>. Delete that line to '
          'start counting it again.</p></div></details>' % (e(f["category"]), e(f["title"])))

W('<h2>Hand this to an AI assistant</h2>')
W('<div class="box">')
W('<p>Neptune can export the same findings as structured JSON, which a model reads '
  'far more reliably than a screenshot of a terminal. The sanitised version replaces '
  'your hostname, username, IP and MAC addresses with placeholders first, so you can '
  'paste it somewhere without handing over a map of your machine.</p>')
W('<ol class="steps">')
W('<li><div class="lbl">Export it</div><pre>./neptune.sh --json --sanitize</pre>'
  '<p class="eff"><span class="kind look">reads only</span>Writes '
  '<code>~/Desktop/neptune_findings_&lt;date&gt;.json</code>. Every finding carries '
  'its severity, category, and the same explanation and commands you see above.</p></li>')
W('<li><div class="lbl">Attach the file and ask for a plan</div>'
  '<pre>Here is a Neptune security audit of my Mac as JSON.\n\n'
  'Walk me through it in priority order. For each finding tell me what it is,\n'
  'whether it looks like a known vendor quirk or something worth chasing, and\n'
  'what I should do about it.\n\n'
  'Constraints: recommend Neptune\'s own commands (./uninstall.sh &lt;app&gt;,\n'
  './neptune.sh --acknowledge N) or documented single-purpose macOS commands.\n'
  'Do not give me shell to paste that I cannot look up. If you are unsure about\n'
  'a finding, say so rather than guessing.</pre>'
  '<p class="eff">That last paragraph is the important one. A model asked for '
  '&ldquo;the fix&rdquo; will happily invent a <code>sudo</code> one-liner, and a '
  'command you cannot verify is exactly the thing this tool exists to argue '
  'against.</p></li>')
W('<li><div class="lbl">Do the work, then run Neptune again</div>'
  '<pre>./neptune.sh --html</pre>'
  '<p class="eff"><span class="kind look">reads only</span>The next report compares '
  'against this one and shows what each score did. That is the loop: audit, '
  'understand, act, re-measure.</p></li>')
W('</ol></div>')

W('<h2>How to read the scores</h2>')
W('<div class="box"><p>Each category starts at 100 and loses points per finding. The '
  'first issue of a kind in a category costs full weight; repeats cost about a third, '
  'because nine unsigned launch items are usually one vendor habit rather than nine '
  'independent problems. Every deduction traces to a finding listed above &mdash; a '
  'score whose arithmetic you cannot follow is decoration, not information.</p>'
  '<p>A low security score is not the same as &ldquo;compromised&rdquo;. On a working '
  'Mac with pro-audio or virtualisation software, most of what lands here is vendor '
  'sloppiness: helpers shipped unsigned, licence daemons running as root. That is worth '
  'knowing and worth acknowledging deliberately &mdash; which is different from a tool '
  'quietly deciding for you that it does not matter.</p></div>')

W('<footer>')
W('<p><strong>This file contains no JavaScript</strong>, no external stylesheet, no '
  'webfont and no image request. Opening it makes no network connections. You can '
  'read the whole thing in a text editor.</p>')
W('<p>Neptune is read-only apart from its own state in <code>~/.neptune/</code> and '
  '<code>~/.sentry/</code>. It has no daemon, nothing scheduled, and it never sends '
  'anything anywhere. See <code>SECURITY.md</code> in the repository for the complete '
  'on-disk footprint, the reason each script asks for <code>sudo</code>, and commands '
  'to verify all of that yourself before you trust it.</p>')
W('<p>Generated %s%s</p>' % (e(generated), " &middot; sanitised" if san else ""))
W('</footer></div></body></html>')

sys.stdout.write("\n".join(parts) + "\n")
PY
}

# --acknowledge N[,N...]: mark findings as known-good vendor quirks.
#
# Every number is resolved against THIS run's listing BEFORE anything is
# written. Acknowledging one finding removes it from the unacknowledged list and
# renumbers the rest, so resolving them one at a time means the second number
# you typed refers to a different finding than the one you read — silently
# suppressing the wrong alert, which is the failure this whole project is about.
if [ -n "$ACK_ARG" ]; then
  ORDER="$TMP/order.txt"
  { awk -F'|' '$1=="attention" && $6==0' "$SCORED"
    awk -F'|' '$1=="unknown"   && $6==0' "$SCORED"
    awk -F'|' '$1=="notice"    && $6==0' "$SCORED"
  } > "$ORDER"
  AVAIL=$(wc -l < "$ORDER" | xargs)
  RESOLVED="$TMP/resolved.txt"; : > "$RESOLVED"
  BAD=""
  for N in $(printf '%s' "$ACK_ARG" | tr ',' ' '); do
    LINE=$(sed -n "${N}p" "$ORDER")
    [ -n "$LINE" ] && printf '%s\n' "$LINE" >> "$RESOLVED" || BAD="$BAD $N"
  done
  if [ -n "$BAD" ]; then
    echo "No finding numbered:$BAD in this run (1-${AVAIL} available)." >&2
    echo "Numbers come from the listing a plain ./neptune.sh run prints." >&2
    exit 64
  fi
  while IFS='|' read -r _SEV _CAT _SCAN TITLE KEY _ACK _VENDOR; do
    printf '%s\n' "$KEY" >> "$ALLOW"
    echo "Acknowledged: $TITLE"
  done < "$RESOLVED"
  echo
  echo "Recorded in $ALLOW."
  echo "These stay listed and counted on every run — they just stop deducting"
  echo "from the score. Delete the line to un-acknowledge."
  exit 0
fi

############################################################
# Report file: verdict on top, full scan output beneath
############################################################
FINAL="$TMP/final.txt"
{
  head -4 "$REPORT"
  echo
  render_verdict
  tail -n +5 "$REPORT"
} > "$FINAL"
mv "$FINAL" "$REPORT"

# Per-finding history. "Flagged" and "flagged in each of the last six runs" are
# different statements, and only the second one tells you whether anything you
# did helped. Keyed the same way --acknowledge is, so the entry survives the
# PIDs, ports and versions that change every run.
#
# Updated BEFORE rendering, unlike history.tsv, and for the opposite reason:
# here the report should say how many runs including this one have seen the
# finding, whereas there "previous run" has to mean the one before this.
#
# A finding that stops appearing keeps its row with its last-seen date. That is
# the record of something being fixed, which is worth more than the few bytes.
SEEN="$NEPTUNE_HOME/seen.tsv"
[ -f "$SEEN" ] || printf '# key\tfirst_seen\tlast_seen\truns\n' > "$SEEN"
awk -F'|' '{print $5}' "$SCORED" | sort -u | grep -v '^$' > "$TMP/keys.txt"
awk -F'\t' -v today="$(date '+%Y-%m-%d')" '
  FNR == NR {
    if ($0 ~ /^#/ || $1 == "") next
    first[$1] = $2; last[$1] = $3; runs[$1] = $4
    if (!($1 in known)) { known[$1] = 1; order[++n] = $1 }
    next
  }
  {
    k = $0
    if (k in known) { last[k] = today; runs[k] = runs[k] + 1 }
    else { known[k] = 1; order[++n] = k; first[k] = today; last[k] = today; runs[k] = 1 }
  }
  END {
    printf "# key\tfirst_seen\tlast_seen\truns\n"
    for (i = 1; i <= n; i++) {
      k = order[i]
      printf "%s\t%s\t%s\t%d\n", k, first[k], last[k], runs[k]
    }
  }
' "$SEEN" "$TMP/keys.txt" > "$TMP/seen.new" && mv "$TMP/seen.new" "$SEEN"

SAN=$( $SANITIZE_OUT && echo 1 || echo 0 )

# Rendered BEFORE this run is appended to the history file, so the renderer's
# "previous run" really is the previous one.
if $JSON_OUT; then render "json" "$SAN" > "$JSON_PATH"; fi
if $HTML_OUT; then render "html" "$SAN" > "$HTML_PATH"; fi

if [ ! -f "$HISTORY" ]; then
  printf '# date\tverdict\tsecurity\tnetwork\tbloat\tmaintenance\tattention\tnotice\tunknown\tacknowledged\n' > "$HISTORY"
fi
getscore() { awk -F'|' -v c="$1" '$1=="score" && $2==c {print $3}' "$SCORES"; }
printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
  "$(date '+%Y-%m-%d %H:%M')" "$VKEY" \
  "$(getscore security)" "$(getscore network)" "$(getscore bloat)" "$(getscore maintenance)" \
  "${N_ATTENTION:-0}" "${N_NOTICE:-0}" "${N_UNKNOWN:-0}" "${N_ACK:-0}" >> "$HISTORY"

echo
echo "${BOLD}${VCOL}${VERDICT}${RST}"
echo
render_verdict | tail -n +4
echo
echo "${BOLD}Full report:${RST} $REPORT"
$HTML_OUT && echo "${BOLD}HTML report:${RST} $HTML_PATH$( $SANITIZE_OUT && echo '   (sanitized)' )"
$JSON_OUT && echo "${BOLD}JSON findings:${RST} $JSON_PATH$( $SANITIZE_OUT && echo '   (sanitized)' )"
if ! $HTML_OUT; then
  echo
  echo "For a readable report with what each finding means and what to do:"
  echo "  ./neptune.sh --html"
fi

# Exit-code contract. Ordered the same way the verdict is, and for the same
# reason: a check that could not run outranks a minor finding, because an
# unknown is not a pass. Acknowledged findings deliberately do not enter this —
# acknowledging says "this is a known vendor quirk", not "this is not a
# problem", and a machine that exits 0 because its owner silenced everything
# would make the exit code a worse signal than no exit code.
if   [ "${N_ATTENTION:-0}" -gt 0 ]; then exit 1
elif [ "${N_UNKNOWN:-0}"   -gt 0 ]; then exit 2
else                                     exit 0
fi
