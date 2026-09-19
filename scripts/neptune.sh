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
SANITIZE_OUT=false
ACK_ARG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --json)        JSON_OUT=true ;;
    --sanitize)    SANITIZE_OUT=true ;;
    --acknowledge) shift; ACK_ARG="${1:-}" ;;
    -h|--help)
      cat <<'USAGE'
neptune.sh — run the Neptune scan suite, then report a verdict and scores.

  ./neptune.sh                    run the suite (read-only; nothing is deleted)
  ./neptune.sh --json             also write structured findings as JSON
  ./neptune.sh --json --sanitize  ...with host, user, IPs and MACs replaced,
                                  for sharing or pasting into a model
  ./neptune.sh --acknowledge N    mark finding N a known-good vendor quirk
  ./neptune.sh --acknowledge 2,5  several at once, resolved before any write

Acknowledged findings stay listed and stay counted — they only stop deducting
from the score. Nothing is ever silently hidden. Edit ~/.neptune/allow to undo.

Reports go to ~/Desktop. See SECURITY.md for the full footprint and how to
verify what this does before running it.
USAGE
      exit 0 ;;
    *)             echo "Unknown option: $1" >&2; exit 1 ;;
  esac
  shift
done
case "$ACK_ARG" in
  ''|*[!0-9,]*) [ -z "$ACK_ARG" ] || { echo "--acknowledge takes finding numbers, e.g. 5 or 5,6,7" >&2; exit 1; } ;;
esac
$SANITIZE_OUT && ! $JSON_OUT && { echo "--sanitize only applies with --json" >&2; exit 1; }

DIR="$(cd "$(dirname "$0")" && pwd)"
STAMP=$(date '+%Y-%m-%d_%H%M')
REPORT="$HOME/Desktop/neptune_full_report_${STAMP}.txt"
JSON_PATH="$HOME/Desktop/neptune_findings_${STAMP}.json"
NEPTUNE_HOME="$HOME/.neptune"
mkdir -p "$NEPTUNE_HOME"
TMP=$(mktemp -d /tmp/neptune.XXXXXX)
trap 'rm -rf "$TMP"' EXIT

# Scans append structured records here. Exported so each child sees it; unset
# in a standalone run, where record() is a no-op.
FINDINGS="$TMP/findings.txt"
: > "$FINDINGS"
export NEPTUNE_FINDINGS="$FINDINGS"

if [ "$(id -u)" -eq 0 ]; then
  echo "Run as your normal user, not with sudo."; exit 1
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
' "$FINDINGS" 2>/dev/null | awk -F'|' '!seen[$1 "|" $2 "|" $4]++' > "$SCORED"

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
      while IFS='|' read -r _sev _cat _scan _title _rest; do
        NUM=$((NUM + 1))
        printf '   %2d. [%s] %s\n' "$NUM" "$_cat" "$_title"
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
render_json() {
  SANITIZE=$1 python3 - "$SCORED" "$SCORES" "$VKEY" <<'PY'
import json, os, re, subprocess, sys, datetime
scored, scores, vkey = sys.argv[1], sys.argv[2], sys.argv[3]
san = os.environ.get("SANITIZE") == "1"
host = subprocess.run(["hostname"], capture_output=True, text=True).stdout.strip()
user = os.environ.get("USER", "")

def clean(t):
    if not san: return t
    if host: t = t.replace(host, "example-mac").replace(host.split(".")[0], "example-mac")
    if user: t = t.replace(user, "exampleuser")
    t = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "0.0.0.0", t)
    t = re.sub(r"\b(?:[0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2}\b", "xx:xx:xx:xx:xx:xx", t)
    return t

sc, ack, counts = {}, {}, {}
for line in open(scores):
    f = line.rstrip("\n").split("|")
    if f[0] == "score": sc[f[1]] = int(f[2]); ack[f[1]] = int(f[3])
    elif f[0] == "count": counts[f[1]] = int(f[2])

findings = []
for line in open(scored):
    f = line.rstrip("\n").split("|")
    if len(f) < 6: continue
    findings.append({"severity": f[0], "category": f[1], "scan": f[2],
                     "title": clean(f[3]), "key": f[4], "acknowledged": f[5] == "1"})

print(json.dumps({
    "neptune": {"schema": 1,
                "generated": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
                "host": clean(host) if san else host,
                "sanitized": san},
    "verdict": vkey,
    "scores": sc,
    "acknowledged_by_category": ack,
    "counts": counts,
    "findings": findings,
}, indent=2))
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
    exit 1
  fi
  while IFS='|' read -r _SEV _CAT _SCAN TITLE KEY _ACK; do
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

if $JSON_OUT; then
  render_json "$( $SANITIZE_OUT && echo 1 || echo 0 )" > "$JSON_PATH"
  echo
  echo "${BOLD}${GRN}Suite complete.${RST}"
  echo "JSON findings: $JSON_PATH$( $SANITIZE_OUT && echo '   (sanitized)' )"
fi

echo
echo "${BOLD}${VCOL}${VERDICT}${RST}"
echo
render_verdict | tail -n +4
echo
echo "${BOLD}Full report:${RST} $REPORT"
