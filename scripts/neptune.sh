#!/bin/bash
#
# neptune.sh — Run the full Neptune scan suite and produce ONE combined report
#
# Runs, in order:  sentry.sh  ->  redflag_scan.sh  ->  network_check.sh
#                  ->  audit_system.sh  ->  check_updates.sh (scan only)
#
# Output: a single plain-text file on the Desktop with ANSI colors stripped,
# ready to copy-paste in full for review. Also prints a condensed digest
# (every FLAG / [!!] / [XX] line) at the end so the action items are on top.
#
# Usage:   ./neptune.sh
# Note:    read-only throughout (no --upgrade, no deletions).
#          uninstall.sh and remove_mackeeper.sh are never run by this script.

set -u

BOLD=$(tput bold 2>/dev/null || true)
CYN=$(tput setaf 6 2>/dev/null || true)
GRN=$(tput setaf 2 2>/dev/null || true)
RST=$(tput sgr0 2>/dev/null || true)

DIR="$(cd "$(dirname "$0")" && pwd)"
STAMP=$(date '+%Y-%m-%d_%H%M')
REPORT="$HOME/Desktop/neptune_full_report_${STAMP}.txt"
TMP=$(mktemp -d /tmp/neptune.XXXXXX)
trap 'rm -rf "$TMP"' EXIT

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
# Digest: pull every actionable line to the top of the file
############################################################
DIGEST="$TMP/digest.txt"
# Collect only PREFIXED finding lines. The numbered lines ('1. ', '2. ') that the
# per-scan summaries print were matched here too, but they are restatements of
# the same [FLAG] lines — so every finding landed in the digest twice, and
# `sort -u` then interleaved two scans' numbering as 1., 10., 2., 3.
#
# Dedupe with awk rather than `sort -u` so each scan's findings stay in the order
# that scan printed them (the glob groups by scan). Alphabetical order across
# everything told the reader nothing and actively scrambled the numbered lines.
grep -hE '^[[:space:]]*(\[FLAG\]|\[!!\]|\[XX\])' "$TMP"/*.txt 2>/dev/null \
  | sed 's/^[[:space:]]*//' | awk '!seen[$0]++' > "$DIGEST"

# `grep -c` PRINTS 0 and EXITS 1 when nothing matches, so `|| echo 0` appended a
# SECOND zero and a clean run rendered as "Digest (0\n0 flag/error line(s))".
# Take grep's count as-is; substitute only when the command produced no output
# at all (e.g. the digest file is missing).
FLAGCOUNT=$(grep -cE '^\[FLAG\]|^\[XX\]' "$DIGEST" 2>/dev/null)
[ -n "$FLAGCOUNT" ] || FLAGCOUNT=0

# Prepend the digest to the report
FINAL="$TMP/final.txt"
{
  head -4 "$REPORT"
  echo
  echo "================================================================"
  echo "  ACTION DIGEST — every flag and warning from all five scans"
  echo "================================================================"
  if [ -s "$DIGEST" ]; then
    cat "$DIGEST"
  else
    echo "  Nothing flagged anywhere. Fully clean run."
  fi
  echo "================================================================"
  tail -n +5 "$REPORT"
} > "$FINAL"
mv "$FINAL" "$REPORT"

echo "${BOLD}${GRN}Suite complete.${RST}"
echo
echo "${BOLD}Digest (${FLAGCOUNT} flag/error line(s)):${RST}"
if [ -s "$DIGEST" ]; then
  sed 's/^/  /' "$DIGEST"
else
  echo "  Nothing flagged anywhere. Fully clean run."
fi
echo
echo "${BOLD}Full combined report:${RST} $REPORT"
echo "Open it, select all, copy, and paste for a complete review."
