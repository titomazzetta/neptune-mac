#!/bin/bash
#
# sentry.sh — Unified host check: HIDS-style change detection, process→network
#             correlation, network health, and app staleness — one run, one report.
#
# Sections:
#   1. CHANGE DETECTION (HIDS-lite / tripwire-style)
#        Snapshots persistence items, privileged helpers, system extensions,
#        installed apps, and listeners. Every run is diffed against the last
#        known-good baseline: NEW or REMOVED items are surfaced immediately.
#        First run establishes the baseline.
#   2. PROCESS -> NETWORK MAP
#        Every process that currently has network connections, with its code
#        signature, listener ports, and outbound connection count. The zoomed
#        out "who is talking, and are they who they say they are" view.
#   3. NETWORK HEALTH
#        Gateway + internet latency, DNS response, double-NAT quick check.
#   4. APP USAGE & STALENESS
#        Apps not opened in 6+ months  -> deletion candidates.
#        Apps used in the last 30 days -> the ones worth keeping updated.
#
# Read-only except its own baseline files in ~/.sentry/
# Report saved to ~/Desktop/sentry_report_<date>.txt
#
# Usage:
#   ./sentry.sh                 normal run (diff vs baseline)
#   ./sentry.sh --rebaseline    accept current state as the new known-good

set -u
export LC_ALL=C   # byte-safe text tools on macOS — see the note in neptune.sh

BOLD=$(tput bold 2>/dev/null || true)
RED=$(tput setaf 1 2>/dev/null || true)
GRN=$(tput setaf 2 2>/dev/null || true)
YEL=$(tput setaf 3 2>/dev/null || true)
CYN=$(tput setaf 6 2>/dev/null || true)
RST=$(tput sgr0 2>/dev/null || true)

BASE="$HOME/.sentry"
# Bump whenever snapshot() changes what it records. An old baseline compared
# against a new format produces a wall of bogus NEW/REMOVED lines, which is
# indistinguishable from a real incident — so a format change must reset the
# baseline explicitly and say it did, never diff across the boundary.
BASELINE_FORMAT=2
REPORT="${NEPTUNE_REPORT_DIR:-$HOME/Desktop}/sentry_report_$(date '+%Y-%m-%d_%H%M').txt"
FLAGS=()

# Structured finding records. When NEPTUNE_FINDINGS is set (neptune.sh sets it),
# every finding is ALSO appended as a pipe-delimited record so the master runner
# can score and render it without re-parsing this script's prose. Unset — i.e. a
# standalone run — record() is a no-op and output is unchanged.
#
# Deliberately duplicated into each scan rather than sourced from a shared file:
# CLAUDE.md requires the scans stay independently runnable, and the existing
# colour helpers are duplicated the same way.
SCAN=sentry
CATEGORY=security          # reset per section below
CHECK=""                   # reset per check below — see the record format in neptune.sh
record() {
  [ -n "${NEPTUNE_FINDINGS:-}" ] || return 0
  printf '%s|%s|%s|%s|%s\n' "$1" "$CATEGORY" "$SCAN" "$CHECK" \
    "$(printf '%s' "$2" | tr '|\t\n' '/  ')" >> "$NEPTUNE_FINDINGS"
}

out()     { echo "$@" | tee -a "$REPORT"; }
section() { out ""; out "${BOLD}${CYN}== $* ==${RST}"; }
ok()      { out "  ${GRN}[ok]${RST} $*"; }                        # prints only
pass()    { out "  ${GRN}[ok]${RST} $*"; record pass "$*"; }      # a check that ran clean
warn()    { out "  ${YEL}[!!]${RST} $*"; record notice "$*"; }
flag()    { FLAGS+=("$*"); out "  ${RED}[FLAG]${RST} $*"; record attention "$*"; }
unknown() { out "  ${YEL}[!!]${RST} $*"; record unknown "$*"; }
# Something the reader should see but that is not a defect in the machine: a
# one-time migration, a mode the scan ran in. It is recorded — suppressing it
# from --json would make the JSON disagree with the report — but it deducts no
# points and does not move the verdict. A tool that charges you for its own
# housekeeping is a tool whose score you stop trusting.
info()    { out "  ${YEL}[!!]${RST} $*"; record info "$*"; }


# sig <path> — apple | signed:<who> | adhoc | unsigned | missing.
# Same contract as redflag_scan.sh, and tests/unit.sh asserts the two copies
# classify every fixture identically. "adhoc" — a valid signature that names no
# signer — is its own class; it used to pass as "signed" (DEVLOG Bug 16).
sig() {
  local BIN=$1 INFO AUTH
  [ -e "$BIN" ] || { echo "missing"; return; }
  if ! codesign -v "$BIN" 2>/dev/null; then echo "unsigned"; return; fi
  INFO=$(codesign -dvv "$BIN" 2>&1)
  case "$INFO" in *"Signature=adhoc"*) echo "adhoc"; return ;; esac
  AUTH=$(printf '%s\n' "$INFO" | grep -m1 '^Authority=' | cut -d= -f2)
  case "$AUTH" in
    # macOS 26 names Apple's own leaf certificate "macOS Software Signing";
    # earlier releases say "Software Signing". Missing the new name classed
    # every Apple binary as a third-party developer (DEVLOG Bug 20).
    "Software Signing"|"macOS Software Signing"|"Apple Mac OS Application Signing") echo "apple" ;;
    "") echo "adhoc" ;;
    *) echo "signed:$AUTH" ;;
  esac
}

# listener_entries — `lsof -i -P -n` output on stdin, baseline entries out.
#
# Collapses listener ports in the dynamic/ephemeral range (49152-65535).
# macOS reassigns those at every boot, so the port NUMBER is churn while the
# process and the interface scope are the actual signal. Unsuppressed,
# rapportd and Splice alone produced 6 of 10 flags on a known-clean machine
# — noise that teaches you to skim the flag list, which is how a real
# finding gets missed.
#
# This does NOT blind the check: a listening process that wasn't there
# before still appears, and one that moves from loopback to all-interfaces
# still changes its entry. Only the per-boot number is dropped. Fixed ports
# (anything below 49152) are recorded exactly as before.
listener_entries() {
  awk '
    $NF ~ /LISTEN/ {
      addr = $9
      n = split(addr, p, ":")
      if (p[n] + 0 >= 49152 && p[n] + 0 <= 65535) sub(/:[0-9]+$/, ":ephemeral", addr)
      print "listener:" $1 ":" addr
    }' | sort -u
}

# ---------------------------------------------------------------------------
# Sourced by tests/unit.sh to exercise the pure functions above against
# captured fixtures, without running a scan or touching the system. Nothing
# below this line executes when NEPTUNE_LIB=1.
#
# Those functions are where the real bugs lived (DEVLOG Bugs 5 and 7), and they
# need no macOS to test — only saved command output.
# ---------------------------------------------------------------------------
[ "${NEPTUNE_LIB:-}" = "1" ] && return 0

mkdir -p "$BASE"

REBASE=false
[ "${1:-}" = "--rebaseline" ] && REBASE=true

if [ "$(id -u)" -eq 0 ]; then echo "Run as normal user, not sudo."; exit 1; fi

: > "$REPORT"
out "${BOLD}Sentry — $(hostname) — $(date '+%Y-%m-%d %H:%M')${RST}"
sudo -v || exit 1
# Keep-alive for the cached sudo credential. Its output is detached: the loop's
# `sleep` outlives a kill of the loop by up to 50 s, and while it holds this
# script's stdout, `neptune.sh`'s `| tee` waits for it (found in review).
( while true; do sudo -n true 2>/dev/null; sleep 50; done ) >/dev/null 2>&1 </dev/null & KA=$!
trap 'kill $KA 2>/dev/null' EXIT

############################################################
# 1. CHANGE DETECTION (HIDS-lite)
############################################################
CATEGORY=security
section "1. Change detection vs baseline"

snapshot() {
  # Produces a sorted, stable inventory of all monitored surfaces
  {
    for D in "$HOME/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons; do
      [ -d "$D" ] && ls "$D" 2>/dev/null | sed "s|^|launchd:$D/|"
    done
    ls /Library/PrivilegedHelperTools 2>/dev/null | sed 's|^|helper:|'
    systemextensionsctl list 2>/dev/null | grep -oE '[a-zA-Z0-9.-]+\.[a-zA-Z0-9.-]+ \(' | sed 's/ ($//;s/ (//' | sed 's|^|sysext:|'
    # Glob, not `ls | grep` — handles names with spaces/newlines and satisfies SC2010.
    # bash 3.2 safe: no globstar, no arrays, `[ -e ]` guards the no-match literal.
    for A in /Applications/*.app; do
      [ -e "$A" ] || continue
      echo "app:$(basename "$A")"
    done
    # Listening sockets, with per-boot ephemeral port numbers collapsed.
    sudo lsof -i -P -n 2>/dev/null | listener_entries
  } | sort -u
}

CURRENT="$BASE/current.txt"
BASELINE="$BASE/baseline.txt"
snapshot > "$CURRENT"

FORMATFILE="$BASE/format"
STORED_FORMAT=$(cat "$FORMATFILE" 2>/dev/null || echo 1)

CHECK=baseline-diff
if [ ! -f "$BASELINE" ] || $REBASE; then
  cp "$CURRENT" "$BASELINE"
  echo "$BASELINE_FORMAT" > "$FORMATFILE"
  info "Baseline $( $REBASE && echo 're-established' || echo 'created' ): $(wc -l < "$BASELINE" | xargs) items are now the known-good snapshot"
  out "  Future runs will flag anything that appears or disappears."
elif [ "$STORED_FORMAT" != "$BASELINE_FORMAT" ]; then
  cp "$CURRENT" "$BASELINE"
  echo "$BASELINE_FORMAT" > "$FORMATFILE"
  info "Baseline format changed (v${STORED_FORMAT} -> v${BASELINE_FORMAT}); baseline REPLACED, nothing diffed this run"
  out "      Listener ports in the dynamic range are now recorded as ':ephemeral'"
  out "      rather than a per-boot number. Your previous baseline is not"
  out "      comparable, so it was replaced rather than diffed against — a"
  out "      cross-format diff would have looked like dozens of new listeners."
  out "      Re-run ./sentry.sh to compare against the new baseline."
else
  # comm needs both sides sorted in the SAME collation. Baselines written before
  # the scans switched to the C locale were sorted under UTF-8 rules, and comm
  # on mismatched orderings reports phantom NEW/REMOVED lines — the exact wall
  # of noise the format guard above exists to prevent. Re-sorting both sides
  # here keeps every existing baseline valid.
  NEW=$(comm -13 <(sort "$BASELINE") <(sort "$CURRENT"))
  GONE=$(comm -23 <(sort "$BASELINE") <(sort "$CURRENT"))
  if [ -z "$NEW" ] && [ -z "$GONE" ]; then
    pass "Nothing has changed since the baseline of $(stat -f '%Sm' -t '%Y-%m-%d' "$BASELINE") — persistence, helpers, extensions, apps and listeners all stable"
  else
    # Something disappearing is not a threat, but it is not nothing either:
    # it is recorded (no score impact), and "nothing new" is the pass. Before,
    # a removal-only diff recorded nothing and the check vanished from the
    # report's coverage (Bug 21).
    if [ -z "$NEW" ]; then
      pass "Nothing new since the baseline of $(stat -f '%Sm' -t '%Y-%m-%d' "$BASELINE") — no new persistence, helpers, extensions, apps or listeners"
    fi
    if [ -n "$GONE" ]; then
      info "$(printf '%s\n' "$GONE" | grep -c .) baseline item(s) are gone — software removed, or an app that is not running right now"
    fi
    if [ -n "$NEW" ]; then
      out "  ${RED}NEW since baseline:${RST}"
      while IFS= read -r L; do flag "NEW since baseline: $L"; done <<EOF
$NEW
EOF
    fi
    if [ -n "$GONE" ]; then
      out "  ${YEL}Removed since baseline:${RST}"
      echo "$GONE" | sed 's/^/      /' | tee -a "$REPORT"
    fi
    out "  If these changes are yours (new software installed/removed), run:"
    out "      ./sentry.sh --rebaseline"
  fi
fi

############################################################
# 2. PROCESS -> NETWORK MAP
############################################################
CATEGORY=security
CHECK=network-signing
section "2. Process -> network map"

# In the suite, redflag_scan.sh owns the signing check for LISTENING processes,
# so a listener is only printed here, not flagged. The old suite reported one
# unsigned localhost service four times — its launch agent, its IPv4 listener,
# its IPv6 listener and here — and deducted for each (DEVLOG Bug 17).
NET_PROBLEMS=0
out "  ${BOLD}Processes with network activity (listeners and outbound):${RST}"
while read -r NAME PID; do
  BIN=$(ps -p "$PID" -o comm= 2>/dev/null)
  [ -z "$BIN" ] && continue
  S=$(sig "$BIN")
  # -a ANDs the selectors: only THIS pid's sockets (without it, lsof ORs and
  # returns every network file on the system for every process)
  LISTENS=$(sudo lsof -a -i -P -n -p "$PID" 2>/dev/null | awk '$NF ~ /LISTEN/ {print $9}' | sort -u | tr '\n' ' ')
  ESTAB=$(sudo lsof -a -i -P -n -p "$PID" 2>/dev/null | awk '$NF ~ /ESTABLISHED/' | wc -l | xargs)
  LINE="$NAME (pid $PID) — sig:$S — outbound:$ESTAB"
  [ -n "$LISTENS" ] && LINE="$LINE — LISTENING on: $LISTENS"
  case "$S" in
    unsigned|adhoc)
      case "$BIN" in
        # SIP-protected Apple code (SIP itself is verified by redflag_scan.sh).
        # Say "not verified", not "unsigned": codesign can fail on a system
        # path for reasons that are not a missing signature.
        /System/*|/usr/bin/*|/usr/sbin/*|/usr/libexec/*|/sbin/*)
          out "      $(printf '%s' "$LINE" | sed "s/sig:$S/sig:not verified (SIP-protected system path)/")" ;;
        *)
          if [ -n "${NEPTUNE_SUITE:-}" ] && [ -n "$LISTENS" ]; then
            out "      $LINE   (listener — signing checked by redflag_scan.sh)"
          else
            NET_PROBLEMS=$((NET_PROBLEMS + 1))
            if [ "$S" = "adhoc" ]; then
              flag "Ad-hoc signed process with network access: $LINE ($BIN)"
            else
              flag "Unsigned process with network access: $LINE ($BIN)"
            fi
          fi ;;
      esac ;;
    missing) NET_PROBLEMS=$((NET_PROBLEMS + 1)); flag "Network-active process whose binary cannot be found: $LINE" ;;
    *) out "      $LINE" ;;
  esac
done < <(sudo lsof -i -P -n 2>/dev/null | awk 'NR>1 {print $1, $2}' | sort -u)
[ "$NET_PROBLEMS" -eq 0 ] && pass "Every process with network activity is signed by Apple or an identified developer"

############################################################
# 3. NETWORK HEALTH
############################################################
CATEGORY=network
section "3. Network health"

# In the suite, network_check.sh owns latency and double NAT. Running both used
# to report one double NAT twice and two different latencies for the same router
# in the same report (DEVLOG Bug 9c). Standalone, sentry still does both.
if [ -n "${NEPTUNE_SUITE:-}" ]; then
  out "  Covered by network_check.sh in this suite (latency, DNS, double NAT)."
else

GATEWAY=$(route -n get default 2>/dev/null | awk '/gateway/{print $2}')

# 5 pings, matching network_check.sh, and avg + worst rather than avg alone.
# At 3 pings a single Wi-Fi power-save wake-up moves the average by 30ms, and
# the two scans then printed different latencies for the same router in the same
# combined report — 38.555ms here against 9.372ms there. Nothing was wrong with
# either number; they sampled different moments and neither said so. Showing the
# spread, at a common sample size, makes the variance the finding.
rtt() { ping -c 5 -q "$1" 2>/dev/null | awk -F/ '/round-trip|rtt/{print $5, $6}'; }
GW_RTT=$(rtt "${GATEWAY:-127.0.0.1}")
GW_PING=$(printf '%s' "$GW_RTT" | awk '{print $1}')
GW_MAX=$(printf  '%s' "$GW_RTT" | awk '{print $2}')
NET_PING=$(rtt 1.1.1.1 | awk '{print $1}')
out "  Gateway ${GATEWAY:-?}: ${GW_PING:-?} ms avg / ${GW_MAX:-?} ms worst (5 pings) | Internet: ${NET_PING:-?} ms avg"

CHECK=lan-latency
if [ -n "${GW_PING:-}" ] && [ -n "${NET_PING:-}" ]; then
  if awk "BEGIN{exit !($GW_PING > 15)}"; then
    warn "LAN latency high (${GW_PING}ms average to your own router over 5 pings) — mesh backhaul or Wi-Fi issue"
  else
    pass "LAN latency is healthy (${GW_PING} ms average to your router)"
  fi
else
  unknown "LAN latency could not be measured (no ping reply from the gateway)"
fi

# DNS timing
DNS_T=$( { time dscacheutil -q host -a name example.org >/dev/null; } 2>&1 | awk '/real/{print $2}')
out "  DNS resolution (example.org): ${DNS_T:-?}"

# Quick double-NAT probe.
# The local gateway counts as NAT layer one (it may not even answer traceroute),
# so ANY OTHER private-address hop in the path means a second router = double NAT.
HOPS=$(traceroute -n -m 4 -w 1 -q 1 1.1.1.1 2>/dev/null | awk 'NR>1{print $2}')
EXTRA_PRIV=""
for H in $HOPS; do
  [ "$H" = "${GATEWAY:-}" ] && continue
  case "$H" in
    100.6[4-9].*|100.[7-9][0-9].*|100.1[0-1][0-9].*|100.12[0-7].*) ;;  # CGNAT = ISP-side, not yours
    10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) EXTRA_PRIV="$EXTRA_PRIV $H" ;;
  esac
done
CHECK=double-nat
if [ -z "$EXTRA_PRIV" ]; then
  pass "Single NAT — no second private router between this Mac and the internet"
else
  flag "Possible double NAT: private router(s) beyond your gateway:$EXTRA_PRIV — verify: if your router's WAN IP is private (192.168.x/10.x), double NAT is real; if it shows your public IP, this is IP-passthrough echo and is fine"
fi
fi   # end: standalone network health

############################################################
# 4. APP USAGE & STALENESS
############################################################
CATEGORY=bloat
section "4. App usage and staleness"

NOW=$(date +%s)
SIX_MONTHS=$((60*60*24*182))
THIRTY_DAYS=$((60*60*24*30))

STALE=()
ACTIVE=()
NODATA=()
while IFS= read -r APP; do
  NAME=$(basename "$APP" .app)
  LASTUSED=$(mdls -name kMDItemLastUsedDate -raw "$APP" 2>/dev/null)
  VER=$(defaults read "$APP/Contents/Info" CFBundleShortVersionString 2>/dev/null || echo "?")
  if [ "$LASTUSED" = "(null)" ] || [ -z "$LASTUSED" ]; then
    NODATA+=("$NAME (v$VER)")
    continue
  fi
  LU_EPOCH=$(date -j -f '%Y-%m-%d %H:%M:%S %z' "$LASTUSED" +%s 2>/dev/null || echo 0)
  AGE=$((NOW - LU_EPOCH))
  if [ "$LU_EPOCH" -gt 0 ] && [ "$AGE" -gt "$SIX_MONTHS" ]; then
    STALE+=("$NAME (v$VER) — last used $(date -j -f '%s' "$LU_EPOCH" '+%b %Y' 2>/dev/null)")
  elif [ "$LU_EPOCH" -gt 0 ] && [ "$AGE" -lt "$THIRTY_DAYS" ]; then
    ACTIVE+=("$NAME (v$VER)")
  fi
done < <(find /Applications -maxdepth 1 -name "*.app" | sort)

out "  ${BOLD}Actively used (last 30 days) — keep these updated:${RST}"
if [ ${#ACTIVE[@]} -gt 0 ]; then
  for A in "${ACTIVE[@]}"; do out "      $A"; done
else
  out "      (none detected)"
fi

out ""
out "  ${BOLD}Stale (6+ months unused, date-confirmed) — deletion candidates:${RST}"
CHECK=stale-apps
if [ ${#STALE[@]} -gt 0 ]; then
  # ONE finding for the lot. Six unused apps are one decision to review, not six
  # problems, and six separate findings would dominate the bloat score.
  STALE_NAMES=$(for A in "${STALE[@]}"; do printf '%s\n' "${A%% (v*}"; done | head -5 | awk 'BEGIN{ORS=""} {print (NR>1 ? ", " : "") $0}')
  [ ${#STALE[@]} -gt 5 ] && STALE_NAMES="$STALE_NAMES and $(( ${#STALE[@]} - 5 )) more"
  warn "${#STALE[@]} app(s) have not been opened in over six months: $STALE_NAMES"
  for A in "${STALE[@]}"; do out "      ${YEL}$A${RST}"; done
  out ""
  out "      Unused apps aren't just disk space — several may still have launch"
  out "      agents or helpers running (cross-reference section 1 and the audit)."
  out "      Review before deleting: some are drivers/editors for hardware you"
  out "      own but rarely reconfigure (those are fine to keep)."
else
  pass "No app with a confirmed last-used date has gone unopened for six months"
fi

if [ ${#NODATA[@]} -gt 0 ]; then
  out ""
  out "  ${BOLD}No Spotlight usage data (UNRELIABLE — do not delete off this list):${RST}"
  out "      Spotlight often misses apps launched via helpers or excluded from"
  out "      indexing; apps here may be in daily use. Judge these manually."
  for A in "${NODATA[@]}"; do out "      $A"; done
fi

############################################################
# SUMMARY
############################################################
out ""
out "${BOLD}================ SENTRY SUMMARY ================${RST}"
if [ ${#FLAGS[@]} -eq 0 ]; then
  out "${GRN}${BOLD}All clear.${RST} No baseline changes, no unsigned network actors,"
  out "no NAT regression."
else
  out "${RED}${BOLD}${#FLAGS[@]} item(s) flagged:${RST}"
  I=1
  for F in "${FLAGS[@]}"; do out "  $I. $F"; I=$((I+1)); done
  out ""
  out "Flags are leads, not verdicts. If flagged changes are software you"
  out "installed yourself, rebaseline with: ./sentry.sh --rebaseline"
fi
out ""
out "Report saved to: $REPORT"
exit 0
