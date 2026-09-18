#!/bin/bash
#
# network_check.sh — One-shot network sanity check for macOS
#
# Read-only. Checks:
#   1. Local network identity (IP, gateway, Wi-Fi vs Ethernet)
#   2. Double-NAT detection (your old nemesis)
#   3. DNS configuration + resolution speed
#   4. Latency baseline (gateway vs internet) — the bufferbloat precondition
#   5. Per-app connection census — what's actually using your network right now
#
# Usage: chmod +x network_check.sh && ./network_check.sh

set -u

BOLD=$(tput bold 2>/dev/null || true)
RED=$(tput setaf 1 2>/dev/null || true)
GRN=$(tput setaf 2 2>/dev/null || true)
YEL=$(tput setaf 3 2>/dev/null || true)
CYN=$(tput setaf 6 2>/dev/null || true)
RST=$(tput sgr0 2>/dev/null || true)

section() { echo; echo "${BOLD}${CYN}== $* ==${RST}"; }
# Structured finding records — see sentry.sh for the rationale. No-op unless
# neptune.sh sets NEPTUNE_FINDINGS, so a standalone run is unchanged.
SCAN=network
CATEGORY=network
record() {
  [ -n "${NEPTUNE_FINDINGS:-}" ] || return 0
  printf '%s|%s|%s|%s\n' "$1" "$CATEGORY" "$SCAN" \
    "$(printf '%s' "$2" | tr '|' '/' | tr -d '\n')" >> "$NEPTUNE_FINDINGS"
}

ok()   { echo "  ${GRN}[ok]${RST} $*"; }
warn() { echo "  ${YEL}[!!]${RST} $*"; record notice "$*"; }
bad()  { echo "  ${RED}[XX]${RST} $*"; record attention "$*"; }


is_private() {
  case "$1" in
    10.*|192.168.*) return 0 ;;
    172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) return 0 ;;
    100.6[4-9].*|100.[7-9][0-9].*|100.1[0-1][0-9].*|100.12[0-7].*) return 0 ;;  # CGNAT
    *) return 1 ;;
  esac
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

PUBLIC_IP=false
[ "${1:-}" = "--public-ip" ] && PUBLIC_IP=true

# Same guard the other scripts carry (CLAUDE.md constraint 5).
if [ "$(id -u)" -eq 0 ]; then
  echo "Run as your normal user, not with sudo."; exit 1
fi

echo "${BOLD}Network check — $(date '+%Y-%m-%d %H:%M')${RST}"

############################################################
# 1. Identity
############################################################
section "Local network identity"

GATEWAY=$(route -n get default 2>/dev/null | awk '/gateway/{print $2}')
IFACE=$(route -n get default 2>/dev/null | awk '/interface/{print $2}')
LOCALIP=$(ipconfig getifaddr "${IFACE:-en0}" 2>/dev/null)

echo "  Interface:  ${IFACE:-?} $(networksetup -listallhardwareports 2>/dev/null | grep -B1 "Device: ${IFACE:-none}" | head -1 | sed 's/Hardware Port: /(/;s/$/)/')"
echo "  Local IP:   ${LOCALIP:-?}"
echo "  Gateway:    ${GATEWAY:-?}"

# Opt-in. This was unconditional, and neptune.sh runs this script as part of the
# standard suite — so every `./neptune.sh` made a third-party request. CLAUDE.md
# constraint 4 permits network use only where it is OPTIONAL, and a tool that
# advertises "no telemetry" should not quietly contact anyone by default. It
# also kept your public IP out of nothing: the value lands in the Desktop report
# the README tells you to copy and paste for review.
PUBIP=""
if $PUBLIC_IP; then
  PUBIP=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || true)
  echo "  Public IP:  ${PUBIP:-<lookup failed>}   (queried api.ipify.org)"
else
  echo "  Public IP:  not checked — re-run with --public-ip to ask api.ipify.org"
fi

############################################################
# 2. Double-NAT detection
############################################################
section "Double-NAT check"

# Your own gateway is NAT layer one, whether or not it answers traceroute
# (many routers silently drop the probe). So the test is: does any OTHER
# private-address router appear in the path?
HOPS=$(traceroute -n -m 4 -w 1 -q 1 1.1.1.1 2>/dev/null | awk 'NR>1 {print $2}')
HOPLIST=""
EXTRA_PRIV=""
CGNAT=""
for H in $HOPS; do
  case "$H" in \*|"") continue ;; esac
  HOPLIST="$HOPLIST $H"
  [ "$H" = "${GATEWAY:-}" ] && continue
  if is_private "$H"; then
    case "$H" in
      100.*) CGNAT="$CGNAT $H" ;;
      *) EXTRA_PRIV="$EXTRA_PRIV $H" ;;
    esac
  fi
done
echo "  First hops:$HOPLIST"

if [ -z "$EXTRA_PRIV" ] && [ -z "$CGNAT" ]; then
  ok "Single NAT — only your router in the private path. Clean."
elif [ -n "$CGNAT" ] && [ -z "$EXTRA_PRIV" ]; then
  warn "CGNAT hop detected ($CGNAT) — your ISP NATs upstream. Not fixable on"
  warn "your end; only matters for inbound connections/port forwarding."
else
  # ONE finding, then unprefixed continuation lines. The explanation used to be
  # seven consecutive bad() calls, so neptune.sh's digest — which greps for the
  # [XX] prefix — counted seven findings for one problem and scattered sentence
  # fragments through the action list. A finding prefix marks a finding; prose
  # that elaborates on it must not carry one.
  bad "SECOND PRIVATE ROUTER in path:$EXTRA_PRIV (beyond your gateway ${GATEWAY:-?})"
  echo "       This usually means double NAT: ISP gateway in router mode in front of"
  echo "       your mesh. BUT ISP boxes in IP-passthrough mode can still echo their"
  echo "       private IP as a hop. Definitive test: check your router's WAN IP —"
  echo "         your public IP${PUBIP:+ ($PUBIP)} shown -> passthrough working, you're fine"
  echo "         192.168.x / 10.x shown    -> double NAT is real; enable bridge/IP-"
  echo "                                      passthrough on the ISP gateway"
fi

############################################################
# 3. DNS
############################################################
section "DNS"

DNS_SERVERS=$(scutil --dns 2>/dev/null | awk '/nameserver\[/{print $3}' | sort -u | tr '\n' ' ')
echo "  Servers: $DNS_SERVERS"
case "$DNS_SERVERS" in
  *"$GATEWAY"*) echo "  (Router is your resolver — normal for mesh setups; the ASUS forwards upstream)" ;;
esac

# Resolution timing (3 lookups, uncached domains vary)
for D in apple.com anthropic.com ableton.com; do
  T=$( { time dscacheutil -q host -a name "$D" >/dev/null; } 2>&1 | awk '/real/{print $2}')
  echo "  Resolve $D: ${T:-?}"
done

############################################################
# 4. Latency baseline
############################################################
section "Latency (idle baseline)"

if [ -n "${GATEWAY:-}" ]; then
  GW_PING=$(ping -c 5 -q "$GATEWAY" 2>/dev/null | awk -F/ '/round-trip|rtt/{print $5}')
  echo "  Gateway ($GATEWAY):  ${GW_PING:-?} ms avg"
  if [ -n "${GW_PING:-}" ] && awk "BEGIN{exit !($GW_PING > 10)}"; then
    warn "Gateway latency over 10ms on your own LAN (${GW_PING} ms)"
    echo "       If this is Wi-Fi, check mesh node placement/backhaul; if Ethernet,"
    echo "       that's unusual."
  fi
fi

NET_PING=$(ping -c 5 -q 1.1.1.1 2>/dev/null | awk -F/ '/round-trip|rtt/{print $5}')
echo "  Internet (1.1.1.1):  ${NET_PING:-?} ms avg"

echo
echo "  ${BOLD}Bufferbloat note:${RST} the numbers above are IDLE latency. Bufferbloat only"
echo "  shows up UNDER LOAD. To test properly, run the Waveform bufferbloat test"
echo "  (search 'waveform bufferbloat') in a browser — it measures latency during"
echo "  saturated up/download and grades A-F. If it grades C or worse, enable"
echo "  QoS/'Adaptive QoS' on the ASUS — that's the fix."

############################################################
# 5. Connection census — what's using the network right now
############################################################
section "Active connections by app"

# Deliberately NOT sudo. This script elevates nowhere else, and prompting for a
# password to list connections is a poor trade for a quick network check. The
# consequence is real and must be stated rather than left for the reader to
# discover: without root, lsof sees only THIS user's processes.
lsof -i -P -n 2>/dev/null | awk '$NF=="(ESTABLISHED)" {print $1}' | sort | uniq -c | sort -rn | head -15 | \
  awk '{printf "  %4d  %s\n", $1, $2}'

echo
warn "Unprivileged view: your own processes only. Root-owned daemons are NOT"
echo "       listed here — sentry.sh and redflag_scan.sh elevate and do cover them."
echo
echo "  High counts are normal for browsers and sync apps (Chrome, MEGAsync, Slack)."
echo "  What deserves a second look: apps you are NOT actively using holding many"
echo "  connections, or names you don't recognize at all."

echo
echo "${BOLD}Check complete.${RST} Read-only — nothing was changed."
