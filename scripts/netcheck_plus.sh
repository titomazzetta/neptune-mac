#!/bin/bash
#
# netcheck_plus.sh — Deep network dial-in check for macOS and your home router
#
# Read-only. Five parts:
#   1. LOCAL HEALTH   — interface, latency, DNS, MTU, packet loss
#   2. WI-FI QUALITY  — signal, noise, tx rate, channel — the "why is it slow" layer
#   3. BUFFERBLOAT    — latency under load (only with --load)
#   4. LAN CENSUS     — every device on your network, so you can spot the unknown one
#   5. ROUTER AUDIT   — what to verify in your router's admin page
#
# Usage:   ./netcheck_plus.sh
#          ./netcheck_plus.sh --load   also measures latency under load
#
# Standalone on purpose: it is not part of neptune.sh, because the census pings
# every address on your subnet and that should be something you choose to do.
#
# --load is the ONLY part that reaches beyond your LAN, DNS and one ping target.
# It saturates the link for up to 8 seconds by downloading from Cloudflare's
# public speed-test endpoint (no account, nothing identifying sent) and then
# stops — on a fast line expect up to 100 MB. Skip it on a metered connection.

set -u
export LC_ALL=C   # byte-safe text tools on macOS — see the note in neptune.sh

BOLD=$(tput bold 2>/dev/null || true)
RED=$(tput setaf 1 2>/dev/null || true)
GRN=$(tput setaf 2 2>/dev/null || true)
YEL=$(tput setaf 3 2>/dev/null || true)
CYN=$(tput setaf 6 2>/dev/null || true)
RST=$(tput sgr0 2>/dev/null || true)

section() { echo; echo "${BOLD}${CYN}== $* ==${RST}"; }
ok()   { echo "  ${GRN}[ok]${RST} $*"; }
warn() { echo "  ${YEL}[!!]${RST} $*"; }
bad()  { echo "  ${RED}[XX]${RST} $*"; }
note() { echo "  $*"; }

# gt <a> <b> — numeric a > b for decimal strings; false if either is empty.
# Values go in with -v, never pasted into the awk program text.
gt() { [ -n "$1" ] && [ -n "$2" ] && awk -v a="$1" -v b="$2" 'BEGIN { exit !(a + 0 > b + 0) }'; }

# mac_kind <mac> — "private" when the locally-administered bit is set (second
# hex digit 2, 6, A or E). Phones, tablets and Macs use a randomized address per
# network by default, so an unrecognizable MAC with this bit is usually a device
# you own with Private Wi-Fi Address on — not an intruder.
mac_kind() {
  printf '%s' "$1" | awk -F: '{ o = $1; if (length(o) == 1) o = "0" o
                               d = toupper(substr(o, 2, 1))
                               if (d == "2" || d == "6" || d == "A" || d == "E") print "private" }'
}

[ "${NEPTUNE_LIB:-}" = "1" ] && return 0

LOAD=false
case "${1:-}" in
  "") ;;
  --load) LOAD=true ;;
  -h|--help) sed -n '3,21p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  *) echo "Unknown option: $1  (try --help)"; exit 64 ;;
esac

# Same guard the other scripts carry (CLAUDE.md constraint 5).
if [ "$(id -u)" -eq 0 ]; then
  echo "Run as your normal user, not with sudo."; exit 1
fi

echo "${BOLD}Network dial-in check — $(date '+%Y-%m-%d %H:%M')${RST}"

############################################################
# 1. Local health
############################################################
section "1. Local network health"

IFACE=$(route -n get default 2>/dev/null | awk '/interface/{print $2}')
GATEWAY=$(route -n get default 2>/dev/null | awk '/gateway/{print $2}')
LOCALIP=$(ipconfig getifaddr "${IFACE:-en0}" 2>/dev/null)
IS_WIFI=false
if [ -n "$IFACE" ] && networksetup -listallhardwareports 2>/dev/null | grep -A2 "Wi-Fi" | grep -qw "$IFACE"; then IS_WIFI=true; fi

if $IS_WIFI; then KIND=Wi-Fi; else KIND=wired; fi
note "Interface: ${IFACE:-?} ($KIND)"
note "Local IP:  ${LOCALIP:-?}    Gateway: ${GATEWAY:-?}"

MTU=$(ifconfig "${IFACE:-en0}" 2>/dev/null | awk '/mtu/{print $NF; exit}')
note "MTU: ${MTU:-?} (1500 = standard; lower can mean a VPN or fragmentation)"

if [ -n "${GATEWAY:-}" ]; then
  PING=$(ping -c 20 -q "$GATEWAY" 2>/dev/null)
  # By pattern, not by comma field: with duplicate replies macOS inserts
  # "+K duplicates," and the third field is no longer the loss.
  LOSS=$(printf '%s\n' "$PING" | grep -oE '[0-9.]+% packet loss' | cut -d' ' -f1)
  AVG=$(printf '%s\n' "$PING" | awk -F'/' '/avg/{print $5}')
  JITTER=$(printf '%s\n' "$PING" | awk -F'/' '/avg/{print $7}' | tr -d ' ms')
  note "Gateway: ${AVG:-?} ms avg   jitter: ${JITTER:-?} ms   loss: ${LOSS:-?}"
  if [ -z "${AVG:-}" ]; then
    warn "The router did not answer pings (some block them) — latency and loss unknown"
  else
    if gt "$AVG" 10; then warn "LAN latency >10ms — high for one local hop; Wi-Fi interference or a weak mesh link"
    else ok "LAN latency healthy"; fi
    case "${LOSS:-}" in
      "") warn "Could not read packet loss from ping's summary" ;;
      0%|0.0%) ok "No packet loss to the router" ;;
      *) bad "Packet loss to your own router (${LOSS}) — RF interference or a failing link" ;;
    esac
  fi
fi

INET=$(ping -c 10 -q 1.1.1.1 2>/dev/null | awk -F'/' '/avg/{print $5}')
note "Internet (1.1.1.1): ${INET:-?} ms avg"
for D in apple.com google.com cloudflare.com; do
  T=$( { /usr/bin/time -p dscacheutil -q host -a name "$D" >/dev/null; } 2>&1 | awk '/real/{print $2}')
  echo "    DNS $D: ${T:-?}s"
done

############################################################
# 2. Wi-Fi signal quality (the "why slow" layer)
############################################################
if $IS_WIFI; then
  section "2. Wi-Fi signal quality"
  WDATA=$(system_profiler SPAirPortDataType 2>/dev/null)
  SN=$(printf '%s\n' "$WDATA" | awk -F': ' '/Signal \/ Noise/{print $2; exit}')
  RATE=$(printf '%s\n' "$WDATA" | awk -F': ' '/Transmit Rate/{print $2; exit}')
  CHAN=$(printf '%s\n' "$WDATA" | awk -F': ' '/^ *Channel/{print $2; exit}')
  PHY=$(printf '%s\n' "$WDATA"  | awk -F': ' '/PHY Mode/{print $2; exit}')
  note "PHY mode:      ${PHY:-?}   (802.11ax / Wi-Fi 6 or newer is current)"
  note "Channel:       ${CHAN:-?}"
  note "Signal/Noise:  ${SN:-?}"
  note "Transmit rate: ${RATE:-?} Mbps"

  RSSI=$(printf '%s' "$SN" | grep -oE -- '-[0-9]+' | head -1)
  if [ -n "${RSSI:-}" ]; then
    if [ "$RSSI" -ge -60 ]; then ok "Signal strong (${RSSI} dBm)"
    elif [ "$RSSI" -ge -70 ]; then warn "Signal moderate (${RSSI} dBm) — a closer router or mesh node would help"
    else bad "Signal weak (${RSSI} dBm) — this alone explains slow or laggy Wi-Fi"; fi
  fi
  if ! system_profiler SPHardwareDataType 2>/dev/null | grep -q 'Model Name: .*Book'; then
    note ""
    note "${BOLD}The single biggest win for a desktop Mac: wire it.${RST} A machine that never"
    note "moves has no reason to be on Wi-Fi — Ethernet to the nearest router or node"
    note "drops LAN latency to ~1ms and frees airtime for devices that actually roam."
  fi
else
  section "2. Connection type"
  ok "On a wired connection — no Wi-Fi quality concerns."
fi

############################################################
# 3. Under-load latency (bufferbloat) — optional
############################################################
if $LOAD; then
  section "3. Bufferbloat (latency under load)"
  # Bufferbloat lives at the slowest hop — usually the modem / ISP link — so the
  # target is a host beyond it. Pinging the router would only measure the LAN.
  TARGET=1.1.1.1
  note "Idle vs loaded latency to $TARGET (saturating the link for up to 8s)..."
  IDLE=$(ping -c 5 -q "$TARGET" 2>/dev/null | awk -F'/' '/avg/{print $5}')
  GOT=$(mktemp "${TMPDIR:-/tmp}/neptune-load.XXXXXX")
  curl -s --max-time 8 -o /dev/null -w '%{size_download}' \
    "https://speed.cloudflare.com/__down?bytes=100000000" > "$GOT" 2>/dev/null &
  DLPID=$!
  sleep 1
  LOADED=$(ping -c 6 -q "$TARGET" 2>/dev/null | awk -F'/' '/avg/{print $5}')
  wait "$DLPID" 2>/dev/null
  BYTES=$(tr -dc '0-9' < "$GOT"); rm -f "$GOT"
  BYTES=${BYTES:-0}
  MB=$(awk -v b="$BYTES" 'BEGIN { printf "%.0f", b / 1000000 }')
  note "Idle latency:   ${IDLE:-?} ms"
  note "Loaded latency: ${LOADED:-?} ms   (while downloading ${MB} MB)"
  # A load test that never loaded the link would report "no bufferbloat" with a
  # straight face. Under 1 MB transferred means the download failed or was
  # blocked, so there is no comparison to make.
  if [ "$BYTES" -lt 1000000 ]; then
    warn "The test download never got going (${BYTES} bytes) — no result; try again later"
  elif [ -n "${IDLE:-}" ] && [ -n "${LOADED:-}" ]; then
    BLOAT=$(awk -v l="$LOADED" -v i="$IDLE" 'BEGIN { printf "%.0f", l - i }')
    if [ "$BLOAT" -lt 30 ]; then ok "Bufferbloat +${BLOAT}ms — excellent (queue management working, or not needed)"
    elif [ "$BLOAT" -lt 100 ]; then warn "Bufferbloat +${BLOAT}ms — noticeable; turn on your router's QoS / Smart Queue (SQM)"
    else bad "Bufferbloat +${BLOAT}ms — severe; QoS / SQM on the router will transform responsiveness"; fi
  else
    warn "Could not measure latency to $TARGET — no result"
  fi
else
  section "3. Bufferbloat"
  note "Skipped. Re-run with --load to measure latency under saturation,"
  note "or use the Waveform bufferbloat test in a browser for a graded result."
fi

############################################################
# 4. LAN device census
############################################################
section "4. LAN device census (who's on your network)"
SUBNET=""
if [ -z "${LOCALIP:-}" ]; then
  # No hardcoded fallback subnet: guessing one would mean sending 254 pings to
  # a network you may not even be on. No local address is information.
  warn "No local IP detected — device census skipped"
  note "     Without a confirmed local address there is no way to know which subnet"
  note "     to sweep. Check the interface report above."
else
  note "Populating the ARP table (pinging your /24, 32 at a time)..."
  SUBNET=$(printf '%s' "$LOCALIP" | cut -d. -f1-3)
fi

if [ -n "$SUBNET" ]; then
  # Throttled sweep: batches of 32 with an explicit wait, so the table is
  # complete before it is read and there is no 254-process fork storm.
  i=1
  while [ "$i" -le 254 ]; do
    j=0
    while [ "$j" -lt 32 ] && [ "$i" -le 254 ]; do
      ping -c1 -t1 "${SUBNET}.$i" >/dev/null 2>&1 &
      i=$((i + 1)); j=$((j + 1))
    done
    wait
  done

  # macOS `arp` prints MACs without zero-padding (8:0:27:a:b:c), so the match
  # accepts one- or two-digit octets; a fixed {17} would drop exactly the odd
  # devices this census exists to surface.
  CENSUS=$(arp -an | grep "(${SUBNET}\." | while read -r line; do
    IP=$(printf '%s' "$line" | grep -oE '\([0-9.]+\)' | tr -d '()')
    MAC=$(printf '%s' "$line" | grep -oiE '([0-9a-f]{1,2}:){5}[0-9a-f]{1,2}')
    [ -z "$MAC" ] && continue
    NOTE=""
    [ "$(mac_kind "$MAC")" = "private" ] && NOTE="private (randomized) address"
    [ "$IP" = "${GATEWAY:-}" ] && NOTE="your router"
    [ "$IP" = "${LOCALIP:-}" ] && NOTE="this Mac"
    printf "  %-16s %-20s %s\n" "$IP" "$MAC" "$NOTE"
  done | sort -t. -k4 -n)

  echo
  printf "  %-16s %-20s %s\n" "IP" "MAC" "NOTE"
  [ -n "$CENSUS" ] && printf '%s\n' "$CENSUS"
  COUNT=$(printf '%s' "$CENSUS" | grep -c ':' || true)
  echo
  note "${COUNT} device(s) in the table. Match each to"
  note "something you own. \"private\" addresses are usually phones and laptops with"
  note "Private Wi-Fi Address on; your router's client list shows their names."
fi

############################################################
# 5. Router settings audit
############################################################
section "5. Router settings to verify"
cat <<'EOF'
  Open your router's admin page or app (its address is the gateway above) and
  confirm each. Names vary by brand; the setting is the same. Security first:

  SECURITY
    - Remote / WAN administration OFF — manage it from inside your network only
    - Admin password changed from the default; firmware auto-update ON if offered
    - Wi-Fi security WPA3, or WPA2/WPA3 mixed; WPS OFF
    - Protected Management Frames (802.11w) = Capable or Required
    - UPnP OFF unless a console or game needs it — it lets any device on the
      LAN open ports to the internet without asking you
    - Guest network for visitors and smart-home gear, with LAN access OFF
    - Review the client list; block anything nobody in the house can identify

  SPEED
    - QoS / Smart Queue (SQM) ON only if --load showed noticeable bufferbloat
    - Mesh: if nodes are cabled together, confirm the backhaul shows as wired —
      a wireless backhaul roughly halves throughput at the far node
    - Band steering / smart connect ON, so devices land on the best band
EOF

echo
echo "${BOLD}Check complete.${RST} Read-only — nothing was changed."
