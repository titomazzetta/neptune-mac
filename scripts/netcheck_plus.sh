#!/bin/bash
#
# netcheck_plus.sh — Deep network dial-in check for macOS + ASUS mesh
#
# Read-only. Four parts:
#   1. LOCAL HEALTH   — interface, latency (idle + under load), DNS, MTU, packet loss
#   2. WI-FI QUALITY  — signal, noise, tx rate, channel — the "why is it slow" layer
#   3. LAN CENSUS     — every device on your network, so you can spot the unknown one
#   4. ASUS AUDIT     — what to verify in the router GUI, with the CLI equivalent
#                       where the router's SSH is enabled
#
# Usage:   ./netcheck_plus.sh
#          ./netcheck_plus.sh --load   also runs an under-load latency test
#
# --load is the ONLY part of this script that touches the network beyond your
# own LAN and DNS. It saturates the link for ~8 seconds by pulling from a 100MB
# public test file and aborting; how much actually transfers depends on your
# line speed, so on a fast connection expect tens of megabytes. Don't run it on
# a metered or capped connection.

set -u

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

LOAD=false
[ "${1:-}" = "--load" ] && LOAD=true

# Same guard the other scripts carry (CLAUDE.md constraint 5): read-only scans
# have no reason to run as root, and running one under sudo would write any
# stray artefact as root.
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
if networksetup -listallhardwareports 2>/dev/null | grep -A2 "Wi-Fi" | grep -q "$IFACE"; then IS_WIFI=true; fi

note "Interface: ${IFACE:-?} ($($IS_WIFI && echo Wi-Fi || echo Ethernet))"
note "Local IP:  ${LOCALIP:-?}    Gateway: ${GATEWAY:-?}"

# MTU
MTU=$(ifconfig "${IFACE:-en0}" 2>/dev/null | awk '/mtu/{print $NF}')
note "MTU: ${MTU:-?} (1500 = standard; lower can mean fragmentation issues)"

# Idle latency + packet loss to gateway (20 pings)
if [ -n "${GATEWAY:-}" ]; then
  PING=$(ping -c 20 -q "$GATEWAY" 2>/dev/null)
  LOSS=$(echo "$PING" | awk -F',' '/packet loss/{print $3}' | grep -oE '[0-9.]+%')
  AVG=$(echo "$PING" | awk -F'/' '/avg/{print $5}')
  JITTER=$(echo "$PING" | awk -F'/' '/avg/{print $7}' | tr -d ' ms')
  note "Gateway: ${AVG:-?} ms avg   jitter: ${JITTER:-?} ms   loss: ${LOSS:-?}"
  awk "BEGIN{exit !(${AVG:-0} > 10)}" && warn "LAN latency >10ms — high for local; Wi-Fi interference or weak mesh link" || ok "LAN latency healthy"
  case "${LOSS:-0%}" in 0%|0.0%) ok "No packet loss to gateway" ;; *) bad "Packet loss to your own router (${LOSS}) — RF interference or failing link" ;; esac
fi

# Internet latency + DNS
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
  RSSI=$(echo "$WDATA" | awk -F': ' '/Signal \/ Noise/{print; exit}')
  RATE=$(echo "$WDATA" | awk -F': ' '/Transmit Rate/{print $2; exit}')
  CHAN=$(echo "$WDATA" | awk -F': ' '/^ *Channel/{print $2; exit}')
  PHY=$(echo "$WDATA"  | awk -F': ' '/PHY Mode/{print $2; exit}')
  note "PHY mode:      ${PHY:-?}   (want 802.11ax/Wi-Fi 6 or better)"
  note "Channel:       ${CHAN:-?}"
  note "Signal/Noise:  ${RSSI#*: }"
  note "Transmit rate: ${RATE:-?} Mbps"

  RSSI_NUM=$(echo "$WDATA" | awk -F': ' '/Signal \/ Noise/{print $2}' | grep -oE '\-[0-9]+' | head -1)
  if [ -n "${RSSI_NUM:-}" ]; then
    if [ "$RSSI_NUM" -ge -60 ]; then ok "Signal strong (${RSSI_NUM} dBm)"
    elif [ "$RSSI_NUM" -ge -70 ]; then warn "Signal moderate (${RSSI_NUM} dBm) — a mesh node closer would help"
    else bad "Signal weak (${RSSI_NUM} dBm) — this alone explains slow/latent Wi-Fi"; fi
  fi
  note ""
  note "${BOLD}The single biggest win for a Mac Studio: wire it.${RST} A desktop that never"
  note "moves has no reason to be on Wi-Fi — Ethernet to the nearest node drops"
  note "LAN latency to ~1ms and frees airtime for devices that actually roam."
else
  section "2. Connection type"
  ok "On Ethernet — ideal for a desktop. No Wi-Fi quality concerns."
fi

############################################################
# 3. Under-load latency (bufferbloat) — optional
############################################################
if $LOAD; then
  section "3. Bufferbloat (latency under load)"
  note "Measuring idle vs loaded latency (saturating the link for ~8s; the"
  note "transfer is aborted after, so volume scales with your line speed)..."
  IDLE=$(ping -c 5 -q "${GATEWAY:-1.1.1.1}" 2>/dev/null | awk -F'/' '/avg/{print $5}')
  # Start a background download to saturate the link
  curl -s -o /dev/null "https://speed.hetzner.de/100MB.bin" &
  DLPID=$!
  sleep 1
  LOADED=$(ping -c 8 -q "${GATEWAY:-1.1.1.1}" 2>/dev/null | awk -F'/' '/avg/{print $5}')
  kill $DLPID 2>/dev/null
  note "Idle latency:   ${IDLE:-?} ms"
  note "Loaded latency: ${LOADED:-?} ms"
  if [ -n "${IDLE:-}" ] && [ -n "${LOADED:-}" ]; then
    BLOAT=$(awk "BEGIN{printf \"%.0f\", ${LOADED}-${IDLE}}")
    if [ "$BLOAT" -lt 30 ]; then ok "Bufferbloat +${BLOAT}ms — excellent (QoS working or not needed)"
    elif [ "$BLOAT" -lt 100 ]; then warn "Bufferbloat +${BLOAT}ms — noticeable; enable Adaptive QoS on the ASUS"
    else bad "Bufferbloat +${BLOAT}ms — severe; Adaptive QoS on the ASUS will transform responsiveness"; fi
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
note "Populating ARP table (pinging your subnet)..."
SUBNET=$(echo "${LOCALIP:-192.168.50.0}" | cut -d. -f1-3)

# Throttled sweep. The previous version launched all 254 pings at once and then
# just slept 3 seconds — a needless fork storm that never actually waited, so a
# slow responder could land in the ARP table after the census had been read.
# Batches of 32 with an explicit wait: bounded, and the table is complete before
# it is read.
i=1
while [ "$i" -le 254 ]; do
  j=0
  while [ "$j" -lt 32 ] && [ "$i" -le 254 ]; do
    ping -c1 -t1 "${SUBNET}.$i" >/dev/null 2>&1 &
    i=$((i + 1)); j=$((j + 1))
  done
  wait
done

# macOS `arp` formats MACs with ether_ntoa(), which does NOT zero-pad octets:
# a real entry can read 8:0:27:a:b:c (13 chars), not only 3c:7c:3f:1a:2b:cc
# (17). Matching a fixed {17} silently dropped every device with a single-digit
# octet — in a census whose entire purpose is "spot the device you can't
# place", the dropped rows are the ones that matter.
CENSUS=$(arp -an | grep "(${SUBNET}\." | while read -r line; do
  IP=$(echo "$line" | grep -oE '\([0-9.]+\)' | tr -d '()')
  MAC=$(echo "$line" | grep -oiE '([0-9a-f]{1,2}:){5}[0-9a-f]{1,2}')
  [ -z "$MAC" ] && continue
  printf "  %-16s %-20s\n" "$IP" "$MAC"
done | sort -t. -k4 -n)

echo
printf "  %-16s %-20s\n" "IP" "MAC"
[ -n "$CENSUS" ] && echo "$CENSUS"

# Count the rows actually shown. Counting raw `arp` lines included
# "(incomplete)" entries, so the total disagreed with the table beneath it.
COUNT=$(printf '%s' "$CENSUS" | grep -c ':' || true)
echo
note "${COUNT} device(s) responded. Match each to something you own. An IP+MAC"
note "you can't place is worth investigating in the ASUS client list, which shows"
note "device names the raw ARP table can't."

############################################################
# 5. ASUS settings audit
############################################################
section "5. ASUS router settings to verify (GUI: router.asus.com)"
cat <<'EOF'
  Log into router.asus.com and confirm each. High-impact ones first:

  SPEED / EFFICIENCY
    - Adaptive QoS > enable ONLY if bufferbloat above was noticeable
    - Wireless > confirm 160MHz channel width on 5GHz (if devices support it)
    - Wireless > Smart Connect on (lets the mesh steer devices to best band)
    - Ethernet backhaul: if nodes are wired to each other, confirm GUI shows
      "Wired" backhaul — wireless backhaul halves throughput at the far node
    - Firmware > update if one is available

  SECURITY
    - Administration > "Enable Web Access from WAN" = OFF
    - WPA2/WPA3 Personal encryption; disable WPS (clear the AP PIN)
    - Protected Management Frames = Capable (hardens against deauth floods)
    - AiProtection ON — flags devices contacting malicious hosts
    - Guest Network for IoT/visitors, intranet access OFF
    - Review the client list; block any device you can't identify

  DNS
    - WAN > DNS: 1.1.1.1 / 1.0.0.1 or 8.8.8.8 if the ISP resolver is slow
EOF

echo
note "${BOLD}If the ASUS has SSH enabled${RST} (Administration > System > Enable SSH),"
note "read-only diagnostics from Terminal:  ssh admin@${GATEWAY:-192.168.50.1}"
note "  nvram get wl1_chanspec   (5GHz channel)   cat /proc/loadavg  (router load)"

echo
echo "${BOLD}Check complete.${RST} Read-only — nothing was changed."
