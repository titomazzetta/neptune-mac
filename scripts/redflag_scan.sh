#!/bin/bash
#
# redflag_scan.sh — Full-system red-flag scan for macOS
#
# One read-only run covering:
#   1. Security baseline        (SIP, Gatekeeper, Firewall, XProtect)
#   2. Persistence              (launch agents/daemons/helpers, signing-verified)
#   3. Other persistence paths  (cron, login hooks, startup items)
#   4. Running processes        (unsigned, or running from suspicious locations)
#   5. Network listeners        (every process accepting connections, signed?)
#   6. Traffic interception     (proxies, content filters, VPN/network extensions,
#                                config profiles — the MacKeeper StopAd category)
#   7. Browser extensions       (Safari app extensions, Chrome extensions)
#
# Everything suspicious is collected into a RED FLAG SUMMARY at the end,
# and the full report is saved to ~/Desktop/redflag_report_<date>.txt
# so it can be shared for review.
#
# Usage:  chmod +x redflag_scan.sh && ./redflag_scan.sh
#         (do not run with sudo; it elevates internally where needed)

set -u

BOLD=$(tput bold 2>/dev/null || true)
RED=$(tput setaf 1 2>/dev/null || true)
GRN=$(tput setaf 2 2>/dev/null || true)
YEL=$(tput setaf 3 2>/dev/null || true)
CYN=$(tput setaf 6 2>/dev/null || true)
RST=$(tput sgr0 2>/dev/null || true)

REPORT="$HOME/Desktop/redflag_report_$(date '+%Y-%m-%d_%H%M').txt"
FLAGS=()

# Print to screen AND report file
out() { echo "$@" | tee -a "$REPORT"; }
section() { out ""; out "== $* =="; }
flag() {
  FLAGS+=("$*")
  out "  ${RED}[FLAG]${RST} $*"
}
ok()   { out "  ${GRN}[ok]${RST} $*"; }
note() { out "  $*"; }

if [ "$(id -u)" -eq 0 ]; then
  echo "Run as your normal user, not with sudo."; exit 1
fi

: > "$REPORT"
out "${BOLD}Red-flag scan — $(hostname) — $(date '+%Y-%m-%d %H:%M')${RST}"
out "macOS $(sw_vers -productVersion) ($(sw_vers -buildVersion))"
sudo -v || exit 1
( while true; do sudo -n true 2>/dev/null; sleep 50; done ) & KA=$!
trap 'kill $KA 2>/dev/null' EXIT

# Helper: signing summary for a binary. Echoes "apple" / "signed:<authority>" / "unsigned" / "missing"
sig() {
  local BIN=$1
  [ -e "$BIN" ] || { echo "missing"; return; }
  if codesign -v "$BIN" 2>/dev/null; then
    local AUTH
    AUTH=$(codesign -dv "$BIN" 2>&1 | grep -m1 '^Authority=' | cut -d= -f2)
    case "$AUTH" in
      "Software Signing"|"Apple Mac OS Application Signing") echo "apple" ;;
      *) echo "signed:${AUTH:-unknown}" ;;
    esac
  else
    echo "unsigned"
  fi
}

############################################################
# 1. Security baseline
############################################################
section "Security baseline"

SIP=$(csrutil status 2>/dev/null)
case "$SIP" in
  *enabled*) ok "System Integrity Protection: enabled" ;;
  *) flag "System Integrity Protection is DISABLED — major weakening of macOS security: $SIP" ;;
esac

GK=$(spctl --status 2>/dev/null)
case "$GK" in
  *enabled*) ok "Gatekeeper: enabled" ;;
  *) flag "Gatekeeper is DISABLED — unsigned apps run without checks" ;;
esac

FW=$(sudo defaults read /Library/Preferences/com.apple.alf globalstate 2>/dev/null || echo "?")
case "$FW" in
  1|2) ok "Application firewall: enabled (state $FW)" ;;
  0) note "${YEL}Application firewall: off${RST} — common default, but worth enabling on laptops that join public Wi-Fi" ;;
  *) note "Application firewall state unknown" ;;
esac

XP=$(defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist CFBundleShortVersionString 2>/dev/null || echo "?")
note "XProtect definitions version: $XP"

############################################################
# 2. Launchd persistence with signing
############################################################
section "Launchd persistence (non-Apple)"

check_plists() {
  local DIR=$1
  [ -d "$DIR" ] || return 0
  local PLIST LABEL PROG S
  for PLIST in "$DIR"/*.plist; do
    [ -e "$PLIST" ] || continue
    LABEL=$(basename "$PLIST" .plist)
    case "$LABEL" in com.apple.*) continue ;; esac
    PROG=$(defaults read "$PLIST" ProgramArguments 2>/dev/null | sed -n 's/^[[:space:]]*"\{0,1\}\([^",]*\).*/\1/p' | head -2 | tail -1)
    [ -z "$PROG" ] && PROG=$(defaults read "$PLIST" Program 2>/dev/null)
    if [ -n "$PROG" ] && [ ! -e "$PROG" ] && command -v "$PROG" >/dev/null 2>&1; then
      PROG=$(command -v "$PROG")   # resolve bare names like "launchctl"
    fi
    S=$(sig "${PROG:-/nonexistent}")
    case "$S" in
      apple)     ok "$LABEL -> $PROG (Apple binary)" ;;
      signed:*)  ok "$LABEL -> ${PROG:-?} (${S#signed:})" ;;
      unsigned)  flag "UNSIGNED persistence: $LABEL runs $PROG ($PLIST)" ;;
      missing)
        if [ -n "$PROG" ]; then
          flag "ORPHANED persistence: $LABEL points at missing $PROG ($PLIST)"
        else
          note "${YEL}[?]${RST} $LABEL — could not resolve target ($PLIST)"
        fi ;;
    esac
  done
}
check_plists "$HOME/Library/LaunchAgents"
check_plists "/Library/LaunchAgents"
check_plists "/Library/LaunchDaemons"

note ""
note "Privileged helpers:"
for H in /Library/PrivilegedHelperTools/*; do
  [ -e "$H" ] || continue
  S=$(sig "$H")
  case "$S" in
    unsigned) flag "UNSIGNED privileged helper (runs as root): $H" ;;
    *) ok "$(basename "$H") ($S)" ;;
  esac
done

############################################################
# 3. Other persistence mechanisms
############################################################
section "Other persistence (cron, hooks, startup items)"

CRON=$(crontab -l 2>/dev/null)
if [ -n "$CRON" ]; then
  note "${YEL}User crontab present:${RST}"
  echo "$CRON" | sed 's/^/      /' | tee -a "$REPORT"
else
  ok "No user crontab"
fi

ROOTCRON=$(sudo crontab -l 2>/dev/null)
if [ -n "$ROOTCRON" ]; then
  flag "ROOT crontab present (unusual on modern macOS):"
  echo "$ROOTCRON" | sed 's/^/      /' | tee -a "$REPORT"
else
  ok "No root crontab"
fi

LHOOK=$(sudo defaults read com.apple.loginwindow LoginHook 2>/dev/null)
[ -n "${LHOOK:-}" ] && flag "Login hook configured (legacy mechanism, favored by malware): $LHOOK" || ok "No login hook"

if [ -d /Library/StartupItems ] && [ -n "$(ls -A /Library/StartupItems 2>/dev/null)" ]; then
  flag "Legacy StartupItems present (deprecated ~15 years — legitimate software no longer uses this): $(ls /Library/StartupItems | tr '\n' ' ')"
else
  ok "No legacy StartupItems"
fi

ETCCRON=$(grep -v '^#' /etc/crontab 2>/dev/null | grep -v '^\s*$' || true)
[ -n "$ETCCRON" ] && flag "/etc/crontab has entries (unusual): $ETCCRON" || ok "/etc/crontab clean"

############################################################
# 4. Suspicious running processes
############################################################
section "Running processes — location & signing spot-check"

# Processes executing from locations malware favors.
# NOTE: implemented in awk, not a shell case statement — macOS ships bash 3.2,
# which cannot parse `case` inside $() command substitution.
SUSP=$(ps axo pid=,comm= 2>/dev/null | awk -v home="$HOME" '
  { pid=$1; $1=""; sub(/^ /,""); c=$0 }
  c ~ /^\/(private\/)?tmp\// || c ~ /^\/(private\/)?var\/tmp\// || c ~ /^\/Users\/Shared\// || index(c, home "/Downloads/")==1 { print pid, c }')
if [ -n "$SUSP" ]; then
  while read -r LINE; do flag "Process running from suspicious location: $LINE"; done <<< "$SUSP"
else
  ok "No processes running from /tmp, Downloads, or /Users/Shared"
fi

############################################################
# 5. Network listeners
############################################################
section "Network listeners (processes accepting connections)"

while read -r NAME PID ADDR; do
  BIN=$(ps -p "$PID" -o comm= 2>/dev/null)
  S=$(sig "${BIN:-/nonexistent}")
  case "$ADDR" in
    127.0.0.1:*|\[::1\]:*) SCOPE="localhost-only" ;;
    *) SCOPE="${YEL}ALL INTERFACES${RST}" ;;
  esac
  case "$S" in
    apple)    ok "$NAME (pid $PID) on $ADDR [$SCOPE] — Apple" ;;
    signed:*) ok "$NAME (pid $PID) on $ADDR [$SCOPE] — ${S#signed:}" ;;
    *)
      case "$BIN" in
        /System/*|/usr/*) ok "$NAME (pid $PID) on $ADDR [$SCOPE] — system binary" ;;
        *) flag "Listener with unverifiable signature: $NAME (pid $PID) on $ADDR [$SCOPE] binary:${BIN:-?}" ;;
      esac ;;
  esac
done < <(sudo lsof -i -P -n 2>/dev/null | grep LISTEN | awk '{print $1, $2, $9}' | sort -u)

note ""
note "Listeners on ALL INTERFACES are reachable from your network — each should be"
note "something you recognize (file sharing, Docker, DAW link protocols, etc.)."

############################################################
# 6. Traffic interception — the MacKeeper StopAd category
############################################################
section "Traffic interception (proxies, filters, VPN/network extensions, profiles)"

# System-wide proxy settings
PROXY=$(scutil --proxy 2>/dev/null)
if echo "$PROXY" | grep -qE '(HTTPEnable|HTTPSEnable|SOCKSEnable|ProxyAutoConfigEnable)\s*:\s*1'; then
  flag "System proxy is ACTIVE — traffic is being routed through a proxy:"
  echo "$PROXY" | grep -E 'Enable|Proxy|Port' | sed 's/^/      /' | tee -a "$REPORT"
else
  ok "No system proxies enabled"
fi

# Content filters / VPN via system extensions
SYSEXT=$(systemextensionsctl list 2>/dev/null | grep -vE '^\s*(0|1|2|3|4|5|6|7|8|9)+ extension|^---|^enabled' | grep -E '\S' || true)
if systemextensionsctl list 2>/dev/null | grep -qiE 'network_extension|endpoint_security'; then
  note "${YEL}Network/Endpoint extensions registered — verify each is yours:${RST}"
  systemextensionsctl list 2>/dev/null | grep -iE 'network_extension|endpoint_security' -A5 | sed 's/^/      /' | tee -a "$REPORT"
else
  ok "No network-filter or endpoint-security extensions registered"
fi

# DNS override check
DNS=$(scutil --dns 2>/dev/null | grep -m4 'nameserver' | awk '{print $3}' | sort -u | tr '\n' ' ')
note "Active DNS servers: ${DNS:-unknown} (should match your router/VPN/chosen DNS)"

# Configuration profiles (MDM-style control)
PROFILES=$(sudo profiles list 2>/dev/null | grep -v "There are no" || true)
if [ -n "$PROFILES" ]; then
  flag "Configuration profiles installed (can enforce proxies/DNS/certs — verify each):"
  echo "$PROFILES" | sed 's/^/      /' | tee -a "$REPORT"
else
  ok "No configuration profiles installed"
fi

# /etc/hosts hijack check
HOSTS=$(grep -vE '^\s*#|^\s*$|localhost|broadcasthost|^::1' /etc/hosts 2>/dev/null || true)
if [ -n "$HOSTS" ]; then
  note "${YEL}Custom /etc/hosts entries (fine if you added them):${RST}"
  echo "$HOSTS" | sed 's/^/      /' | tee -a "$REPORT"
else
  ok "/etc/hosts is stock"
fi

############################################################
# 7. Browser extensions
############################################################
section "Browser extensions"

note "Safari app extensions (enabled state is managed in Safari settings):"
SAFARI_EXT=$(pluginkit -mAvvv -p com.apple.Safari.web-extension 2>/dev/null | grep -E 'Display Name|Path' || true)
if [ -n "$SAFARI_EXT" ]; then
  echo "$SAFARI_EXT" | sed 's/^/      /' | tee -a "$REPORT"
else
  note "      none found via pluginkit"
fi

if [ -d "$HOME/Library/Application Support/Google/Chrome" ]; then
  note ""
  note "Chrome extensions (by manifest name):"
  find "$HOME/Library/Application Support/Google/Chrome" -maxdepth 4 -name manifest.json -path "*Extensions*" 2>/dev/null | while read -r MF; do
    NAME=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1])).get('name',''))" "$MF" 2>/dev/null)
    case "$NAME" in __MSG_*|"") continue ;; esac
    echo "      $NAME" | tee -a "$REPORT"
  done | sort -u
fi

############################################################
# SUMMARY
############################################################
out ""
out "${BOLD}================ RED FLAG SUMMARY ================${RST}"
if [ ${#FLAGS[@]} -eq 0 ]; then
  out "${GRN}${BOLD}No red flags found.${RST} All persistence signed or accounted for,"
  out "no traffic interception, no suspicious processes or listeners."
else
  out "${RED}${BOLD}${#FLAGS[@]} item(s) flagged:${RST}"
  I=1
  for F in "${FLAGS[@]}"; do
    out "  $I. $F"
    I=$((I+1))
  done
  out ""
  out "Flags are leads, not verdicts — vendor quirks (Waves, Sonarworks, Docker)"
  out "routinely fail signature checks. Share this report for a second opinion."
fi
out ""
out "Full report saved to: $REPORT"
