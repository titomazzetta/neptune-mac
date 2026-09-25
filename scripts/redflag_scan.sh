#!/bin/bash
#
# redflag_scan.sh — Full-system red-flag scan for macOS
#
# One read-only run covering:
#   1. Security posture         (FileVault, SIP, Gatekeeper, firewall,
#                                automatic security updates, guest, auto-login)
#   2. Launchd persistence      (every third-party agent/daemon/helper, signed?)
#   3. Other persistence        (cron, login hooks, startup items)
#   4. Running processes        (odd locations, hidden folders, deleted binaries,
#                                unverified code running as root)
#   5. Network listeners        (who accepts connections, signed?, remote access)
#   6. Traffic interception     (proxies, network extensions, profiles, hosts)
#   7. Browser extensions       (Chromium-family, with the two permissions that
#                                can see or reroute everything)
#
# Everything suspicious is collected into a RED FLAG SUMMARY at the end, and the
# full report is saved to ~/Desktop/redflag_report_<date>.txt.
#
# Usage:  ./redflag_scan.sh     (do not run with sudo; it elevates where needed)

set -u
export LC_ALL=C   # byte-safe text tools on macOS — see the note in neptune.sh

BOLD=$(tput bold 2>/dev/null || true)
RED=$(tput setaf 1 2>/dev/null || true)
GRN=$(tput setaf 2 2>/dev/null || true)
YEL=$(tput setaf 3 2>/dev/null || true)
RST=$(tput sgr0 2>/dev/null || true)

DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"   # BASH_SOURCE: correct when sourced by tests too
REPORT="${NEPTUNE_REPORT_DIR:-$HOME/Desktop}/redflag_report_$(date '+%Y-%m-%d_%H%M').txt"
FLAGS=()

# Structured result records — see the record format in neptune.sh. No-op unless
# neptune.sh sets NEPTUNE_FINDINGS, so a standalone run is unchanged. Duplicated
# into each scan on purpose: the scans stay independently runnable.
SCAN=redflag
CATEGORY=security
CHECK=""
record() {
  [ -n "${NEPTUNE_FINDINGS:-}" ] || return 0
  printf '%s|%s|%s|%s|%s\n' "$1" "$CATEGORY" "$SCAN" "$CHECK" \
    "$(printf '%s' "$2" | tr '|\t\n' '/  ')" >> "$NEPTUNE_FINDINGS"
}

out()     { echo "$@" | tee -a "$REPORT"; }
section() { out ""; out "== $* =="; }
ok()      { out "  ${GRN}[ok]${RST} $*"; }                        # prints only
pass()    { out "  ${GRN}[ok]${RST} $*"; record pass "$*"; }      # a check that ran clean
note()    { out "  $*"; }
flag()    { FLAGS+=("$*"); out "  ${RED}[FLAG]${RST} $*"; record attention "$*"; }
warn()    { out "  ${YEL}[!!]${RST} $*"; record notice "$*"; }
unknown() { out "  ${YEL}[!!]${RST} $*"; record unknown "$*"; }

# sig <path> — who signed this, in five classes:
#
#   apple         signed by Apple
#   signed:<who>  signed by an identified developer (Developer ID etc.)
#   adhoc         a valid signature that names NO signer
#   unsigned      no valid signature
#   missing       no such file
#
# "adhoc" is its own class because it used to fall through as "signed:unknown"
# and pass. On Apple silicon every executable must carry at least an ad-hoc
# signature, which anyone can produce with one command, and `codesign -v`
# accepts it as valid. An ad-hoc signature proves the file has not changed since
# it was signed; it says nothing about who wrote it. Commodity Mac malware ships
# exactly like that — so a persistence check that treats it as "signed" is blind
# to the thing it most needs to see (DEVLOG Bug 16).
sig() {
  local BIN=$1 INFO AUTH
  [ -e "$BIN" ] || { echo "missing"; return; }
  if ! codesign -v "$BIN" 2>/dev/null; then echo "unsigned"; return; fi
  INFO=$(codesign -dvv "$BIN" 2>&1)
  case "$INFO" in *"Signature=adhoc"*) echo "adhoc"; return ;; esac
  AUTH=$(printf '%s\n' "$INFO" | grep -m1 '^Authority=' | cut -d= -f2)
  case "$AUTH" in
    "Software Signing"|"Apple Mac OS Application Signing") echo "apple" ;;
    "") echo "adhoc" ;;
    *) echo "signed:$AUTH" ;;
  esac
}

# plist_target <plist> — the executable launchd will actually run.
#
# launchd runs `Program` if it is set, and ProgramArguments[0] otherwise. The old
# code read the text output of `defaults read` with sed, checked
# ProgramArguments first, and on some plists came back empty — so the item was
# reported as "could not resolve target" and never had its signature checked.
# PlistBuddy reads binary and XML plists alike and has shipped since 10.5.
plist_target() {
  local PL=$1 PB=/usr/libexec/PlistBuddy P
  P=$("$PB" -c 'Print :Program' "$PL" 2>/dev/null)
  [ -n "$P" ] || P=$("$PB" -c 'Print :ProgramArguments:0' "$PL" 2>/dev/null)
  if [ -z "$P" ] && [ ! -r "$PL" ]; then
    P=$(sudo -n "$PB" -c 'Print :Program' "$PL" 2>/dev/null)
    [ -n "$P" ] || P=$(sudo -n "$PB" -c 'Print :ProgramArguments:0' "$PL" 2>/dev/null)
  fi
  # A bare command name ("launchctl", "open") rather than a path.
  if [ -n "$P" ] && [ ! -e "$P" ] && command -v "$P" >/dev/null 2>&1; then
    P=$(command -v "$P")
  fi
  printf '%s' "$P"
}

# is_system_path <path> — inside the SIP-protected, Apple-only part of the disk.
is_system_path() {
  case "$1" in
    /usr/local/*) return 1 ;;
    /System/*|/usr/*|/bin/*|/sbin/*|/Library/Apple/*|/private/var/db/*) return 0 ;;
  esac
  return 1
}

# sig_word <class> — how a signing class reads in a finding title.
sig_word() { case "$1" in adhoc) echo "AD-HOC SIGNED" ;; unsigned) echo "UNSIGNED" ;; *) echo "$1" ;; esac; }

# Known listening ports, so a report says "Remote Login (SSH)" instead of
# "launchd on *:22". Only the first group is a finding when exposed to the
# network; the second is labelled for the reader and left alone.
port_label() {
  case "$1" in
    22)   echo "Remote Login (SSH)|remote" ;;
    5900) echo "Screen Sharing|remote" ;;
    3283) echo "Remote Management (ARD)|remote" ;;
    445)  echo "File Sharing (SMB)|remote" ;;
    548)  echo "File Sharing (AFP)|remote" ;;
    5000|7000) echo "AirPlay Receiver|label" ;;
    631)  echo "Printer Sharing|label" ;;
    3689) echo "Media Sharing|label" ;;
    *)    echo "" ;;
  esac
}

# covered_by_flag <path> (reads FLAGGED_BINS) — the path, or anything inside it (a helper .app bundle
# whose executable a launch item runs), was already reported under another
# heading. Used so one unsigned helper is one finding, not two (DEVLOG Bug 17).
covered_by_flag() {
  printf '%s\n' "$FLAGGED_BINS" | P="$1" awk '$0 == ENVIRON["P"] || index($0, ENVIRON["P"] "/") == 1 { f = 1 } END { exit !f }'
}

# ---------------------------------------------------------------------------
# Sourced by tests with NEPTUNE_LIB=1 to exercise the pure functions above
# against captured fixtures. Nothing below this line runs when sourced.
# ---------------------------------------------------------------------------
[ "${NEPTUNE_LIB:-}" = "1" ] && return 0

if [ "$(id -u)" -eq 0 ]; then
  echo "Run as your normal user, not with sudo."; exit 1
fi

mkdir -p "$(dirname "$REPORT")"
: > "$REPORT"
out "${BOLD}Red-flag scan — $(hostname) — $(date '+%Y-%m-%d %H:%M')${RST}"
out "macOS $(sw_vers -productVersion) ($(sw_vers -buildVersion))"
sudo -v || exit 1
# Keep-alive for the cached sudo credential. Its output is detached: the loop's
# `sleep` outlives a kill of the loop by up to 50 s, and while it holds this
# script's stdout, `neptune.sh`'s `| tee` waits for it (found in review).
( while true; do sudo -n true 2>/dev/null; sleep 50; done ) >/dev/null 2>&1 </dev/null & KA=$!
trap 'kill $KA 2>/dev/null' EXIT

# Binaries already flagged, one per line, so the same unverified binary is not
# reported again by a later check that sees it from a different angle.
FLAGGED_BINS=""
mark_flagged() { FLAGGED_BINS="$FLAGGED_BINS
$1"; }
already_flagged() { printf '%s\n' "$FLAGGED_BINS" | grep -qxF "$1"; }

############################################################
# 1. Security posture
############################################################
section "Security posture"

CHECK=filevault
FV=$(fdesetup status 2>/dev/null)
case "$FV" in
  *"Decryption in progress"*) flag "FileVault is being turned OFF — the startup disk is decrypting" ;;
  *"Encryption in progress"*) pass "FileVault is on (encryption still in progress)" ;;
  *"FileVault is On"*)        pass "FileVault disk encryption is on" ;;
  *"FileVault is Off"*)       flag "FileVault is OFF — the startup disk is not encrypted" ;;
  *)                          unknown "FileVault state could not be determined (fdesetup gave no answer)" ;;
esac

CHECK=sip
SIP=$(csrutil status 2>/dev/null)
case "$SIP" in
  *"status: enabled"*) pass "System Integrity Protection is enabled" ;;
  *disabled*)          flag "System Integrity Protection is DISABLED — root can modify macOS itself" ;;
  *)                   unknown "System Integrity Protection state could not be determined" ;;
esac

CHECK=gatekeeper
GK=$(spctl --status 2>/dev/null)
case "$GK" in
  *"assessments enabled"*)  pass "Gatekeeper is enabled" ;;
  *"assessments disabled"*) flag "Gatekeeper is DISABLED — unsigned apps open without any check" ;;
  *)                        unknown "Gatekeeper state could not be determined" ;;
esac

# Ask socketfilterfw first — the supported interface. The com.apple.alf plist is
# not a reliable source on current macOS. A check that cannot run says so.
CHECK=firewall
FW_STATE=""
SFW=/usr/libexec/ApplicationFirewall/socketfilterfw
if [ -x "$SFW" ]; then
  case "$("$SFW" --getglobalstate 2>/dev/null)" in
    *disabled*) FW_STATE=off ;;
    *enabled*)  FW_STATE=on ;;
  esac
fi
if [ -z "$FW_STATE" ]; then
  case "$(sudo defaults read /Library/Preferences/com.apple.alf globalstate 2>/dev/null)" in
    1|2) FW_STATE=on ;;
    0)   FW_STATE=off ;;
  esac
fi
case "$FW_STATE" in
  on)  pass "Application firewall is enabled" ;;
  off) warn "Application firewall is OFF — a common default, but worth enabling on any machine that joins public Wi-Fi" ;;
  *)   unknown "Application firewall state could not be determined (socketfilterfw and com.apple.alf both unreadable)" ;;
esac

# Automatic updates. An ABSENT key means Apple's default, which is on — so only
# an explicit 0 is a finding. Reading "no answer" as "off" would flag every
# machine that has never touched the setting.
SU=/Library/Preferences/com.apple.SoftwareUpdate
su_key() { defaults read "$SU" "$1" 2>/dev/null; }
CHECK=auto-security-updates
if [ "$(su_key CriticalUpdateInstall)" = "0" ] || [ "$(su_key ConfigDataInstall)" = "0" ]; then
  flag "Automatic installation of security responses and XProtect definitions is turned OFF"
else
  pass "Security responses and XProtect definitions install automatically"
fi
CHECK=auto-update-check
if [ "$(su_key AutomaticCheckEnabled)" = "0" ]; then
  warn "macOS is not checking for software updates automatically"
else
  pass "macOS checks for software updates automatically"
fi

LW=/Library/Preferences/com.apple.loginwindow
CHECK=auto-login
ALU=$(defaults read "$LW" autoLoginUser 2>/dev/null)
if [ -n "$ALU" ]; then
  flag "Automatic login is ON for account '$ALU' — anyone who starts this Mac is at its desktop"
else
  pass "Automatic login is off"
fi
CHECK=guest-account
if [ "$(defaults read "$LW" GuestEnabled 2>/dev/null)" = "1" ]; then
  warn "The Guest account is enabled — a password-free login on this Mac"
else
  pass "The Guest account is disabled"
fi

XP=$(defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist CFBundleShortVersionString 2>/dev/null || echo "?")
note "XProtect definitions version: $XP"

############################################################
# 2. Launchd persistence with signing
############################################################
section "Launchd persistence (non-Apple)"

PERSIST_TOTAL=0
PERSIST_PROBLEMS=0
check_plists() {
  local DIRP=$1 PLIST LABEL PROG S
  [ -d "$DIRP" ] || return 0
  for PLIST in "$DIRP"/*.plist; do
    [ -e "$PLIST" ] || continue
    LABEL=$(basename "$PLIST" .plist)
    case "$LABEL" in com.apple.*) continue ;; esac
    PERSIST_TOTAL=$((PERSIST_TOTAL + 1))
    PROG=$(plist_target "$PLIST")
    S=$(sig "${PROG:-/nonexistent}")
    case "$S" in
      apple)    ok "$LABEL -> $PROG (Apple)" ;;
      signed:*) ok "$LABEL -> $PROG (${S#signed:})" ;;
      adhoc)
        PERSIST_PROBLEMS=$((PERSIST_PROBLEMS + 1)); CHECK=persistence-launchd
        flag "AD-HOC SIGNED persistence: $LABEL runs $PROG ($PLIST)"
        mark_flagged "$PROG" ;;
      unsigned)
        PERSIST_PROBLEMS=$((PERSIST_PROBLEMS + 1)); CHECK=persistence-launchd
        flag "UNSIGNED persistence: $LABEL runs $PROG ($PLIST)"
        mark_flagged "$PROG" ;;
      missing)
        PERSIST_PROBLEMS=$((PERSIST_PROBLEMS + 1))
        if [ -n "$PROG" ]; then
          CHECK=persistence-orphan
          warn "ORPHANED persistence: $LABEL points at $PROG, which no longer exists ($PLIST)"
        else
          CHECK=persistence-unresolved
          unknown "Launch item $LABEL: could not resolve its target, so its signature was not checked ($PLIST)"
        fi ;;
    esac
  done
}
check_plists "$HOME/Library/LaunchAgents"
check_plists "/Library/LaunchAgents"
check_plists "/Library/LaunchDaemons"
CHECK=persistence-launchd
if [ "$PERSIST_PROBLEMS" -eq 0 ]; then
  pass "All $PERSIST_TOTAL third-party launch items resolve to code signed by Apple or an identified developer"
fi

note ""
note "Privileged helpers (run as root):"
CHECK=privileged-helpers
HELPER_PROBLEMS=0
for H in /Library/PrivilegedHelperTools/*; do
  [ -e "$H" ] || continue
  S=$(sig "$H")
  case "$S" in
    unsigned|adhoc)
      if covered_by_flag "$H"; then
        # Still a problem — it must not let the pass line below print — but it
        # was reported above as the launch item that runs it.
        HELPER_PROBLEMS=$((HELPER_PROBLEMS + 1))
        note "  $(basename "$H") ($(sig_word "$S")) — reported above with the launch item that runs it"
        continue
      fi ;;
  esac
  case "$S" in
    unsigned) HELPER_PROBLEMS=$((HELPER_PROBLEMS + 1)); flag "UNSIGNED privileged helper (runs as root): $H"; mark_flagged "$H" ;;
    adhoc)    HELPER_PROBLEMS=$((HELPER_PROBLEMS + 1)); flag "AD-HOC SIGNED privileged helper (runs as root): $H"; mark_flagged "$H" ;;
    *)        ok "$(basename "$H") ($S)" ;;
  esac
done
[ "$HELPER_PROBLEMS" -eq 0 ] && pass "Every privileged helper tool is signed by Apple or an identified developer"

############################################################
# 3. Other persistence mechanisms
############################################################
section "Other persistence (cron, hooks, startup items)"

CHECK=cron-user
CRON=$(crontab -l 2>/dev/null)
if [ -n "$CRON" ]; then
  warn "Your user account has a crontab with $(printf '%s\n' "$CRON" | grep -cv '^[[:space:]]*#') active line(s)"
  printf '%s\n' "$CRON" | sed 's/^/      /' | tee -a "$REPORT"
else
  pass "No user crontab"
fi

CHECK=cron-root
ROOTCRON=$(sudo crontab -l 2>/dev/null)
if [ -n "$ROOTCRON" ]; then
  flag "ROOT crontab present — commands scheduled to run as root, which nothing on current macOS needs"
  printf '%s\n' "$ROOTCRON" | sed 's/^/      /' | tee -a "$REPORT"
else
  pass "No root crontab"
fi

CHECK=login-hook
LHOOK=$(sudo defaults read com.apple.loginwindow LoginHook 2>/dev/null)
if [ -n "${LHOOK:-}" ]; then
  flag "Login hook configured (legacy mechanism, favoured by malware): $LHOOK"
else
  pass "No login hook is configured"
fi

CHECK=startup-items
if [ -d /Library/StartupItems ] && [ -n "$(ls -A /Library/StartupItems 2>/dev/null)" ]; then
  flag "Legacy StartupItems present (deprecated for over a decade): $(ls /Library/StartupItems | tr '\n' ' ')"
else
  pass "No legacy StartupItems"
fi

CHECK=etc-crontab
ETCCRON=$(grep -v '^#' /etc/crontab 2>/dev/null | grep -v '^[[:space:]]*$' || true)
if [ -n "$ETCCRON" ]; then
  flag "/etc/crontab has active entries: $ETCCRON"
else
  pass "/etc/crontab has no entries"
fi

############################################################
# 4. Running processes
############################################################
section "Running processes"

# One pass over the process table. On macOS `ps -o comm` is the full path of
# the executable, which every check below depends on. Only THIRD-PARTY paths are
# examined: anything under /System, /usr (except /usr/local) and friends is
# SIP-protected Apple code.
PROCS=$(ps -axo pid=,user=,comm= 2>/dev/null)

CHECK=process-location
SUSP=$(printf '%s\n' "$PROCS" | awk -v home="$HOME" '
  { match($0, /^ *[0-9]+ +[^ ]+ +/); pid = $1; c = substr($0, RLENGTH + 1) }
  c ~ /^\/(private\/)?tmp\// || c ~ /^\/(private\/)?var\/tmp\// || c ~ /^\/Users\/Shared\// ||
  index(c, home "/Downloads/") == 1 { print pid, c }')
if [ -n "$SUSP" ]; then
  while IFS= read -r LINE; do flag "Process running from suspicious location: $LINE"; done <<EOF
$SUSP
EOF
else
  pass "No process is running from /tmp, Downloads or /Users/Shared"
fi

# Hidden folders, deleted binaries, and unverified code running as root.
HIDDEN_N=0; DELETED_N=0; ROOT_N=0
DELETED_SEEN=""
while read -r PID PUSER CMD; do
  case "$CMD" in /*) ;; *) continue ;; esac
  is_system_path "$CMD" && continue

  if [ ! -e "$CMD" ]; then
    # Group by app bundle: an updated browser leaves a dozen helpers behind,
    # and that is one thing to restart, not a dozen findings.
    SUBJ=$(printf '%s\n' "$CMD" | sed -n 's|^\(.*\.app\)/.*|\1|p')
    SUBJ=${SUBJ:-$CMD}
    if ! printf '%s\n' "$DELETED_SEEN" | grep -qxF "$SUBJ"; then
      DELETED_SEEN="$DELETED_SEEN
$SUBJ"
      DELETED_N=$((DELETED_N + 1)); CHECK=process-deleted
      warn "A running program's file is no longer on disk — usually an app that updated itself and needs a restart: $SUBJ (pid $PID)"
    fi
    continue
  fi

  already_flagged "$CMD" && continue

  case "$CMD" in
    */.*)
      S=$(sig "$CMD")
      case "$S" in unsigned|adhoc)
        HIDDEN_N=$((HIDDEN_N + 1)); CHECK=process-hidden
        flag "$(sig_word "$S") process running from a hidden folder: $CMD (pid $PID, user $PUSER)"
        mark_flagged "$CMD"; continue ;;
      esac ;;
  esac

  if [ "$PUSER" = "root" ]; then
    S=$(sig "$CMD")
    case "$S" in unsigned|adhoc)
      ROOT_N=$((ROOT_N + 1)); CHECK=process-root
      flag "$(sig_word "$S") third-party process running as root: $CMD (pid $PID)"
      mark_flagged "$CMD" ;;
    esac
  fi
done <<EOF
$PROCS
EOF
CHECK=process-deleted;  [ "$DELETED_N" -eq 0 ] && pass "Every running program's file is still on disk"
CHECK=process-hidden;   [ "$HIDDEN_N" -eq 0 ]  && pass "No unverified program is running from a hidden folder"
CHECK=process-root;     [ "$ROOT_N" -eq 0 ]    && pass "No unverified third-party program is running as root"

############################################################
# 5. Network listeners
############################################################
section "Network listeners (processes accepting connections)"

# One line per PROCESS with all its addresses. The old loop was per address, so
# one unsigned localhost service listening on IPv4 and IPv6 was two findings —
# and with its launch agent and sentry's network check, the same binary was four
# items in one report (DEVLOG Bug 17).
LISTEN_PROBLEMS=0; REMOTE_N=0; REMOTE_SEEN=""
LISTENERS=$(sudo lsof -i -P -n 2>/dev/null | awk '$NF ~ /LISTEN/ {print $2, $1, $9}' | sort -u | awk '
  { if (!($1 in name)) { name[$1] = $2; order[++n] = $1 }
    if (index(" " addrs[$1] " ", " " $3 " ") == 0) addrs[$1] = addrs[$1] (addrs[$1] == "" ? "" : " ") $3 }
  END { for (i = 1; i <= n; i++) print order[i], name[order[i]], addrs[order[i]] }')
while read -r PID NAME ADDRS; do
  [ -n "${PID:-}" ] || continue
  BIN=$(ps -p "$PID" -o comm= 2>/dev/null)
  SCOPE="localhost-only"; LABELS=""
  for A in $ADDRS; do
    case "$A" in 127.0.0.1:*|\[::1\]:*|localhost:*) ;; *) SCOPE="ALL INTERFACES" ;; esac
    L=$(port_label "${A##*:}")
    if [ -n "$L" ]; then
      case "$LABELS" in *"${L%%|*}"*) ;; *) LABELS="${LABELS:+$LABELS, }${L%%|*}" ;; esac
      case "$A" in 127.0.0.1:*|\[::1\]:*) ;; *)
        if [ "${L##*|}" = "remote" ] && ! printf '%s\n' "$REMOTE_SEEN" | grep -qxF "${L%%|*}"; then
          REMOTE_SEEN="$REMOTE_SEEN
${L%%|*}"
          REMOTE_N=$((REMOTE_N + 1)); CHECK=remote-access
          warn "${L%%|*} is on and reachable from your network (port ${A##*:})"
        fi ;;
      esac
    fi
  done
  S=$(sig "${BIN:-/nonexistent}")
  DESC="$NAME (pid $PID) on $ADDRS [$SCOPE]${LABELS:+ — $LABELS}"
  case "$S" in
    apple)    ok "$DESC — Apple" ;;
    signed:*) ok "$DESC — ${S#signed:}" ;;
    *)
      if is_system_path "${BIN:-}"; then
        ok "$DESC — system binary"
      elif already_flagged "${BIN:-}"; then
        ok "$DESC — already flagged above"
      else
        LISTEN_PROBLEMS=$((LISTEN_PROBLEMS + 1)); CHECK=listeners
        flag "Listener with unverifiable signature: $DESC binary:${BIN:-?}"
        mark_flagged "${BIN:-?}"
      fi ;;
  esac
done <<EOF
$LISTENERS
EOF
CHECK=listeners;     [ "$LISTEN_PROBLEMS" -eq 0 ] && pass "Every listening process is signed by Apple or an identified developer"
CHECK=remote-access; [ "$REMOTE_N" -eq 0 ] && pass "No remote-access service (SSH, Screen Sharing, Remote Management, File Sharing) is reachable from the network"

note ""
note "Listeners on ALL INTERFACES are reachable from your network — each should be"
note "something you recognize (file sharing, Docker, DAW link protocols, etc.)."

############################################################
# 6. Traffic interception — the MacKeeper StopAd category
############################################################
section "Traffic interception (proxies, filters, VPN/network extensions, profiles)"

CHECK=proxy
PROXY=$(scutil --proxy 2>/dev/null)
if printf '%s\n' "$PROXY" | grep -qE '(HTTPEnable|HTTPSEnable|SOCKSEnable|ProxyAutoConfigEnable)[[:space:]]*:[[:space:]]*1'; then
  flag "System proxy is ACTIVE — web traffic is routed through a proxy"
  printf '%s\n' "$PROXY" | grep -E 'Enable|Proxy|Port' | sed 's/^/      /' | tee -a "$REPORT"
else
  pass "No system proxy is enabled"
fi

CHECK=net-extensions
NETX=$(systemextensionsctl list 2>/dev/null | grep -iE 'network_extension|endpoint_security' | grep -oE '[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+ \(' | sed 's/ ($//' | sort -u | tr '\n' ' ')
if [ -n "$NETX" ]; then
  warn "Network or endpoint-security system extensions are registered — verify each is yours: $NETX"
else
  pass "No network-filter or endpoint-security extension is registered"
fi

DNS=$(scutil --dns 2>/dev/null | grep -m4 'nameserver' | awk '{print $3}' | sort -u | tr '\n' ' ')
note "Active DNS servers: ${DNS:-unknown} (should match your router/VPN/chosen DNS)"

# Count profile identifiers rather than grepping for the absence of a sentence:
# "There are no configuration profiles" is not a stable string to depend on, and
# a command that fails outright must read as unknown, never as clean.
CHECK=config-profiles
PROFILES_OUT=$(sudo profiles list 2>&1); PROFILES_RC=$?
PROFILE_IDS=$(printf '%s\n' "$PROFILES_OUT" | grep -c 'profileIdentifier' || true)
if [ "${PROFILE_IDS:-0}" -gt 0 ]; then
  flag "Configuration profiles installed ($PROFILE_IDS) — they can enforce proxies, DNS and trusted certificates; verify each"
  printf '%s\n' "$PROFILES_OUT" | grep 'profileIdentifier' | sed 's/^/      /' | tee -a "$REPORT"
elif [ "$PROFILES_RC" -eq 0 ] || printf '%s' "$PROFILES_OUT" | grep -qi 'no configuration profiles'; then
  pass "No configuration profiles are installed"
else
  unknown "Configuration profiles could not be listed, so this check did not run"
fi

CHECK=etc-hosts
HOSTS=$(grep -vE '^[[:space:]]*#|^[[:space:]]*$|localhost|broadcasthost|^::1' /etc/hosts 2>/dev/null || true)
if [ -n "$HOSTS" ]; then
  HOSTS_N=$(printf '%s\n' "$HOSTS" | wc -l | tr -d ' ')
  warn "/etc/hosts overrides DNS for $HOSTS_N line(s) of custom entries — fine if you added them"
  printf '%s\n' "$HOSTS" | sed 's/^/      /' | tee -a "$REPORT"
else
  pass "/etc/hosts is stock"
fi

############################################################
# 7. Browser extensions
############################################################
section "Browser extensions"

note "Safari app extensions (enabled state is managed in Safari settings):"
SAFARI_EXT=$(pluginkit -mAvvv -p com.apple.Safari.web-extension 2>/dev/null | grep -E 'Display Name|Path' || true)
if [ -n "$SAFARI_EXT" ]; then
  printf '%s\n' "$SAFARI_EXT" | sed 's/^/      /' | tee -a "$REPORT"
else
  note "      none found via pluginkit"
fi

# Chromium-family browsers keep extensions at
#   <root>/<profile>/Extensions/<id>/<version>/manifest.json
AS="$HOME/Library/Application Support"
ROOTS=""
for R in "$AS/Google/Chrome" "$AS/BraveSoftware/Brave-Browser" "$AS/Microsoft Edge" \
         "$AS/Arc/User Data" "$AS/Vivaldi"; do
  [ -d "$R" ] && ROOTS="$ROOTS
$R"
done

CHECK=browser-extensions
PYOK=false
P3=$(command -v python3 2>/dev/null || true)
if [ -n "$P3" ] && [ -f "$DIR/neptune_inspect.py" ]; then
  if [ "$P3" != "/usr/bin/python3" ] || xcode-select -p >/dev/null 2>&1; then PYOK=true; fi
fi
if [ -z "$ROOTS" ]; then
  note ""
  note "No Chromium-family browser profiles found."
elif ! $PYOK; then
  note ""
  note "Chromium-family extensions not inspected: needs python3 (xcode-select --install)."
  CATEGORY=security; record info "Browser extension permissions were not inspected, because python3 is not installed"
else
  EXT_TMP=$(mktemp "${TMPDIR:-/tmp}/neptune-ext.XXXXXX")
  printf '%s\n' "$ROOTS" | grep -v '^$' | while IFS= read -r R; do printf '%s\0' "$R"; done \
    | xargs -0 "$P3" "$DIR/neptune_inspect.py" extensions > "$EXT_TMP" 2>/dev/null
  EXT_N=$(grep -c . "$EXT_TMP" || true)
  RISKY_N=0
  note ""
  note "Chromium-family extensions ($EXT_N):"
  while IFS="$(printf '\t')" read -r BROWSER NAME EID RISKY; do
    [ -n "${BROWSER:-}" ] || continue
    if [ -n "${RISKY:-}" ]; then
      RISKY_N=$((RISKY_N + 1))
      warn "$BROWSER extension '$NAME' holds the $RISKY permission — it can see or reroute everything the browser does ($EID)"
    else
      note "      $BROWSER: $NAME"
    fi
  done < "$EXT_TMP"
  rm -f "$EXT_TMP"
  [ "$RISKY_N" -eq 0 ] && pass "$EXT_N browser extension(s) checked; none can reroute traffic or attach a debugger"
fi

############################################################
# SUMMARY
############################################################
out ""
out "${BOLD}================ RED FLAG SUMMARY ================${RST}"
if [ ${#FLAGS[@]} -eq 0 ]; then
  out "${GRN}${BOLD}No red flags found.${RST} Posture, persistence, processes, listeners and"
  out "interception all checked clean."
else
  out "${RED}${BOLD}${#FLAGS[@]} item(s) flagged:${RST}"
  I=1
  for F in ${FLAGS[@]:+"${FLAGS[@]}"}; do
    out "  $I. $F"
    I=$((I+1))
  done
  out ""
  out "Flags are leads, not verdicts — vendor quirks (Waves, Sonarworks, Docker)"
  out "routinely fail signature checks. Share this report for a second opinion."
fi
out ""
out "Full report saved to: $REPORT"
exit 0
