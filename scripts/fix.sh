#!/bin/bash
#
# fix.sh — walk the findings from your last run and fix them, one at a time
#
# Usage:
#   ./fix.sh           (or ./neptune.sh --fix) go through your last run's list
#   ./fix.sh --plan    show what would be offered for each item; change nothing
#
# The scan diagnoses; this is the second half of the loop: audit, understand,
# fix, re-measure. For every numbered finding from your LAST run it shows the
# fix, the exact command, and what kind of change it is — then asks. Nothing is
# applied without a "y" for that item. At the end it offers to re-scan so the
# report shows the before and after.
#
# What it will do, and nothing else:
#   - change a macOS security setting (firewall, Guest account, auto-login,
#     automatic updates) with the one documented command for it
#   - hand off to Neptune's own confirmed tools: check_updates.sh --upgrade,
#     clean_caches.sh --apply, uninstall.sh, sentry.sh --rebaseline
#   - run `brew cleanup` for Homebrew's own download cache
#   - open the right System Settings pane, or reveal a file in Finder
# It deletes nothing itself — deletion always goes through the three confirmed
# scripts — and where there is no honest one-command fix (double NAT, FileVault,
# an unsigned vendor helper) it says what to do instead of inventing one.
#
# Every change it applies is logged to ~/.neptune/fix-log.tsv.

set -u
export LC_ALL=C   # byte-safe, platform-identical text tools — see the note in neptune.sh

BOLD=$(tput bold 2>/dev/null || true)
GRN=$(tput setaf 2 2>/dev/null || true)
YEL=$(tput setaf 3 2>/dev/null || true)
CYN=$(tput setaf 6 2>/dev/null || true)
RST=$(tput sgr0 2>/dev/null || true)

DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"   # BASH_SOURCE: correct when sourced by tests too

PANE_SECURITY="x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension"
PANE_LOGIN="x-apple.systempreferences:com.apple.LoginItems-Settings.extension"
PANE_SHARING="x-apple.systempreferences:com.apple.Sharing-Settings.extension"
PANE_NETWORK="x-apple.systempreferences:com.apple.Network-Settings.extension"
PANE_PROFILES="x-apple.systempreferences:com.apple.Profiles-Settings.extension"
PANE_UPDATE="x-apple.systempreferences:com.apple.Software-Update-Settings.extension"

# plan_for <check> <title> [n] — decide what to offer. Sets:
#   KIND   run | open | guide
#   ACTION a key for de-duplication (one upgrade run covers three findings)
#   CMD    the command, as plain words: it is split on spaces and executed
#          directly — never passed to eval, never globbed — and it is exactly
#          what the user was shown
#   LABEL  what the change is, in words
#   TAG    reads only | changes a setting | installs or removes software | Neptune command
#   GUIDE  what to do by hand, when that is the honest answer
plan_for() {
  local CHK=$1 TITLE=$2 NUM=${3:-N} APP
  KIND=guide; ACTION="guide:$CHK"; CMD=""; LABEL=""; TAG=""; GUIDE=""; NEP=""; NARGS=""
  APP=$(printf '%s' "$TITLE" | sed -n 's|.*/Applications/\([^/]*\)\.app.*|\1|p' | head -1)
  case "$CHK" in
    firewall)
      KIND=run; ACTION=firewall; TAG="changes a setting"
      LABEL="Turn on the macOS application firewall (blocks unsolicited incoming connections; apps you allow keep working)"
      CMD="sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on" ;;
    guest-account)
      KIND=run; ACTION=guest; TAG="changes a setting"
      LABEL="Disable the Guest account (no password-free login)"
      CMD="sudo sysadminctl -guestAccount off" ;;
    auto-login)
      KIND=run; ACTION=autologin; TAG="changes a setting"
      LABEL="Turn off automatic login (the Mac asks for a password at startup)"
      CMD="sudo sysadminctl -autologin off" ;;
    auto-update-check)
      KIND=run; ACTION=update-schedule; TAG="changes a setting"
      LABEL="Turn automatic update checking back on"
      CMD="sudo softwareupdate --schedule on" ;;
    auto-security-updates)
      KIND=open; ACTION=pane-update; CMD="open $PANE_UPDATE"; TAG="reads only"
      LABEL="Open Software Update settings"
      GUIDE="Under Automatic Updates, turn on 'Install Security Responses and system files'." ;;
    macos-updates|brew-outdated|mas-outdated)
      KIND=run; ACTION=upgrade; TAG="installs or removes software"
      LABEL="Install pending updates — Apple minor updates, Homebrew, App Store — asking before each source; never a major macOS upgrade"
      NEP=check_updates.sh; NARGS="--upgrade"; CMD="./check_updates.sh --upgrade" ;;
    app-updates)
      GUIDE="Open each app listed and use its own 'Check for Updates', or hand it to Homebrew once with: brew install --cask --adopt <cask>. Leave licence-managed software on its vendor's updater." ;;
    brew-cache)
      KIND=run; ACTION=brew-cleanup; TAG="installs or removes software"
      LABEL="Let Homebrew delete its old downloads and old versions (installed software is untouched)"
      CMD="brew cleanup --prune=all" ;;
    caches)
      KIND=run; ACTION=caches; TAG="Neptune command"
      LABEL="Pick caches to clear — you choose by number and type 'yes' before anything goes"
      NEP=clean_caches.sh; NARGS="--apply"; CMD="./clean_caches.sh --apply" ;;
    stale-apps)
      KIND=run; ACTION=uninstall-pick; TAG="Neptune command"
      LABEL="Uninstall apps you no longer use, one at a time, with every leftover shown first"
      NEP=uninstall.sh; NARGS=""; CMD="./uninstall.sh" ;;
    baseline-diff)
      KIND=run; ACTION=rebaseline; TAG="Neptune command"
      LABEL="Accept the current state as known-good — ONLY if you recognize every new item"
      NEP=sentry.sh; NARGS="--rebaseline"; CMD="./sentry.sh --rebaseline" ;;
    persistence-launchd|privileged-helpers|listeners|network-signing|process-root|process-hidden)
      if [ -n "$APP" ]; then
        KIND=run; ACTION="uninstall:$APP"; TAG="Neptune command"
        LABEL="If you do not need $APP: remove it and everything it installed (shows the full list, asks first)"
        CMD="./uninstall.sh \"$APP\""
        GUIDE="If you use $APP, skip this and acknowledge it instead: ./neptune.sh --acknowledge $NUM"
      else
        KIND=run; ACTION="ack:$NUM"; TAG="Neptune command"
        LABEL="If you recognize this as software you use (a licence daemon, an audio or VM helper): acknowledge it — it stays listed and counted, it just stops costing points"
        NEP=neptune.sh; NARGS="--acknowledge $NUM"; CMD="./neptune.sh --acknowledge $NUM"
        GUIDE="If you cannot place it, skip this and find out what installed it before anything else."
      fi ;;
    persistence-orphan|persistence-unresolved|login-hook|cron-user|cron-root|etc-crontab|startup-items)
      KIND=open; ACTION=pane-login; CMD="open $PANE_LOGIN"; TAG="reads only"
      LABEL="Open Login Items & Extensions settings"
      GUIDE="A launch item whose program is gone, or that cannot be read, is usually left behind by uninstalled software. Turn it off under 'Allow in the Background', or remove the .plist named in the finding." ;;
    remote-access)
      KIND=open; ACTION=pane-sharing; CMD="open $PANE_SHARING"; TAG="reads only"
      LABEL="Open Sharing settings"
      GUIDE="Turn off Remote Login, Screen Sharing, Remote Management or File Sharing unless you use it on purpose." ;;
    config-profiles)
      KIND=open; ACTION=pane-profiles; CMD="open $PANE_PROFILES"; TAG="reads only"
      LABEL="Open Device Management settings"
      GUIDE="Remove any profile you did not install on purpose. On a work Mac, ask IT first." ;;
    proxy|dns)
      KIND=open; ACTION=pane-network; CMD="open $PANE_NETWORK"; TAG="reads only"
      LABEL="Open Network settings"
      GUIDE="Under your connection > Details, check Proxies and DNS for anything you did not set." ;;
    net-extensions|kexts)
      KIND=open; ACTION=pane-login; CMD="open $PANE_LOGIN"; TAG="reads only"
      LABEL="Open Login Items & Extensions settings"
      GUIDE="Check each extension belongs to software you chose; turn off the ones that do not." ;;
    filevault|gatekeeper|sip)
      KIND=open; ACTION=pane-security; CMD="open $PANE_SECURITY"; TAG="reads only"
      LABEL="Open Privacy & Security settings"
      GUIDE="FileVault and Gatekeeper are turned on here (FileVault shows you a recovery key — store it). SIP can only be changed from Recovery; if it is off and you did not do that, treat the Mac as untrusted." ;;
    double-nat)
      GUIDE="A router setting, not a Mac one. On a mesh behind an ISP gateway, open the mesh's main router and check its WAN address: a public IP means the ISP box is in passthrough (fine); a 192.168.x or 10.x address means enable IP Passthrough or bridge mode on the ISP gateway." ;;
    gateway-latency|lan-latency)
      GUIDE="On a mesh this is usually a node reaching the main router over Wi-Fi. Cable the nodes together (Ethernet backhaul), move this Mac closer to the main router, or wire the Mac." ;;
    etc-hosts)
      GUIDE="Read /etc/hosts and remove entries you cannot account for (sudo nano /etc/hosts)." ;;
    browser-extensions)
      GUIDE="Open the browser's extensions page and remove any extension you did not install on purpose." ;;
    process-location|process-deleted)
      GUIDE="Quit and reopen the program named; if it runs from Downloads, /tmp or /Users/Shared and you do not know it, stop it in Activity Monitor and find what launched it." ;;
    dev-junk)
      GUIDE="Delete it from inside Xcode (Settings > Locations > Derived Data) — it all regenerates." ;;
    logs)
      GUIDE="Find the app writing the logs (du -sh ~/Library/Logs/*) and fix or reinstall it; deleting logs alone just resets the clock." ;;
    brew-doctor)
      GUIDE="Run brew doctor and follow each warning's own instructions." ;;
    cgnat)
      GUIDE="Nothing to fix on this Mac; ask your ISP for a public IP only if you need inbound connections." ;;
    *)
      GUIDE="Re-run Neptune. If this keeps appearing, run the scan named in the finding on its own to see why it could not check." ;;
  esac
}

# run_words <command> — execute the words shown, with no eval and no globbing.
run_words() {
  local RC
  set -f
  # shellcheck disable=SC2086  # deliberate: the command is a list of plain words
  set -- $1
  set +f
  "$@"; RC=$?
  return "$RC"
}

[ "${NEPTUNE_LIB:-}" = "1" ] && return 0

PLAN=false
case "${1:-}" in
  "") ;;
  --plan) PLAN=true ;;
  -h|--help) sed -n '3,26p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  *) echo "Unknown option: $1  (try --help)" >&2; exit 64 ;;
esac

LISTING="$HOME/.neptune/last-listing.tsv"
FIXLOG="$HOME/.neptune/fix-log.tsv"
if [ ! -s "$LISTING" ]; then
  echo "No saved results yet. Run ./neptune.sh first; fix.sh works from its list." >&2
  exit 64
fi
RUN_OF=$(head -1 "$LISTING" | sed 's/^# //')
TOTAL=$(grep -vc '^#' "$LISTING" || true)

if $PLAN; then
  printf '# n\tcheck\tkind\taction\tcommand\n'
  while IFS="$(printf '\t')" read -r N _SEV _CAT _KEY TITLE CHK; do
    case "$N" in ''|'#'*) continue ;; esac
    plan_for "${CHK:-}" "$TITLE" "$N"
    printf '%s\t%s\t%s\t%s\t%s\n' "$N" "${CHK:-}" "$KIND" "$ACTION" "$CMD"
  done < "$LISTING"
  exit 0
fi

# --plan changes nothing, so it may run anywhere; applying fixes as root would
# run brew as root and write root-owned files into your home.
if [ "$(id -u)" -eq 0 ]; then
  echo "Run as your normal user, not with sudo — each fix asks for it only if it needs it." >&2; exit 64
fi

echo "${BOLD}Neptune fix — $TOTAL item(s) from the $RUN_OF${RST}"
echo "Each fix is shown with its exact command and asks first: y = apply, Enter = skip, q = stop."
[ "$TOTAL" -gt 0 ] || { echo "Nothing to fix. Run ./neptune.sh again any time."; exit 0; }
[ -f "$FIXLOG" ] || printf '# date\tn\tcheck\taction\tresult\n' > "$FIXLOG"

ask() { # <prompt> -> 0 yes, 1 no, 2 quit
  local R
  read -r -p "  ${BOLD}$1${RST} [y/N/q] " R </dev/tty
  case "$R" in [yY]|[yY][eE][sS]) return 0 ;; [qQ]*) return 2 ;; *) return 1 ;; esac
}
log_fix() { printf '%s\t%s\t%s\t%s\t%s\n' "$(date '+%Y-%m-%d %H:%M')" "$1" "$2" "$3" "$4" >> "$FIXLOG"; }

DONE=""; APPLIED=0; SKIPPED=0; GUIDED=0
while IFS="$(printf '\t')" read -r N SEV CAT _KEY TITLE CHK; do
  case "$N" in ''|'#'*) continue ;; esac
  plan_for "${CHK:-}" "$TITLE" "$N"
  echo
  echo "${BOLD}${CYN}[$N/$TOTAL]${RST} ${BOLD}[$CAT/$SEV]${RST} $TITLE"
  # One upgrade run covers macOS, brew and App Store findings; offer it once.
  if printf '%s\n' "$DONE" | grep -qxF "$ACTION"; then
    if [ "$KIND" = guide ]; then echo "  Same kind of finding as above — same guidance."
    else echo "  Covered by a fix already offered above."; fi
    continue
  fi
  DONE="$DONE
$ACTION"
  [ -n "$GUIDE" ] && echo "  ${YEL}What to do:${RST} $GUIDE"
  [ "$KIND" = "guide" ] && { GUIDED=$((GUIDED + 1)); continue; }
  echo "  ${GRN}Fix:${RST} $LABEL"
  echo "  Command: $CMD    (${TAG})"
  if [ "$ACTION" = "uninstall-pick" ]; then
    read -r -p "  ${BOLD}App to remove (exact name, Enter to skip, q to stop):${RST} " PICK </dev/tty
    case "$PICK" in "") SKIPPED=$((SKIPPED + 1)); continue ;; [qQ]) break ;; esac
    "$DIR/uninstall.sh" "$PICK" </dev/tty; RC=$?
    log_fix "$N" "$CHK" "uninstall:$PICK" "exit $RC"; APPLIED=$((APPLIED + 1))
    continue
  fi
  ask "Apply this fix?"; A=$?
  [ "$A" -eq 2 ] && break
  if [ "$A" -ne 0 ]; then SKIPPED=$((SKIPPED + 1)); continue; fi
  if [ "${ACTION#uninstall:}" != "$ACTION" ]; then
    "$DIR/uninstall.sh" "${ACTION#uninstall:}" </dev/tty; RC=$?     # the name as an argument, never re-split
  else
    if [ -n "$NEP" ]; then
      # Neptune's own scripts by absolute path, flags split as plain words —
      # the install path may contain spaces; the flags never do.
      set -f
      # shellcheck disable=SC2086
      "$DIR/$NEP" $NARGS </dev/tty; RC=$?
      set +f
    else
      run_words "$CMD" </dev/tty; RC=$?
    fi
  fi
  if [ "$RC" -eq 0 ]; then echo "  ${GRN}[done]${RST}"; else echo "  ${YEL}[exited $RC — nothing further was attempted]${RST}"; fi
  log_fix "$N" "$CHK" "$ACTION" "exit $RC"; APPLIED=$((APPLIED + 1))
done < "$LISTING"

echo
echo "${BOLD}Applied $APPLIED, skipped $SKIPPED, $GUIDED with instructions only.${RST} Logged in $FIXLOG."
if [ "$APPLIED" -gt 0 ]; then
  read -r -p "  ${BOLD}Re-scan now so the report shows before and after?${RST} [y/N] " R </dev/tty
  case "$R" in [yY]|[yY][eE][sS]) exec "$DIR/neptune.sh" --html ;; esac
fi
exit 0
