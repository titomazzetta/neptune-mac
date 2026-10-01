#!/bin/bash
#
# fix.sh — walk the findings from your last run and fix them, one at a time
#
# Usage:
#   ./fix.sh                (or ./neptune.sh --fix) go through your last run's list
#   ./fix.sh --only 9,2,12  just those items, in that order — a queue
#   ./fix.sh --plan         show what would be offered for each item; change nothing
#
# The scan diagnoses; this is the second half of the loop: audit, understand,
# fix, re-measure. For every numbered finding from your LAST run it shows the
# fix, the exact command, and what kind of change it is — then asks. Nothing is
# applied without a "y" for that item. Software you might recognize (an
# unsigned audio helper, a licence daemon) gets a choice instead: k keeps it
# (listed, no longer costing points), u uninstalls it through uninstall.sh, s
# skips. At the end it offers to re-scan so the report shows before and after.
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

# Colour only on a terminal that wants it (NO_COLOR, TERM=dumb and pipes get none).
BOLD=""; DIM=""; GRN=""; YEL=""; CYN=""; RST=""
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != dumb ]; then
  BOLD=$(tput bold 2>/dev/null || true); DIM=$(tput dim 2>/dev/null || true)
  GRN=$(tput setaf 2 2>/dev/null || true); YEL=$(tput setaf 3 2>/dev/null || true)
  CYN=$(tput setaf 6 2>/dev/null || true); RST=$(tput sgr0 2>/dev/null || true)
fi

DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"   # BASH_SOURCE: correct when sourced by tests too

PANE_SECURITY="x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension"
PANE_LOGIN="x-apple.systempreferences:com.apple.LoginItems-Settings.extension"
PANE_SHARING="x-apple.systempreferences:com.apple.Sharing-Settings.extension"
PANE_NETWORK="x-apple.systempreferences:com.apple.Network-Settings.extension"
PANE_PROFILES="x-apple.systempreferences:com.apple.Profiles-Settings.extension"
PANE_UPDATE="x-apple.systempreferences:com.apple.Software-Update-Settings.extension"

# plan_for <check> <title> — decide what to offer. Sets:
#   KIND   run | open | guide
#   ACTION a key for de-duplication (one upgrade run covers three findings)
#   CMD    the command, as plain words: it is split on spaces and executed
#          directly — never passed to eval, never globbed — and it is exactly
#          what the user was shown
#   LABEL  what the change is, in words
#   TAG    reads only | changes a setting | installs or removes software | Neptune command
#   GUIDE  what to do by hand, when that is the honest answer
#   KEEP   1 when "keep it" is a fair answer (KEEPWHY says when it is) — software you may have chosen, or
#          a double NAT you have confirmed is passthrough. The menu then offers
#          k (keep: acknowledge it) beside the fix.
plan_for() {
  local CHK=$1 TITLE=$2 APP
  KIND=guide; ACTION="guide:$CHK"; CMD=""; LABEL=""; TAG=""; GUIDE=""; NEP=""; NARGS=""; KEEP=0
  KEEPWHY="you know it and use it. Stays listed, stops costing points."
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
      KEEP=1
      if [ -n "$APP" ]; then
        KIND=run; ACTION="uninstall:$APP"; TAG="Neptune command"
        LABEL="Remove $APP and everything it installed (shows the full list, asks first)"
        CMD="./uninstall.sh \"$APP\""
      else
        GUIDE="If you recognize it as software you use (a licence daemon, an audio or VM helper), keep it. If you cannot place it, skip it and find out what installed it before anything else."
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
      KEEP=1; KEEPWHY="you checked the router and it is passthrough. Stays listed, stops costing points."
      GUIDE="A router setting, not a Mac one. On a mesh behind an ISP gateway, open the mesh's main router and check its WAN address: a public IP means the ISP box is in passthrough (fine, and safe to keep); a 192.168.x or 10.x address means enable IP Passthrough or bridge mode on the ISP gateway." ;;
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

PLAN=false; ONLY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --plan) PLAN=true ;;
    --only)
      shift; ONLY="${1:-}"
      case "$ONLY" in ''|*[!0-9,]*) echo "--only takes item numbers from your last run, e.g. --only 9,2,12" >&2; exit 64 ;; esac ;;
    -h|--help) sed -n '3,28p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $1  (try --help)" >&2; exit 64 ;;
  esac
  shift
done

LISTING="$HOME/.neptune/last-listing.tsv"
FIXLOG="$HOME/.neptune/fix-log.tsv"
ALLOWF="$HOME/.neptune/allow"
if [ ! -s "$LISTING" ]; then
  echo "No saved results yet. Run ./neptune.sh first; fix.sh works from its list." >&2
  exit 64
fi
RUN_OF=$(head -1 "$LISTING" | sed 's/^# //')
AVAIL=$(grep -vc '^#' "$LISTING" || true)

# The queue: every item in list order, or exactly the numbers given, in the
# order given (a number twice is played once). An unknown number stops it
# before anything runs — a typo must not quietly fix something else.
QUEUE=""
if [ -n "$ONLY" ]; then
  BADN=""
  for N in $(printf '%s' "$ONLY" | tr ',' ' '); do
    LINE=$(awk -F'\t' -v n="$N" '$1 == n' "$LISTING")
    if [ -z "$LINE" ]; then BADN="$BADN $N"; continue; fi
    printf '%s\n' "$QUEUE" | grep -qxF "$LINE" || QUEUE="$QUEUE$LINE
"
  done
  if [ -n "$BADN" ]; then
    echo "No item numbered:$BADN in your last run (1-$AVAIL, from the $RUN_OF). Nothing was changed." >&2
    exit 64
  fi
else
  QUEUE=$(grep -v '^#' "$LISTING" || true)
fi
TOTAL=$(printf '%s' "$QUEUE" | grep -c . || true)

if $PLAN; then
  printf '# n\tcheck\tkind\taction\tkeep\tcommand\n'
  while IFS="$(printf '\t')" read -r N _SEV _CAT _KEY TITLE CHK _HEAD _CTX; do
    case "$N" in ''|'#'*) continue ;; esac
    plan_for "${CHK:-}" "$TITLE" "$N"
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$N" "${CHK:-}" "$KIND" "$ACTION" "$KEEP" "$CMD"
  done <<EOQ
$QUEUE
EOQ
  exit 0
fi

# --plan changes nothing, so it may run anywhere; applying fixes as root would
# run brew as root and write root-owned files into your home.
if [ "$(id -u)" -eq 0 ]; then
  echo "Run as your normal user, not with sudo — each fix asks for it only if it needs it." >&2; exit 64
fi

echo
if [ -n "$ONLY" ]; then
  printf '  %sNeptune fix%s %s%s queued from the %s%s\n' "$BOLD" "$RST" "$DIM" "$TOTAL" "$RUN_OF" "$RST"
else
  printf '  %sNeptune fix%s %s%s item(s) from the %s%s\n' "$BOLD" "$RST" "$DIM" "$TOTAL" "$RUN_OF" "$RST"
fi
printf '  %sEach one shows its exact command first. Nothing changes until you say so.%s\n' "$DIM" "$RST"
[ "$TOTAL" -gt 0 ] || { echo "  Nothing to fix. Run ./neptune.sh again any time."; exit 0; }
mkdir -p "$HOME/.neptune"
[ -f "$FIXLOG" ] || printf '# date\tn\tcheck\taction\tresult\n' > "$FIXLOG"

# choose <keys> <prompt> — one answer from /dev/tty, lowercased to its first
# letter; Enter (or anything not offered) means skip.
choose() {
  local R
  read -r -p "  ${BOLD}$2${RST} " R </dev/tty
  R=$(printf '%s' "$R" | cut -c1 | tr 'A-Z' 'a-z')
  case "$1" in *"$R"*) [ -n "$R" ] && { ANSWER=$R; return 0; } ;; esac
  ANSWER=s
}
log_fix() { printf '%s\t%s\t%s\t%s\t%s\n' "$(date '+%Y-%m-%d %H:%M')" "$1" "$2" "$3" "$4" >> "$FIXLOG"; }

# keep <key> — the same line --acknowledge writes, without a second prompt:
# pressing k WAS the confirmation.
keep() {
  touch "$ALLOWF"
  grep -qxF "$1" "$ALLOWF" || printf '%s\n' "$1" >> "$ALLOWF"
}

# apply — run the fix that plan_for chose. Sets RC.
apply() {
  if [ "${ACTION#uninstall:}" != "$ACTION" ]; then
    "$DIR/uninstall.sh" "${ACTION#uninstall:}" </dev/tty; RC=$?     # the name as an argument, never re-split
  elif [ -n "$NEP" ]; then
    # Neptune's own scripts by absolute path, flags split as plain words —
    # the install path may contain spaces; the flags never do.
    set -f
    # shellcheck disable=SC2086
    "$DIR/$NEP" $NARGS </dev/tty; RC=$?
    set +f
  else
    run_words "$CMD" </dev/tty; RC=$?
  fi
  if [ "$RC" -eq 0 ]; then echo "  ${GRN}Done.${RST}"; else echo "  ${YEL}Stopped with exit $RC; nothing further was attempted.${RST}"; fi
}

DONE=""; I=0; APPLIED=0; KEPT=0; SKIPPED=0; GUIDED=0
while IFS="$(printf '\t')" read -r N _SEV _CAT KEY TITLE CHK HEAD CTX; do
  case "$N" in ''|'#'*) continue ;; esac
  I=$((I + 1))
  plan_for "${CHK:-}" "$TITLE" "$N"
  echo
  printf '  %s%s/%s%s  %s#%s%s  %s%s%s\n' "$DIM" "$I" "$TOTAL" "$RST" "$CYN" "$N" "$RST" "$BOLD" "${HEAD:-$TITLE}" "$RST"
  [ -n "${CTX:-}" ] && printf '         %s%s%s\n' "$DIM" "$CTX" "$RST"
  # One upgrade run covers macOS, brew and App Store findings: offer it once.
  # An app already removed covers its other items. Keep is always per item.
  if printf '%s\n' "$DONE" | grep -qxF "$ACTION"; then
    if [ "$KIND" = guide ]; then echo "         Same as above."
    else echo "         Covered by the fix above."; fi
    continue
  fi
  [ "$KEEP" = 1 ] || DONE="$DONE
$ACTION"
  [ -n "$GUIDE" ] && echo "         ${YEL}What to do:${RST} $GUIDE"

  if [ "$KEEP" = 1 ]; then
    echo "         ${GRN}k${RST}  keep it: $KEEPWHY"
    if [ "$KIND" = run ]; then
      echo "         ${GRN}u${RST}  $LABEL"
      echo "            $CMD    ($TAG)"
      choose kusq "k keep · u uninstall · Enter skip · q stop:"
    else
      choose ksq "k keep · Enter skip · q stop:"
    fi
    case "$ANSWER" in
      q) break ;;
      k) keep "$KEY"; log_fix "$N" "$CHK" "keep" "ok"; KEPT=$((KEPT + 1)); echo "  ${GRN}Kept.${RST} ${DIM}Undo: delete its line from $ALLOWF${RST}" ;;
      u) apply; DONE="$DONE
$ACTION"; log_fix "$N" "$CHK" "$ACTION" "exit $RC"; APPLIED=$((APPLIED + 1)) ;;
      *) SKIPPED=$((SKIPPED + 1)) ;;
    esac
    continue
  fi

  [ "$KIND" = "guide" ] && { GUIDED=$((GUIDED + 1)); continue; }
  echo "         ${GRN}Fix:${RST} $LABEL"
  echo "         $CMD    ($TAG)"
  if [ "$ACTION" = "uninstall-pick" ]; then
    read -r -p "  ${BOLD}App to remove (exact name, Enter to skip, q to stop):${RST} " PICK </dev/tty
    case "$PICK" in "") SKIPPED=$((SKIPPED + 1)); continue ;; [qQ]) break ;; esac
    "$DIR/uninstall.sh" "$PICK" </dev/tty; RC=$?
    log_fix "$N" "$CHK" "uninstall:$PICK" "exit $RC"; APPLIED=$((APPLIED + 1))
    continue
  fi
  choose yq "Apply it? y yes · Enter skip · q stop:"
  case "$ANSWER" in
    q) break ;;
    y) apply; log_fix "$N" "$CHK" "$ACTION" "exit $RC"; APPLIED=$((APPLIED + 1)) ;;
    *) SKIPPED=$((SKIPPED + 1)) ;;
  esac
done <<EOQ
$QUEUE
EOQ

echo
printf '  %sApplied %s, kept %s, skipped %s, %s with instructions only.%s %sLogged in %s%s\n' \
  "$BOLD" "$APPLIED" "$KEPT" "$SKIPPED" "$GUIDED" "$RST" "$DIM" "$FIXLOG" "$RST"
if [ "$APPLIED" -gt 0 ] || [ "$KEPT" -gt 0 ]; then
  read -r -p "  ${BOLD}Scan again so the report shows before and after?${RST} [y/N] " R </dev/tty
  case "$R" in [yY]|[yY][eE][sS]) exec "$DIR/neptune.sh" ;; esac
fi
exit 0
