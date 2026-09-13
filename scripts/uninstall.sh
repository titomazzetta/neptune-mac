#!/bin/bash
#
# uninstall.sh — Complete, careful app removal for macOS
#
# Usage:
#   ./uninstall.sh "AppName"          e.g.  ./uninstall.sh "Spotify"
#   ./uninstall.sh "AppName" --deep   also match the vendor name in file search
#
# What it does, in order:
#   1. Finds the .app bundle and reads its bundle ID + vendor
#   2. Quits the app and kills its processes
#   3. Unloads and removes any launch agents/daemons/helpers it owns
#   4. Discovers every related file in the Library locations
#   5. SHOWS YOU EVERYTHING and asks once before deleting
#   6. Deletes, then verifies with a final scan
#
# Never deletes anything without showing it first. Never runs unattended.

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
die()  { echo "  ${RED}[XX]${RST} $*"; exit 1; }

if [ "$(id -u)" -eq 0 ]; then
  echo "Run as your normal user, not with sudo."; exit 1
fi

APPNAME="${1:-}"
DEEP=false
[ "${2:-}" = "--deep" ] && DEEP=true

if [ -z "$APPNAME" ]; then
  echo "Usage: $0 \"AppName\" [--deep]"
  echo "Installed applications:"
  for A in /Applications/*.app; do
    [ -e "$A" ] || continue
    echo "  $(basename "$A" .app)"
  done
  exit 1
fi

############################################################
# 1. Locate the app and identify it
############################################################
section "1. Locating '$APPNAME'"

APP_PATH=""
for CAND in "/Applications/$APPNAME.app" "/Applications/$APPNAME" "$HOME/Applications/$APPNAME.app"; do
  [ -d "$CAND" ] && APP_PATH="$CAND" && break
done
# Fuzzy fallback: first /Applications bundle whose name contains APPNAME,
# case-insensitively. Glob + `case` instead of `ls | grep` (SC2010).
# NOTE: the search term is now matched as a LITERAL substring rather than as a
# regex. For ordinary app names this is identical; for a name containing regex
# metacharacters it is strictly safer, since this value goes on to drive `find`
# and `pkill`. bash 3.2 safe: no ${var,,}, so `tr` does the case folding.
if [ -z "$APP_PATH" ]; then
  MATCH=""
  NEEDLE=$(printf '%s' "$APPNAME" | tr '[:upper:]' '[:lower:]')
  for A in /Applications/*.app; do
    [ -e "$A" ] || continue
    BUNDLE=$(basename "$A")
    HAYSTACK=$(printf '%s' "$BUNDLE" | tr '[:upper:]' '[:lower:]')
    case "$HAYSTACK" in
      *"$NEEDLE"*) MATCH="$BUNDLE"; break ;;
    esac
  done
  [ -n "$MATCH" ] && APP_PATH="/Applications/$MATCH"
fi

BUNDLE_ID=""
VENDOR=""
if [ -n "$APP_PATH" ]; then
  ok "Found: $APP_PATH"
  BUNDLE_ID=$(defaults read "$APP_PATH/Contents/Info" CFBundleIdentifier 2>/dev/null || true)
  [ -n "$BUNDLE_ID" ] && ok "Bundle ID: $BUNDLE_ID"
  # Vendor = second segment of reverse-DNS bundle id (com.VENDOR.app)
  VENDOR=$(echo "$BUNDLE_ID" | awk -F. '{print $2}')
else
  warn "No .app bundle found — will still search for leftover files."
  warn "(Useful for apps already dragged to Trash that left residue behind.)"
fi

# Search terms: app name always; bundle id if known; vendor only with --deep
SHORTNAME=$(basename "${APP_PATH:-$APPNAME}" .app)

############################################################
# 2. Stop it
############################################################
section "2. Stopping processes"

if [ -n "$APP_PATH" ]; then
  osascript -e "quit app \"$SHORTNAME\"" 2>/dev/null
  sleep 1
fi
pkill -if "$SHORTNAME" 2>/dev/null && ok "Killed running processes" || ok "No processes running"

############################################################
# 3. Launch agents / daemons / helpers
############################################################
section "3. Persistence owned by this app"

PLISTS=()
for DIR in "$HOME/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons; do
  [ -d "$DIR" ] || continue
  while IFS= read -r P; do
    PLISTS+=("$P")
  done < <(grep -il -e "$SHORTNAME" ${BUNDLE_ID:+-e "$BUNDLE_ID"} "$DIR"/*.plist 2>/dev/null)
done

HELPERS=()
if [ -n "$BUNDLE_ID" ]; then
  while IFS= read -r H; do
    HELPERS+=("$H")
  done < <(find /Library/PrivilegedHelperTools -maxdepth 1 -iname "*${VENDOR:-$SHORTNAME}*" 2>/dev/null)
fi

if [ ${#PLISTS[@]} -eq 0 ] && [ ${#HELPERS[@]} -eq 0 ]; then
  ok "No launch items or privileged helpers found"
else
  for P in ${PLISTS[@]:+"${PLISTS[@]}"}; do warn "Launch item: $P"; done
  for H in ${HELPERS[@]:+"${HELPERS[@]}"}; do warn "Privileged helper: $H"; done
fi

############################################################
# 4. Discover related files
############################################################
section "4. Discovering related files (this can take a moment)"

SEARCH_DIRS=(
  "$HOME/Library/Application Support"
  "$HOME/Library/Caches"
  "$HOME/Library/Preferences"
  "$HOME/Library/Preferences/ByHost"
  "$HOME/Library/Logs"
  "$HOME/Library/Containers"
  "$HOME/Library/Group Containers"
  "$HOME/Library/Application Scripts"
  "$HOME/Library/WebKit"
  "$HOME/Library/HTTPStorages"
  "$HOME/Library/Saved Application State"
  "$HOME/Library/Cookies"
  "/Library/Application Support"
  "/Library/Caches"
  "/Library/Preferences"
)

FOUND=()
add_found() { local F; for F in "$@"; do [ -e "$F" ] && FOUND+=("$F"); done; }

for DIR in "${SEARCH_DIRS[@]}"; do
  [ -d "$DIR" ] || continue
  # Match by app name
  while IFS= read -r F; do FOUND+=("$F"); done \
    < <(find "$DIR" -maxdepth 1 -iname "*${SHORTNAME}*" 2>/dev/null)
  # Match by bundle id
  if [ -n "$BUNDLE_ID" ]; then
    while IFS= read -r F; do FOUND+=("$F"); done \
      < <(find "$DIR" -maxdepth 1 -iname "*${BUNDLE_ID}*" 2>/dev/null)
  fi
  # Vendor match only in deep mode (broader, riskier — review carefully)
  if $DEEP && [ -n "$VENDOR" ]; then
    while IFS= read -r F; do FOUND+=("$F"); done \
      < <(find "$DIR" -maxdepth 1 -iname "*${VENDOR}*" 2>/dev/null)
  fi
done

# De-duplicate
UNIQUE=()
while IFS= read -r F; do UNIQUE+=("$F"); done < <(printf '%s\n' "${FOUND[@]:-}" | sort -u | grep -v '^$')

############################################################
# 5. Review and confirm
############################################################
section "5. Review — everything that will be deleted"

TOTAL=0
[ -n "$APP_PATH" ] && { echo "  ${BOLD}App:${RST}"; echo "      $APP_PATH"; TOTAL=$((TOTAL+1)); }
if [ ${#PLISTS[@]} -gt 0 ] || [ ${#HELPERS[@]} -gt 0 ]; then
  echo "  ${BOLD}Persistence:${RST}"
  for P in ${PLISTS[@]:+"${PLISTS[@]}"}; do echo "      $P"; TOTAL=$((TOTAL+1)); done
  for H in ${HELPERS[@]:+"${HELPERS[@]}"}; do echo "      $H"; TOTAL=$((TOTAL+1)); done
fi
if [ ${#UNIQUE[@]} -gt 0 ]; then
  echo "  ${BOLD}Library files:${RST}"
  for F in ${UNIQUE[@]:+"${UNIQUE[@]}"}; do
    SIZE=$(du -sh "$F" 2>/dev/null | awk '{print $1}')
    echo "      [$SIZE] $F"
    TOTAL=$((TOTAL+1))
  done
fi

if [ "$TOTAL" -eq 0 ]; then
  echo "  Nothing found for '$APPNAME'. Check the spelling, or try --deep."
  exit 0
fi

echo
echo "  ${BOLD}$TOTAL item(s) total.${RST} Review the list above carefully —"
echo "  especially any entries that look like they belong to OTHER software."
$DEEP && warn "Deep mode matched on vendor '$VENDOR' — extra scrutiny warranted."
echo
read -r -p "  Delete ALL of the above? [y/N] " REPLY
case "$REPLY" in [yY]|[yY][eE][sS]) ;; *) echo "  Aborted. Nothing was changed."; exit 0 ;; esac

sudo -v || die "Could not obtain sudo"

############################################################
# 6. Delete
############################################################
section "6. Deleting"

FAILED=()

# Unload persistence first
for P in ${PLISTS[@]:+"${PLISTS[@]}"}; do
  LABEL=$(basename "$P" .plist)
  case "$P" in
    "$HOME"/*) launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null ;;
    *)         sudo launchctl bootout "system/$LABEL" 2>/dev/null
               sudo launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null ;;
  esac
done

zap() {
  local F=$1
  case "$F" in
    "$HOME"/*) rm -rf "$F" 2>/dev/null ;;
    *)         sudo rm -rf "$F" 2>/dev/null ;;
  esac
  if [ -e "$F" ]; then
    FAILED+=("$F"); echo "  ${RED}[XX]${RST} $F"
  else
    ok "$F"
  fi
}

[ -n "$APP_PATH" ] && zap "$APP_PATH"
for P in ${PLISTS[@]:+"${PLISTS[@]}"}; do zap "$P"; done
for H in ${HELPERS[@]:+"${HELPERS[@]}"}; do zap "$H"; done
for F in ${UNIQUE[@]:+"${UNIQUE[@]}"}; do zap "$F"; done

############################################################
# 7. Verify
############################################################
section "7. Verification"

LEFT=$(find /Applications "$HOME/Library" /Library -maxdepth 3 -iname "*${SHORTNAME}*" 2>/dev/null | head -10)
if [ -z "$LEFT" ] && [ ${#FAILED[@]} -eq 0 ]; then
  echo "  ${GRN}${BOLD}CLEAN.${RST} '$SHORTNAME' fully removed."
else
  [ -n "$LEFT" ] && { warn "Still matching '$SHORTNAME' on disk:"; echo "$LEFT" | sed 's/^/      /'; }
  if [ ${#FAILED[@]} -gt 0 ]; then
    warn "${#FAILED[@]} item(s) could not be deleted — likely TCC protection."
    echo "      Fix: System Settings > Privacy & Security > Full Disk Access > Terminal,"
    echo "      then re-run this script (safe to re-run). Toggle it off after."
  fi
fi

echo
echo "  Note: if this app appeared in sentry's baseline, run ./sentry.sh --rebaseline"
echo "  after you're done removing things, to lock in the new state."
