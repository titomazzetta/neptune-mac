#!/bin/bash
#
# remove_mackeeper.sh — Complete MacKeeper/Clario removal
# Built for Tito's Mac Pro, 2026-07-02, based on actual find(1) inventory.
#
# Usage:
#   chmod +x remove_mackeeper.sh
#   ./remove_mackeeper.sh          (do NOT run with sudo — it elevates only where needed)
#
# The script is staged:
#   1. Deactivate the Endpoint Security system extension (while app still exists)
#   2. Kill processes and unload all launchd persistence
#   3. Delete every known file/directory
#   4. Verify and report
#
# It asks for confirmation before the destructive stage and prints
# everything it does. Re-runnable: already-deleted items are skipped silently.

set -u

BOLD=$(tput bold 2>/dev/null || true)
RED=$(tput setaf 1 2>/dev/null || true)
GRN=$(tput setaf 2 2>/dev/null || true)
YEL=$(tput setaf 3 2>/dev/null || true)
RST=$(tput sgr0 2>/dev/null || true)

info()  { echo "${BOLD}==>${RST} $*"; }
ok()    { echo "  ${GRN}[ok]${RST} $*"; }
warn()  { echo "  ${YEL}[!!]${RST} $*"; }
fail()  { echo "  ${RED}[XX]${RST} $*"; }

FAILED_PATHS=()

# Refuse to run as root — user-level launchctl bootout needs the real user session
if [ "$(id -u)" -eq 0 ]; then
  echo "${RED}Do not run this script with sudo.${RST} Run it as your normal user;"
  echo "it will prompt for your password only where root is required."
  exit 1
fi

echo
echo "${BOLD}MacKeeper / Clario complete removal${RST}"
echo "This will permanently delete MacKeeper, its system extension,"
echo "privileged helper, launch agents, Safari extensions, and all data."
echo
read -r -p "Proceed? [y/N] " REPLY
case "$REPLY" in
  [yY]|[yY][eE][sS]) ;;
  *) echo "Aborted. Nothing was changed."; exit 0 ;;
esac

# Cache sudo credentials up front so prompts don't interleave with output
info "Requesting administrator privileges (sudo)..."
sudo -v || { fail "Could not obtain sudo. Aborting."; exit 1; }
# Keep sudo alive for the duration of the script
( while true; do sudo -n true 2>/dev/null; sleep 50; done ) &
SUDO_KEEPALIVE=$!
trap 'kill $SUDO_KEEPALIVE 2>/dev/null' EXIT

############################################################
# STAGE 1 — System extension (must happen BEFORE app deletion)
############################################################
info "Stage 1: Endpoint Security system extension"

if systemextensionsctl list 2>/dev/null | grep -qi 'com.mackeeper'; then
  warn "MacKeeper system extension is registered. Attempting deactivation..."
  # Team ID for MacKeeper/Clario appears in the systemextensionsctl listing;
  # deactivate takes <teamID> <bundleID>. Extract it dynamically.
  MK_LINE=$(systemextensionsctl list 2>/dev/null | grep -i 'com.mackeeper' | head -1)
  MK_TEAM=$(echo "$MK_LINE" | grep -oE '\b[A-Z0-9]{10}\b' | head -1)
  if [ -n "${MK_TEAM:-}" ]; then
    sudo systemextensionsctl deactivate "$MK_TEAM" com.mackeeper.AntivirusEndpointSecurity \
      && ok "System extension deactivation requested (may prompt / may require reboot)" \
      || warn "Deactivation command failed — will rely on app deletion + reboot to orphan-remove it"
  else
    warn "Could not parse team ID from: $MK_LINE"
    warn "Extension will be flagged for cleanup when the app is deleted; a reboot finalizes it."
  fi
else
  ok "No MacKeeper system extension registered — nothing to deactivate"
fi

############################################################
# STAGE 2 — Kill processes, unload persistence
############################################################
info "Stage 2: Stopping processes and unloading launchd items"

sudo pkill -if mackeeper 2>/dev/null && ok "Killed running MacKeeper processes" || ok "No MacKeeper processes running"
sudo pkill -if clario    2>/dev/null || true

USER_AGENTS=(
  com.mackeeper.MacKeeperAgent
  com.mackeeper.MacKeeper-Info
  com.mackeeper.MacKeeper-Reminder
  com.mackeeper.MacKeeperBannerNotificationService
  com.mackeeper.MacKeeperAlertNotificationService
)
for AGENT in "${USER_AGENTS[@]}"; do
  if launchctl print "gui/$(id -u)/$AGENT" >/dev/null 2>&1; then
    launchctl bootout "gui/$(id -u)/$AGENT" 2>/dev/null \
      && ok "Unloaded user agent: $AGENT" \
      || warn "Could not unload $AGENT (may already be gone)"
  else
    ok "Not loaded: $AGENT"
  fi
done

if sudo launchctl print system/com.mackeeper.MacKeeperPrivilegedHelper >/dev/null 2>&1; then
  sudo launchctl bootout system/com.mackeeper.MacKeeperPrivilegedHelper 2>/dev/null \
    && ok "Unloaded root helper: com.mackeeper.MacKeeperPrivilegedHelper" \
    || warn "Could not unload privileged helper"
else
  ok "Privileged helper not loaded"
fi

############################################################
# STAGE 3 — Delete files
############################################################
info "Stage 3: Deleting files"

# rm wrapper: tracks failures (usually TCC-protected paths)
zap() {
  # $1 = "sudo" or "user", remaining args = paths (globs expanded by caller shell)
  local MODE=$1; shift
  local P
  for P in "$@"; do
    [ -e "$P" ] || continue
    if [ "$MODE" = "sudo" ]; then
      sudo rm -rf "$P" 2>/dev/null
    else
      rm -rf "$P" 2>/dev/null
    fi
    if [ -e "$P" ]; then
      fail "Could not delete: $P"
      FAILED_PATHS+=("$P")
    else
      ok "Deleted: $P"
    fi
  done
}

# --- Root-level items ---
zap sudo \
  "/Applications/MacKeeper.app" \
  "/Library/LaunchDaemons/com.mackeeper.MacKeeperPrivilegedHelper.plist" \
  "/Library/PrivilegedHelperTools/com.mackeeper.MacKeeperPrivilegedHelper" \
  "/Library/Application Support/MacKeeper" \
  "/Library/Preferences/vpnwholesaler"

zap sudo /Library/Application\ Support/CrashReporter/MacKeeper*
zap sudo /Library/Logs/DiagnosticReports/MacKeeper*

# --- User launch agents ---
zap user "$HOME"/Library/LaunchAgents/com.mackeeper.*

# --- User application data ---
zap user \
  "$HOME/Library/Application Support/MacKeeper" \
  "$HOME/Library/Logs/MacKeeper"
zap user "$HOME"/Library/Application\ Support/com.mackeeper.*
zap user "$HOME"/Library/Application\ Support/CrashReporter/MacKeeper*
zap user "$HOME"/Library/Containers/com.mackeeper.*
zap user "$HOME"/Library/Application\ Scripts/com.mackeeper.*
zap user "$HOME"/Library/WebKit/com.mackeeper.*
zap user "$HOME"/Library/WebKit/com.apple.Safari/ContentExtensions/ContentExtension-com.mackeeper.*
zap user "$HOME"/Library/HTTPStorages/com.mackeeper.*
zap user "$HOME"/Library/Preferences/com.mackeeper.*
zap user "$HOME"/Library/Caches/com.mackeeper.*
zap user "$HOME"/Library/Caches/com.crashlytics.data/com.mackeeper.*

# --- TCC-protected areas (Safari, Cookies) — may need Full Disk Access ---
zap user "$HOME"/Library/Safari/Extensions/MacKeeper*
zap user "$HOME"/Library/Cookies/com.mackeeper.*

############################################################
# STAGE 4 — Verify
############################################################
info "Stage 4: Verification"

echo "  Scanning disk (this takes a minute)..."
LEFTOVERS=$(sudo find /Applications /Library "$HOME/Library" \
  \( -iname "*mackeeper*" -o -iname "*clario*" \) 2>/dev/null)

LOADED_USER=$(launchctl list 2>/dev/null | grep -i mackeeper || true)
LOADED_ROOT=$(sudo launchctl list 2>/dev/null | grep -i mackeeper || true)
SYSEXT=$(systemextensionsctl list 2>/dev/null | grep -i mackeeper || true)

echo
if [ -z "$LEFTOVERS" ] && [ -z "$LOADED_USER" ] && [ -z "$LOADED_ROOT" ] && [ -z "$SYSEXT" ]; then
  echo "${GRN}${BOLD}CLEAN.${RST} No MacKeeper/Clario files, launch items, or extensions remain."
else
  [ -n "$LOADED_USER$LOADED_ROOT" ] && { warn "Still loaded in launchd:"; echo "$LOADED_USER"; echo "$LOADED_ROOT"; }
  [ -n "$SYSEXT" ] && { warn "System extension still registered (a REBOOT usually clears this):"; echo "$SYSEXT"; }
  if [ -n "$LEFTOVERS" ]; then
    warn "Files remaining on disk:"
    echo "$LEFTOVERS" | sed 's/^/      /'
  fi
fi

if [ ${#FAILED_PATHS[@]} -gt 0 ]; then
  echo
  warn "${#FAILED_PATHS[@]} path(s) could not be deleted — likely macOS TCC protection."
  echo "      Fix: System Settings > Privacy & Security > Full Disk Access > enable Terminal,"
  echo "      then re-run this script. (Toggle it back off afterwards.)"
fi

echo
info "Done. ${BOLD}Reboot now${RST} to finalize system-extension removal, then check"
echo "    System Settings > General > Login Items — MacKeeper, CLARIO, and most"
echo "    likely the fake 'launchctl' entries should be gone."
echo
echo "    Reminder: cancel the subscription in your MacKeeper/Clario account if"
echo "    you haven't already — uninstalling does not stop billing."
