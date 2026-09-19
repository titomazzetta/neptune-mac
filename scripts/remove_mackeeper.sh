#!/bin/bash
#
# remove_mackeeper.sh — Complete MacKeeper/Clario removal
# Built for a real infection, 2026-07-02, from an actual find(1) inventory.
#
# Usage:
#   chmod +x remove_mackeeper.sh
#   ./remove_mackeeper.sh             (do NOT run with sudo — it elevates only where needed)
#   ./remove_mackeeper.sh --dry-run   show exactly what would be removed, change nothing
#
# The script is staged:
#   1. INVENTORY — find every known file, launch item, process and extension
#   2. SHOW the complete list and ask once
#   3. Deactivate the Endpoint Security system extension (app must still exist)
#   4. Stop processes and unload all launchd persistence
#   5. Delete every inventoried path
#   6. Verify and report
#
# Stages 1 and 2 changed in the 2026-09 audit. The script used to ask "Proceed?"
# before it had looked at anything, then deactivate, kill and delete while
# narrating. That meant the user agreed to a description rather than to a list —
# and CLAUDE.md's rule for the destructive scripts is that both MUST show
# everything first. It was true of uninstall.sh and false here. Now nothing
# mutates until after the inventory is on screen.

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

DRYRUN=false
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRYRUN=true ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
  shift
done

# Sandbox root — see the long note in uninstall.sh. Same contract: it can only
# narrow what this script can reach, sudo is refused while it is set, and
# tests/blast_radius.sh is the reason it exists.
ROOT="${NEPTUNE_ROOT:-}"
SANDBOX=false
if [ -n "$ROOT" ]; then
  SANDBOX=true
  # A prefix check alone is not containment: "$ROOT/../elsewhere" starts with
  # "$ROOT/" and still escapes it. Reject any HOME containing a parent
  # reference, then require the prefix. (Found by tests/blast_radius.sh, which
  # is the argument for having written it.)
  case "$HOME" in
    *..*) echo "HOME ('$HOME') contains '..' — refusing to resolve it." >&2
          echo "Refusing to run: a half-redirected removal is worse than none." >&2
          exit 1 ;;
  esac
  case "$HOME" in
    "$ROOT"/*) ;;
    *) echo "NEPTUNE_ROOT is set to '$ROOT' but HOME ('$HOME') is outside it." >&2
       echo "Refusing to run: a half-redirected removal is worse than none." >&2
       exit 1 ;;
  esac
fi
APPS_DIR="$ROOT/Applications"
SYS_LIB="$ROOT/Library"
run_priv() { if $SANDBOX; then "$@"; else sudo "$@"; fi; }

# The root guard does not apply in sandbox mode. It exists because running the
# whole script as root is a blast-radius problem and because user-level
# `launchctl bootout` needs the real user session — neither is true against a
# temporary directory with sudo disabled and launchctl never invoked. CI
# containers commonly run as root, and a test that can only pass on one kind of
# machine is a test people learn to ignore.
if [ "$(id -u)" -eq 0 ] && ! $SANDBOX; then
  echo "${RED}Do not run this script with sudo.${RST} Run it as your normal user;"
  echo "it will prompt for your password only where root is required."
  exit 1
fi

echo
echo "${BOLD}MacKeeper / Clario complete removal${RST}"
if $SANDBOX; then
  echo "${BOLD}${YEL}SANDBOX MODE${RST} — operating against '$ROOT', not the real system."
  echo "sudo is disabled for this run."
fi
echo

############################################################
# STAGE 1 — Inventory. Read-only. Nothing below this changes anything.
############################################################
info "Stage 1: Inventory (read-only)"

# TARGETS holds "mode<TAB>path" so the delete stage removes exactly what was
# displayed — never a fresh glob expansion after the fact, which could pick up
# something created between the confirmation and the rm.
TARGETS=()
collect() {
  local MODE=$1; shift
  local P
  for P in "$@"; do
    [ -e "$P" ] && TARGETS+=("$MODE	$P")
  done
}

# --- Root-level items ---
collect sudo \
  "$APPS_DIR/MacKeeper.app" \
  "$SYS_LIB/LaunchDaemons/com.mackeeper.MacKeeperPrivilegedHelper.plist" \
  "$SYS_LIB/PrivilegedHelperTools/com.mackeeper.MacKeeperPrivilegedHelper" \
  "$SYS_LIB/Application Support/MacKeeper" \
  "$SYS_LIB/Preferences/vpnwholesaler"
collect sudo "$SYS_LIB"/Application\ Support/CrashReporter/MacKeeper*
collect sudo "$SYS_LIB"/Logs/DiagnosticReports/MacKeeper*

# --- User launch agents ---
collect user "$HOME"/Library/LaunchAgents/com.mackeeper.*

# --- User application data ---
collect user \
  "$HOME/Library/Application Support/MacKeeper" \
  "$HOME/Library/Logs/MacKeeper"
collect user "$HOME"/Library/Application\ Support/com.mackeeper.*
collect user "$HOME"/Library/Application\ Support/CrashReporter/MacKeeper*
collect user "$HOME"/Library/Containers/com.mackeeper.*
collect user "$HOME"/Library/Application\ Scripts/com.mackeeper.*
collect user "$HOME"/Library/WebKit/com.mackeeper.*
collect user "$HOME"/Library/WebKit/com.apple.Safari/ContentExtensions/ContentExtension-com.mackeeper.*
collect user "$HOME"/Library/HTTPStorages/com.mackeeper.*
collect user "$HOME"/Library/Preferences/com.mackeeper.*
collect user "$HOME"/Library/Caches/com.mackeeper.*
collect user "$HOME"/Library/Caches/com.crashlytics.data/com.mackeeper.*

# --- TCC-protected areas (Safari, Cookies) — may need Full Disk Access ---
collect user "$HOME"/Library/Safari/Extensions/MacKeeper*
collect user "$HOME"/Library/Cookies/com.mackeeper.*

# Live state: looked at, not touched.
SYSEXT_LINE=""
LOADED_AGENTS=()
RUNNING=""
if ! $SANDBOX; then
  SYSEXT_LINE=$(systemextensionsctl list 2>/dev/null | grep -i 'com.mackeeper' | head -1 || true)
  for AGENT in com.mackeeper.MacKeeperAgent \
               com.mackeeper.MacKeeper-Info \
               com.mackeeper.MacKeeper-Reminder \
               com.mackeeper.MacKeeperBannerNotificationService \
               com.mackeeper.MacKeeperAlertNotificationService; do
    launchctl print "gui/$(id -u)/$AGENT" >/dev/null 2>&1 && LOADED_AGENTS+=("$AGENT")
  done
  RUNNING=$(pgrep -il -f 'mackeeper\|clario' 2>/dev/null | grep -v "^$$ " || true)
fi

############################################################
# STAGE 2 — Show everything, then ask
############################################################
info "Stage 2: Review"

TOTAL=${#TARGETS[@]}
if [ "$TOTAL" -eq 0 ] && [ -z "$SYSEXT_LINE" ] && [ ${#LOADED_AGENTS[@]} -eq 0 ] && [ -z "$RUNNING" ]; then
  echo
  ok "Nothing found. No MacKeeper or Clario files, launch items, processes or"
  ok "extensions are present. There is nothing to remove."
  exit 0
fi

if [ "$TOTAL" -gt 0 ]; then
  echo "  ${BOLD}Files and directories to delete ($TOTAL):${RST}"
  for T in ${TARGETS[@]:+"${TARGETS[@]}"}; do
    MODE=${T%%	*}; P=${T#*	}
    SIZE=$(du -sh "$P" 2>/dev/null | awk '{print $1}')
    printf '      [%s] %-6s %s\n' "${SIZE:-?}" "$MODE" "$P"
  done
fi
if [ -n "$RUNNING" ]; then
  echo "  ${BOLD}Processes to stop:${RST}"
  echo "$RUNNING" | sed 's/^/      /'
fi
if [ ${#LOADED_AGENTS[@]} -gt 0 ]; then
  echo "  ${BOLD}Launch agents to unload:${RST}"
  for A in ${LOADED_AGENTS[@]:+"${LOADED_AGENTS[@]}"}; do echo "      $A"; done
fi
if [ -n "$SYSEXT_LINE" ]; then
  echo "  ${BOLD}System extension to deactivate:${RST}"
  echo "      $SYSEXT_LINE"
  echo "      (Endpoint Security extension — deactivation may prompt and may need a reboot.)"
fi

if $DRYRUN; then
  echo
  echo "  ${BOLD}DRY RUN — nothing was changed and nothing will be.${RST}"
  echo
  echo "DELETE-SET BEGIN"
  for T in ${TARGETS[@]:+"${TARGETS[@]}"}; do
    MODE=${T%%	*}; P=${T#*	}
    printf '%s\t%s\n' "$MODE" "$P"
  done
  echo "DELETE-SET END"
  exit 0
fi

echo
echo "  Everything above will be permanently deleted. This does not cancel a"
echo "  MacKeeper or Clario subscription — do that in your account separately."
echo
read -r -p "  Proceed? [y/N] " REPLY
case "$REPLY" in
  [yY]|[yY][eE][sS]) ;;
  *) echo "  Aborted. Nothing was changed."; exit 0 ;;
esac

if ! $SANDBOX; then
  info "Requesting administrator privileges (sudo)..."
  sudo -v || { fail "Could not obtain sudo. Aborting."; exit 1; }
  ( while true; do sudo -n true 2>/dev/null; sleep 50; done ) &
  SUDO_KEEPALIVE=$!
  trap 'kill $SUDO_KEEPALIVE 2>/dev/null' EXIT
fi

############################################################
# STAGE 3 — System extension (must happen BEFORE app deletion)
############################################################
info "Stage 3: Endpoint Security system extension"

if [ -n "$SYSEXT_LINE" ]; then
  # deactivate takes <teamID> <bundleID>; the team ID is in the listing line.
  MK_TEAM=$(echo "$SYSEXT_LINE" | grep -oE '\b[A-Z0-9]{10}\b' | head -1)
  if [ -n "${MK_TEAM:-}" ]; then
    sudo systemextensionsctl deactivate "$MK_TEAM" com.mackeeper.AntivirusEndpointSecurity \
      && ok "System extension deactivation requested (may prompt / may require reboot)" \
      || warn "Deactivation failed — will rely on app deletion + reboot to orphan-remove it"
  else
    warn "Could not parse team ID from: $SYSEXT_LINE"
    warn "Extension will be flagged for cleanup when the app is deleted; a reboot finalizes it."
  fi
else
  ok "No MacKeeper system extension registered — nothing to deactivate"
fi

############################################################
# STAGE 4 — Stop processes, unload persistence
############################################################
info "Stage 4: Stopping processes and unloading launchd items"

if ! $SANDBOX; then
  if [ -n "$RUNNING" ]; then
    # By PID, from the list shown above — not a fresh pkill pattern, which could
    # match something started since the confirmation.
    echo "$RUNNING" | while read -r LINE; do
      PID=${LINE%% *}
      [ -n "$PID" ] && kill "$PID" 2>/dev/null && ok "Asked pid $PID to quit"
    done
    sleep 1
    echo "$RUNNING" | while read -r LINE; do
      PID=${LINE%% *}
      if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
        kill -9 "$PID" 2>/dev/null && warn "pid $PID ignored SIGTERM — force-stopped"
      fi
    done
  else
    ok "No MacKeeper processes running"
  fi

  for AGENT in ${LOADED_AGENTS[@]:+"${LOADED_AGENTS[@]}"}; do
    launchctl bootout "gui/$(id -u)/$AGENT" 2>/dev/null \
      && ok "Unloaded user agent: $AGENT" \
      || warn "Could not unload $AGENT (may already be gone)"
  done

  if sudo launchctl print system/com.mackeeper.MacKeeperPrivilegedHelper >/dev/null 2>&1; then
    sudo launchctl bootout system/com.mackeeper.MacKeeperPrivilegedHelper 2>/dev/null \
      && ok "Unloaded root helper: com.mackeeper.MacKeeperPrivilegedHelper" \
      || warn "Could not unload privileged helper"
  else
    ok "Privileged helper not loaded"
  fi
fi

############################################################
# STAGE 5 — Delete exactly what was inventoried
############################################################
info "Stage 5: Deleting"

for T in ${TARGETS[@]:+"${TARGETS[@]}"}; do
  MODE=${T%%	*}; P=${T#*	}
  [ -e "$P" ] || continue
  if [ "$MODE" = "sudo" ]; then
    run_priv rm -rf "$P" 2>/dev/null
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

############################################################
# STAGE 6 — Verify
############################################################
info "Stage 6: Verification"

echo "  Scanning disk (this takes a minute)..."
LEFTOVERS=$(run_priv find "$APPS_DIR" "$SYS_LIB" "$HOME/Library" \
  \( -iname "*mackeeper*" -o -iname "*clario*" \) 2>/dev/null)

LOADED_USER=""; LOADED_ROOT=""; SYSEXT=""
if ! $SANDBOX; then
  LOADED_USER=$(launchctl list 2>/dev/null | grep -i mackeeper || true)
  LOADED_ROOT=$(sudo launchctl list 2>/dev/null | grep -i mackeeper || true)
  SYSEXT=$(systemextensionsctl list 2>/dev/null | grep -i mackeeper || true)
fi

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
