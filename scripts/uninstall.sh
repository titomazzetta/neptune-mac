#!/bin/bash
#
# uninstall.sh — Complete, careful app removal for macOS
#
# Usage:
#   ./uninstall.sh "AppName"             e.g.  ./uninstall.sh "Spotify"
#   ./uninstall.sh "AppName" --deep      also match the vendor name in file search
#   ./uninstall.sh "AppName" --dry-run   show the exact delete set and stop
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

APPNAME=""
DEEP=false
DRYRUN=false
while [ $# -gt 0 ]; do
  case "$1" in
    --deep)    DEEP=true ;;
    --dry-run) DRYRUN=true ;;
    -*)        echo "Unknown option: $1" >&2; exit 1 ;;
    *)         [ -z "$APPNAME" ] && APPNAME="$1" || { echo "Only one app name, please." >&2; exit 1; } ;;
  esac
  shift
done

# ---------------------------------------------------------------------------
# Sandbox root. Empty in every normal run, which is the only supported
# configuration for actually removing software.
#
# tests/blast_radius.sh sets it to a temporary directory holding a fake
# /Applications, /Library and home, so CI can assert the exact set of paths this
# script would delete for a known app layout — and, more to the point, assert
# that a decoy belonging to different software is never in that set. Without a
# seam like this there is no way to test the only part of Neptune that runs
# `rm -rf` as root, and "we read it carefully" is not a test.
#
# It can only ever NARROW what this script touches. Every path is built from the
# prefix and discovery only looks inside it, so a sandbox run cannot reach
# anything the prefix does not contain. When it is set the script refuses sudo
# outright and says so on screen, so it cannot escalate either.
# ---------------------------------------------------------------------------
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
          echo "Refusing to run: a half-redirected uninstall is worse than none." >&2
          exit 1 ;;
  esac
  case "$HOME" in
    "$ROOT"/*) ;;
    *) echo "NEPTUNE_ROOT is set to '$ROOT' but HOME ('$HOME') is outside it." >&2
       echo "Refusing to run: a half-redirected uninstall is worse than none." >&2
       exit 1 ;;
  esac
fi
APPS_DIR="$ROOT/Applications"
SYS_LIB="$ROOT/Library"

# In sandbox mode there is no sudo and nothing that needs it.
run_priv() { if $SANDBOX; then "$@"; else sudo "$@"; fi; }

# The root guard does not apply in sandbox mode. It exists because running the
# whole script as root is a blast-radius problem and because user-level
# `launchctl bootout` needs the real user session — neither is true against a
# temporary directory with sudo disabled and launchctl never invoked. CI
# containers commonly run as root, and a test that can only pass on one kind of
# machine is a test people learn to ignore.
if [ "$(id -u)" -eq 0 ] && ! $SANDBOX; then
  echo "Run as your normal user, not with sudo."; exit 1
fi

if [ -z "$APPNAME" ]; then
  echo "Usage: $0 \"AppName\" [--deep] [--dry-run]"
  echo "Installed applications:"
  for A in "$APPS_DIR"/*.app; do
    [ -e "$A" ] || continue
    echo "  $(basename "$A" .app)"
  done
  exit 1
fi

if $SANDBOX; then
  echo "${BOLD}${YEL}SANDBOX MODE${RST} — operating against '$ROOT', not the real system."
  echo "  sudo is disabled for this run. Nothing outside that directory is reachable."
  echo
fi

############################################################
# 1. Locate the app and identify it
############################################################
section "1. Locating '$APPNAME'"

APP_PATH=""
for CAND in "$APPS_DIR/$APPNAME.app" "$APPS_DIR/$APPNAME" "$HOME/Applications/$APPNAME.app"; do
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
  for A in "$APPS_DIR"/*.app; do
    [ -e "$A" ] || continue
    BUNDLE=$(basename "$A")
    HAYSTACK=$(printf '%s' "$BUNDLE" | tr '[:upper:]' '[:lower:]')
    case "$HAYSTACK" in
      *"$NEEDLE"*) MATCH="$BUNDLE"; break ;;
    esac
  done
  [ -n "$MATCH" ] && APP_PATH="$APPS_DIR/$MATCH"
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
section "2. Processes matching '$SHORTNAME'"

# READ-ONLY. This stage used to run `pkill -if "$SHORTNAME"` right here — before
# the user had seen a single thing or agreed to anything. Terminating processes
# is a mutation, and `-f` matches the whole command line case-insensitively, so
# a short or generic search term ("code", "Go", "Box") silently killed an
# unpredictable set of unrelated programs. The script's own guarantee is "never
# does anything without showing it first"; that was true of files and false of
# processes.
#
# Now: list here, confirm in stage 5, and stop in stage 6 BY PID — exactly the
# processes that were displayed, never a fresh pattern match after the fact.
PROC_PIDS=""
if $SANDBOX; then
  # The process table belongs to the real machine, not to $ROOT. Scanning it in
  # sandbox mode would list processes this run cannot and must not touch.
  ok "Sandbox mode — process scan skipped (the process table is not sandboxed)"
elif [ ${#SHORTNAME} -lt 3 ]; then
  warn "Search term '$SHORTNAME' is under 3 characters — process scan skipped."
  warn "A term that short matches almost anything. Quit the app yourself first."
else
  while IFS= read -r LINE; do
    [ -z "$LINE" ] && continue
    PROC_PIDS="$PROC_PIDS ${LINE%% *}"
    warn "Running: $LINE"
  done < <(pgrep -il -f "$SHORTNAME" 2>/dev/null | grep -v "^$$ ")
fi
[ -z "$PROC_PIDS" ] && ok "No matching processes running"

############################################################
# 3. Launch agents / daemons / helpers
############################################################
section "3. Persistence owned by this app"

PLISTS=()
for DIR in "$HOME/Library/LaunchAgents" "$SYS_LIB/LaunchAgents" "$SYS_LIB/LaunchDaemons"; do
  [ -d "$DIR" ] || continue
  while IFS= read -r P; do
    PLISTS+=("$P")
  done < <(grep -il -e "$SHORTNAME" ${BUNDLE_ID:+-e "$BUNDLE_ID"} "$DIR"/*.plist 2>/dev/null)
done

HELPERS=()
if [ -n "$BUNDLE_ID" ]; then
  while IFS= read -r H; do
    HELPERS+=("$H")
  done < <(find "$SYS_LIB/PrivilegedHelperTools" -maxdepth 1 -iname "*${VENDOR:-$SHORTNAME}*" 2>/dev/null)
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
  "$SYS_LIB/Application Support"
  "$SYS_LIB/Caches"
  "$SYS_LIB/Preferences"
)

FOUND=()
NEARMISS=()

# ---------------------------------------------------------------------------
# A bare `-iname "*NAME*"` is an over-match, and tests/blast_radius.sh caught it
# doing real damage: removing "Dovetail" also selected DovetailPro's preferences
# and an unrelated vendor's cache, because both contain the string "dovetail".
# On a real Mac that is `./uninstall.sh Mail` taking MailMate's data with it.
#
# The term must therefore match as a WHOLE WORD: bounded at both ends by a
# non-alphanumeric character or by the start/end of the filename. Every real
# filename shape still matches —
#     Dovetail                     exact
#     Dovetail Helper              followed by a space
#     com.acme.dovetail.plist      surrounded by dots
# — while dovetailpro and acmecorp.dovetailer do not.
#
# Near misses are NOT silently dropped. They are collected and displayed under
# their own heading, because "the script considered this and excluded it" is
# information the person reviewing a delete list should have. Silently doing
# less than expected is its own kind of surprise.
#
# bash 3.2: `case` with a quoted variable in the pattern matches it literally,
# so a term containing glob metacharacters cannot widen the match.
# ---------------------------------------------------------------------------
lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

whole_word() {  # <haystack> <needle> — both lowercased by the caller
  local H=$1 N=$2
  case "$H" in
    "$N")                     return 0 ;;
    "$N"[!a-z0-9]*)           return 0 ;;
    *[!a-z0-9]"$N")           return 0 ;;
    *[!a-z0-9]"$N"[!a-z0-9]*) return 0 ;;
  esac
  return 1
}

sift() {  # <needle> — reads candidate paths on stdin, sorts them into the lists
  local NEEDLE BASE F
  NEEDLE=$(lower "$1")
  while IFS= read -r F; do
    [ -n "$F" ] || continue
    BASE=$(lower "$(basename "$F")")
    if whole_word "$BASE" "$NEEDLE"; then
      FOUND+=("$F")
    else
      NEARMISS+=("$F")
    fi
  done
}

for DIR in "${SEARCH_DIRS[@]}"; do
  [ -d "$DIR" ] || continue
  # Match by app name
  sift "$SHORTNAME" < <(find "$DIR" -maxdepth 1 -iname "*${SHORTNAME}*" 2>/dev/null)
  # Match by bundle id
  if [ -n "$BUNDLE_ID" ]; then
    sift "$BUNDLE_ID" < <(find "$DIR" -maxdepth 1 -iname "*${BUNDLE_ID}*" 2>/dev/null)
  fi
  # Vendor match only in deep mode (broader, riskier — review carefully)
  if $DEEP && [ -n "$VENDOR" ]; then
    sift "$VENDOR" < <(find "$DIR" -maxdepth 1 -iname "*${VENDOR}*" 2>/dev/null)
  fi
done

# De-duplicate
UNIQUE=()
while IFS= read -r F; do UNIQUE+=("$F"); done < <(printf '%s\n' "${FOUND[@]:-}" | sort -u | grep -v '^$')

# A path that matched one term as a whole word and another only as a substring
# belongs in the delete set, not in the near-miss list.
EXCLUDED=()
while IFS= read -r F; do
  [ -n "$F" ] || continue
  printf '%s\n' ${UNIQUE[@]:+"${UNIQUE[@]}"} | grep -qxF "$F" || EXCLUDED+=("$F")
done < <(printf '%s\n' "${NEARMISS[@]:-}" | sort -u | grep -v '^$')

############################################################
# 5. Review and confirm
############################################################
section "5. Review — everything that will be deleted"

TOTAL=0
[ -n "$APP_PATH" ] && { echo "  ${BOLD}App:${RST}"; echo "      $APP_PATH"; TOTAL=$((TOTAL+1)); }
if [ -n "$PROC_PIDS" ]; then
  echo "  ${BOLD}Running processes (these will be stopped first):${RST}"
  for P in $PROC_PIDS; do
    echo "      pid $P  $(ps -p "$P" -o comm= 2>/dev/null)"
    TOTAL=$((TOTAL+1))
  done
fi
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

if [ ${#EXCLUDED[@]} -gt 0 ]; then
  echo "  ${BOLD}Excluded — '$SHORTNAME' appears only inside a longer word:${RST}"
  for F in ${EXCLUDED[@]:+"${EXCLUDED[@]}"}; do echo "      $F"; done
  echo "      These are NOT in the delete set. They almost always belong to"
  echo "      different software. If one really is yours, remove it by hand."
fi

if [ "$TOTAL" -eq 0 ]; then
  echo "  Nothing found for '$APPNAME'. Check the spelling, or try --deep."
  exit 0
fi

echo
echo "  ${BOLD}$TOTAL item(s) total.${RST} Review the list above carefully —"
echo "  especially any entries that look like they belong to OTHER software."
$DEEP && warn "Deep mode matched on vendor '$VENDOR' — extra scrutiny warranted."

# --dry-run stops here, before the confirmation prompt and before sudo is even
# requested. Everything above this line is discovery; everything below it
# mutates. There is deliberately no flag that skips the prompt — dry-run exists
# so you can see the blast radius without agreeing to it, which is the opposite
# of a --yes flag and the reason it is safe to add.
#
# The machine-readable block is what tests/blast_radius.sh asserts against.
if $DRYRUN; then
  echo
  echo "  ${BOLD}DRY RUN — nothing was changed and nothing will be.${RST}"
  echo "  Re-run without --dry-run to be asked for confirmation."
  echo
  echo "DELETE-SET BEGIN"
  [ -n "$APP_PATH" ] && printf 'app\t%s\n' "$APP_PATH"
  for P in $PROC_PIDS; do printf 'process\t%s\n' "$P"; done
  for P in ${PLISTS[@]:+"${PLISTS[@]}"}; do printf 'launch\t%s\n' "$P"; done
  for H in ${HELPERS[@]:+"${HELPERS[@]}"}; do printf 'helper\t%s\n' "$H"; done
  for F in ${UNIQUE[@]:+"${UNIQUE[@]}"}; do printf 'file\t%s\n' "$F"; done
  echo "DELETE-SET END"
  exit 0
fi

echo
read -r -p "  Stop those processes and delete ALL of the above? [y/N] " REPLY
case "$REPLY" in [yY]|[yY][eE][sS]) ;; *) echo "  Aborted. Nothing was changed."; exit 0 ;; esac

$SANDBOX || sudo -v || die "Could not obtain sudo"

############################################################
# 6. Delete
############################################################
section "6. Deleting"

FAILED=()

# Stop processes now — after the confirmation, and only the PIDs shown above.
# Killing by stored PID rather than re-running a pattern match means what gets
# terminated is exactly what the user approved, even if something else started
# in the meantime that happens to match the name.
if [ -n "$PROC_PIDS" ] && ! $SANDBOX; then
  [ -n "$APP_PATH" ] && { osascript -e "quit app \"$SHORTNAME\"" 2>/dev/null; sleep 1; }
  for P in $PROC_PIDS; do
    kill "$P" 2>/dev/null && ok "Asked pid $P to quit"
  done
  sleep 1
  for P in $PROC_PIDS; do
    if kill -0 "$P" 2>/dev/null; then
      kill -9 "$P" 2>/dev/null && warn "pid $P ignored SIGTERM — force-stopped"
    fi
  done
fi

# Unload persistence first
if ! $SANDBOX; then
  for P in ${PLISTS[@]:+"${PLISTS[@]}"}; do
    LABEL=$(basename "$P" .plist)
    case "$P" in
      "$HOME"/*) launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null ;;
      *)         sudo launchctl bootout "system/$LABEL" 2>/dev/null
                 sudo launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null ;;
    esac
  done
fi

zap() {
  local F=$1
  case "$F" in
    "$HOME"/*) rm -rf "$F" 2>/dev/null ;;
    *)         run_priv rm -rf "$F" 2>/dev/null ;;
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

LEFT=$(find "$APPS_DIR" "$HOME/Library" "$SYS_LIB" -maxdepth 3 -iname "*${SHORTNAME}*" 2>/dev/null | head -10)
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
