#!/bin/bash
#
# clean_caches.sh — See what your caches cost, and clear the ones you choose
#
# Usage:
#   ./clean_caches.sh                   list caches by size (changes nothing)
#   ./clean_caches.sh --apply           pick caches to clear; shows exactly what
#                                       goes, then asks you to type "yes"
#   ./clean_caches.sh --apply --dry-run pick, show the list, and stop
#
# What it will touch: the CONTENTS of folders directly inside ~/Library/Caches,
# that you picked by number, after you typed "yes". Nothing else — no system
# caches, no sudo, no logs, no "junk" heuristics, no app data.
#
# What it never offers:
#   com.apple.*      macOS manages its own caches and some hold state it expects
#   CloudKit, FileProvider, com.apple.bird   iCloud sync state, not caches
#   Homebrew         `brew cleanup` knows what is safe there; this script doesn't
#   symlinks         a cache folder that points elsewhere could point anywhere
#
# Why the contents and not the folder: apps create their cache folder once and
# some (sandboxed ones especially) misbehave if it disappears. Emptying it is
# what "clear the cache" means.
#
# This is the third script in Neptune that deletes anything (after uninstall.sh
# and remove_mackeeper.sh) and it follows the same rules: list first, nothing
# without a typed confirmation, no --yes flag, never unattended.

set -u
export LC_ALL=C   # byte-safe, platform-identical text tools — see the note in neptune.sh

BOLD=$(tput bold 2>/dev/null || true)
RED=$(tput setaf 1 2>/dev/null || true)
GRN=$(tput setaf 2 2>/dev/null || true)
YEL=$(tput setaf 3 2>/dev/null || true)
CYN=$(tput setaf 6 2>/dev/null || true)
RST=$(tput sgr0 2>/dev/null || true)

section() { echo; echo "${BOLD}${CYN}== $* ==${RST}"; }
ok()   { echo "  ${GRN}[ok]${RST} $*"; }
warn() { echo "  ${YEL}[!!]${RST} $*"; }
die()  { echo "  ${RED}[XX]${RST} $*" >&2; exit 1; }

human() { awk -v k="$1" 'BEGIN { if (k >= 1048576) printf "%.1f GB", k/1048576;
                                 else if (k >= 1024) printf "%.0f MB", k/1024;
                                 else printf "%d KB", k }'; }

# never_offer <name> — caches this script will not list, whatever their size.
never_offer() {
  case "$1" in
    com.apple.*|CloudKit|FileProvider|Homebrew|homebrew) return 0 ;;
    # Apple also keeps some caches under names without the com.apple prefix.
    # These are the ones known; an unknown one is still Apple's to manage, and
    # clearing a protected one just reports "could not be removed".
    GeoServices|PassKit|FamilyCircle|Metadata|SiriTTS|CloudKitMetadata|\
    AMSDataMigratorTool|TelephonyUtilities|storeassetd|findmydevice) return 0 ;;
  esac
  return 1
}

# slow_rebuild <name> — clearing is safe but costly: sample libraries, plug-in
# scans and media indexes can take a long time to rebuild. Listed, and marked.
slow_rebuild() {
  case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
    *ableton*|*splice*|*native*instruments*|*adobe*|*steam*) return 0 ;;
  esac
  return 1
}

# parse_selection <count> <input> — prints the chosen item numbers, one per
# line, sorted and unique. Accepts "3", "1 4 7", "2-5", "all", commas. Anything
# else — a number out of range, a letter, a backwards range — is an error
# (exit 1) rather than a best guess: a typo must not select a different cache.
parse_selection() {
  local N=$1 IN=$2 TOK A B i OUT=""
  IN=$(printf '%s' "$IN" | tr ',' ' ')
  if [ "$(printf '%s' "$IN" | tr -d ' ')" = "all" ]; then
    A=1; B=$N; IN="$A-$B"
  fi
  # Whole input first: digits, spaces and dashes only. This also keeps glob
  # characters away from the unquoted split below — "?" must not expand
  # against the current directory into a number (found in review).
  case "$IN" in *[!0-9\ -]*) return 1 ;; esac
  # Validate everything before emitting anything: no partial selections.
  for TOK in $IN; do
    case "$TOK" in
      *[!0-9-]*|-*|*-|*-*-*|*[0-9][0-9][0-9][0-9][0-9]*) return 1 ;;   # 5+ digits: no
      *-*) A=${TOK%-*}; B=${TOK#*-} ;;
      *)   A=$TOK; B=$TOK ;;
    esac
    A=$((10#$A)); B=$((10#$B))              # "08" is eight, not bad octal
    [ "$A" -ge 1 ] && [ "$B" -le "$N" ] && [ "$A" -le "$B" ] || return 1
    i=$A; while [ "$i" -le "$B" ]; do OUT="$OUT$i
"; i=$((i + 1)); done
  done
  [ -n "$OUT" ] || return 1
  printf '%b' "$OUT" | sort -n -u
}

[ "${NEPTUNE_LIB:-}" = "1" ] && return 0

APPLY=false
DRYRUN=false
while [ $# -gt 0 ]; do
  case "$1" in
    --apply)   APPLY=true ;;
    --dry-run) DRYRUN=true ;;
    -h|--help) sed -n '3,27p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $1  (try --help)" >&2; exit 64 ;;
  esac
  shift
done

# Sandbox root for tests/blast_radius.sh — same contract as uninstall.sh: it can
# only narrow what is reachable, and a HOME outside it is refused outright.
ROOT="${NEPTUNE_ROOT:-}"
SANDBOX=false
if [ -n "$ROOT" ]; then
  SANDBOX=true
  case "$HOME" in
    *..*) echo "HOME ('$HOME') contains '..' — refusing to resolve it." >&2
          echo "Refusing to run: a half-redirected cleanup is worse than none." >&2
          exit 1 ;;
  esac
  case "$HOME" in
    "$ROOT"/*) ;;
    *) echo "NEPTUNE_ROOT is set to '$ROOT' but HOME ('$HOME') is outside it." >&2
       echo "Refusing to run: a half-redirected cleanup is worse than none." >&2
       exit 1 ;;
  esac
fi

# Your own caches need no privileges, so this script never asks for any — and
# refuses to run as root, where $HOME and ownership stop meaning what they say.
if [ "$(id -u)" -eq 0 ] && ! $SANDBOX; then
  echo "Run as your normal user, not with sudo."; exit 1
fi

CACHES="$HOME/Library/Caches"
[ -d "$CACHES" ] || die "No cache folder at $CACHES — nothing to do."
[ -L "$CACHES" ] && die "$CACHES is a symlink. Refusing: clearing it could reach anywhere."

$SANDBOX && echo "${BOLD}${YEL}SANDBOX MODE${RST} — operating against '$ROOT', not the real system."

############################################################
# 1. Inventory
############################################################
section "Your caches (~/Library/Caches), largest first"

NAMES=()
SIZES=()
SKIPPED=""
while IFS=$'\t' read -r K NAME; do
  [ -n "$NAME" ] || continue
  # Written by the producer below, which skips names with a tab or newline:
  # `read` would trim or split them into the name of a DIFFERENT folder.
  if [ -L "$CACHES/$NAME" ]; then SKIPPED="$SKIPPED $NAME"; continue; fi
  [ -d "$CACHES/$NAME" ] || continue
  if never_offer "$NAME"; then continue; fi
  [ "$K" -ge 1024 ] || continue             # under 1 MB: not worth a line
  NAMES+=("$NAME"); SIZES+=("$K")
done < <(for D in "$CACHES"/* "$CACHES"/.[!.]*; do
           [ -e "$D" ] || [ -L "$D" ] || continue
           # No `case` here: this loop is inside <( ), and bash 3.2's parser
           # breaks on case patterns inside substitutions (CLAUDE.md rule 1).
           B=$(basename "$D")
           [ "$B" = "$(printf '%s' "$B" | tr -d '\t\n')" ] || continue
           printf '%s\t%s\n' "$(du -sk "$D" 2>/dev/null | awk '{print $1 + 0}')" "$B"
         done | sort -t "$(printf '\t')" -k1,1rn)

TOTAL=0
i=0
for NAME in ${NAMES[@]:+"${NAMES[@]}"}; do
  K=${SIZES[$i]}
  TOTAL=$((TOTAL + K))
  MARK=""
  slow_rebuild "$NAME" && MARK="  ${YEL}(slow to rebuild)${RST}"
  printf '  %3d  %9s  %s%s\n' $((i + 1)) "$(human "$K")" "$NAME" "$MARK"
  i=$((i + 1))
done
COUNT=$i

if [ "$COUNT" -eq 0 ]; then
  ok "No third-party cache over 1 MB — nothing worth clearing."
else
  echo
  echo "  $COUNT caches, $(human "$TOTAL") in total."
fi
[ -n "$SKIPPED" ] && warn "Not offered, because they are symlinks:$SKIPPED"
echo "  Not offered: Apple's own caches, iCloud state, and Homebrew's download cache."

section "Other space you can reclaim (Neptune does not touch these)"
OTHER=0
if command -v brew >/dev/null 2>&1 && ! $SANDBOX; then
  BC=$(HOMEBREW_NO_ANALYTICS=1 brew --cache 2>/dev/null)
  [ -n "$BC" ] && [ -d "$BC" ] && \
    { echo "  Homebrew downloads  $(human "$(du -sk "$BC" 2>/dev/null | awk '{print $1 + 0}')")   ->  brew cleanup --prune=all"; OTHER=1; }
fi
DD="$HOME/Library/Developer/Xcode/DerivedData"
[ -d "$DD" ] && { echo "  Xcode DerivedData   $(human "$(du -sk "$DD" 2>/dev/null | awk '{print $1 + 0}')")   ->  Xcode > Settings > Locations"; OTHER=1; }
[ -d "$HOME/.Trash" ] && { echo "  Trash               $(human "$(du -sk "$HOME/.Trash" 2>/dev/null | awk '{print $1 + 0}')")   ->  empty it in Finder"; OTHER=1; }
[ "$OTHER" -eq 1 ] || echo "  Nothing found."

if ! $APPLY; then
  echo
  echo "Nothing was changed. To clear some of these:  ./clean_caches.sh --apply"
  exit 0
fi
[ "$COUNT" -gt 0 ] || exit 0

############################################################
# 2. Choose
############################################################
section "Choose"
echo "  Enter the numbers to clear — e.g.  3   or  1 4 7   or  2-5   or  all."
echo "  Quit the apps involved first; an app that is running may rebuild the cache"
echo "  immediately, or hold files open that cannot be removed."
read -r -p "  Clear which? (Enter for none) " PICK
[ -n "$PICK" ] || { echo "  Nothing selected. Nothing was changed."; exit 0; }
SEL=$(parse_selection "$COUNT" "$PICK") || die "Could not read '$PICK' as item numbers 1-$COUNT. Nothing was changed."
[ -n "$SEL" ] || die "Could not read '$PICK' as item numbers 1-$COUNT. Nothing was changed."

############################################################
# 3. Show exactly what goes
############################################################
section "Will be emptied (the folders themselves stay)"
CHOSEN=()
SUM=0
for n in $SEL; do
  NAME=${NAMES[$((n - 1))]}
  CHOSEN+=("$NAME")
  SUM=$((SUM + ${SIZES[$((n - 1))]}))
  M=""; slow_rebuild "$NAME" && M="  (slow to rebuild)"
  printf '  %9s  %s%s\n' "$(human "${SIZES[$((n - 1))]}")" "$CACHES/$NAME" "$M"
done
echo "  Total: $(human "$SUM")"

if $DRYRUN; then
  echo
  echo "  Dry run: nothing was changed."
  echo "DELETE-SET BEGIN"
  for NAME in ${CHOSEN[@]:+"${CHOSEN[@]}"}; do printf 'contents\t%s\n' "$CACHES/$NAME"; done
  echo "DELETE-SET END"
  exit 0
fi

echo
read -r -p "  Type yes to empty these ${#CHOSEN[@]} cache folders: " REPLY
[ "$REPLY" = "yes" ] || { echo "  Not confirmed. Nothing was changed."; exit 0; }

############################################################
# 4. Clear, re-checking each path at the moment of deletion
############################################################
section "Clearing"
BEFORE_K=0; AFTER_K=0
for NAME in ${CHOSEN[@]:+"${CHOSEN[@]}"}; do
  T="$CACHES/$NAME"
  # Re-checked now, not trusted from the listing: a folder swapped for a symlink
  # between the list and the "yes" must not redirect the delete.
  case "$NAME" in ""|.|..|*/*) warn "Skipped '$NAME': not a plain folder name"; continue ;; esac
  if [ -L "$T" ] || [ ! -d "$T" ]; then warn "Skipped $T: no longer a plain folder"; continue; fi
  K1=$(du -sk "$T" 2>/dev/null | awk '{print $1 + 0}')
  find "$T" -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null
  K2=$(du -sk "$T" 2>/dev/null | awk '{print $1 + 0}')
  BEFORE_K=$((BEFORE_K + K1)); AFTER_K=$((AFTER_K + K2))
  if [ "$K2" -gt 1024 ]; then
    warn "$NAME: $(human "$K2") could not be removed (in use, or protected by macOS)"
  else
    ok "$NAME emptied"
  fi
done

echo
echo "${BOLD}Reclaimed $(human $((BEFORE_K - AFTER_K))).${RST} Apps rebuild what they need as they run."
exit 0
