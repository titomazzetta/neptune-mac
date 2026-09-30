#!/bin/bash
#
# audit_system.sh — Resources, extensions, and disk bloat for macOS
#
# Read-only: changes nothing, deletes nothing. Reports:
#   1. Top CPU and memory consumers right now
#   2. Third-party launch agents/daemons/helpers, with code signing
#      (in the full suite this is redflag_scan.sh's job, so it is skipped here)
#   3. System extensions and third-party kernel extensions
#   4. Where the disk went — and which of it is safely reclaimable
#
# Usage:  ./audit_system.sh          (sudo prompted once, for system dirs)

set -u
export LC_ALL=C   # byte-safe text tools on macOS — see the note in neptune.sh

BOLD=$(tput bold 2>/dev/null || true)
RED=$(tput setaf 1 2>/dev/null || true)
GRN=$(tput setaf 2 2>/dev/null || true)
YEL=$(tput setaf 3 2>/dev/null || true)
CYN=$(tput setaf 6 2>/dev/null || true)
RST=$(tput sgr0 2>/dev/null || true)

section() { echo; echo "${BOLD}${CYN}== $* ==${RST}"; }

# Structured result records — see the record format in neptune.sh. This scan
# used to record NOTHING, which is why the bloat score could not move off
# 100/100 on a machine with a 3.5 GB Homebrew cache (DEVLOG Bug 18).
SCAN=audit
CATEGORY=bloat
CHECK=""
record() {
  [ -n "${NEPTUNE_FINDINGS:-}" ] || return 0
  printf '%s|%s|%s|%s|%s\n' "$1" "$CATEGORY" "$SCAN" "$CHECK" \
    "$(printf '%s' "$2" | tr '|\t\n' '/  ')" >> "$NEPTUNE_FINDINGS"
}
ok()   { echo "  ${GRN}[ok]${RST} $*"; }
pass() { echo "  ${GRN}[ok]${RST} $*"; record pass "$*"; }
warn() { echo "  ${YEL}[!!]${RST} $*"; record notice "$*"; }

# Sizes in KiB from `du -sk` — integers, identical in every locale. The old
# listings used `du -h`, which prints "3,5G" under some locales and cannot be
# compared against a threshold anyway.
kib()   { du -sk "$@" 2>/dev/null | awk '{s += $1} END {print s + 0}'; }
human() { awk -v k="$1" 'BEGIN { if (k >= 1048576) printf "%.1f GB", k/1048576;
                                 else if (k >= 1024) printf "%.0f MB", k/1024;
                                 else printf "%d KB", k }'; }
GIB=1048576

[ "${NEPTUNE_LIB:-}" = "1" ] && return 0

# Refuse to run wholesale as root (CLAUDE.md constraint 5). This script elevates
# only `du` on system paths.
if [ "$(id -u)" -eq 0 ]; then
  echo "Run as your normal user, not with sudo."; exit 1
fi

echo "${BOLD}System audit — $(date '+%Y-%m-%d %H:%M')${RST}"
sudo -v || exit 1

############################################################
# 1. Top resource consumers
############################################################
section "Top 12 CPU consumers"
ps -Arco pcpu,pmem,pid,comm | head -13 | sed 's/^/  /'

section "Top 12 memory consumers"
ps -Amco pmem,pcpu,pid,comm | head -13 | sed 's/^/  /'

############################################################
# 2. Third-party persistence (standalone only)
############################################################
if [ -n "${NEPTUNE_SUITE:-}" ]; then
  section "Third-party persistence"
  echo "  Covered by redflag_scan.sh in this suite, with signing verified."
else
  plist_target() {
    local PL=$1 PB=/usr/libexec/PlistBuddy P
    P=$("$PB" -c 'Print :Program' "$PL" 2>/dev/null)
    [ -n "$P" ] || P=$("$PB" -c 'Print :ProgramArguments:0' "$PL" 2>/dev/null)
    if [ -n "$P" ] && [ ! -e "$P" ] && command -v "$P" >/dev/null 2>&1; then P=$(command -v "$P"); fi
    printf '%s' "$P"
  }
  list_plists() {
    local DIRP=$1 PLIST LABEL PROG SIGN SIGNER
    [ -d "$DIRP" ] || return 0
    for PLIST in "$DIRP"/*.plist; do
      [ -e "$PLIST" ] || continue
      LABEL=$(basename "$PLIST" .plist)
      case "$LABEL" in com.apple.*) continue ;; esac
      PROG=$(plist_target "$PLIST")
      if [ -n "$PROG" ] && [ -e "$PROG" ]; then
        if codesign -v "$PROG" 2>/dev/null; then
          SIGNER=$(codesign -dvv "$PROG" 2>&1 | grep -m1 '^Authority=' | cut -d= -f2)
          SIGN="${GRN}signed${RST} (${SIGNER:-ad-hoc — no identified signer})"
        else
          SIGN="${RED}UNSIGNED or invalid signature${RST}"
        fi
      elif [ -n "$PROG" ]; then
        SIGN="${RED}TARGET MISSING:${RST} $PROG (orphaned plist)"
      else
        SIGN="${YEL}could not resolve target binary${RST}"
      fi
      echo "  ${BOLD}$LABEL${RST}"
      echo "      plist:  $PLIST"
      [ -n "$PROG" ] && echo "      runs:   $PROG"
      echo "      status: $SIGN"
    done
  }
  section "User launch agents (~/Library/LaunchAgents)";     list_plists "$HOME/Library/LaunchAgents"
  section "Global launch agents (/Library/LaunchAgents)";    list_plists "/Library/LaunchAgents"
  section "Global launch daemons (/Library/LaunchDaemons)";  list_plists "/Library/LaunchDaemons"
  section "Privileged helper tools (/Library/PrivilegedHelperTools)"
  for H in /Library/PrivilegedHelperTools/*; do
    [ -e "$H" ] || continue
    if codesign -v "$H" 2>/dev/null; then
      echo "  $(basename "$H") — ${GRN}signed${RST} ($(codesign -dvv "$H" 2>&1 | grep -m1 '^Authority=' | cut -d= -f2))"
    else
      echo "  $(basename "$H") — ${RED}UNSIGNED${RST}"
    fi
  done
fi

############################################################
# 3. System + kernel extensions
############################################################
section "System extensions"
systemextensionsctl list 2>/dev/null | sed 's/^/  /'

section "Third-party kernel extensions (loaded)"
# Count DATA rows only. The old filter was `grep -v com.apple`, which let
# kextstat's column-header line through — so every report showed a "third-party
# kext" section containing nothing but headings, and recording that would have
# made a false finding on every Mac.
CATEGORY=security
CHECK=kexts
KEXTS=$(kextstat 2>/dev/null | awk '$1 ~ /^[0-9]+$/ && $6 !~ /^com\.apple\./ {print $6}')
if [ -n "$KEXTS" ]; then
  warn "Third-party kernel extensions are loaded: $(printf '%s\n' "$KEXTS" | tr '\n' ' ')"
else
  pass "No third-party kernel extensions are loaded"
fi
CATEGORY=bloat

############################################################
# 4. Disk: where it went, and what is reclaimable
############################################################
section "Space consumers"

C="$HOME/Library/Caches"
BREW_CACHE=""
command -v brew >/dev/null 2>&1 && BREW_CACHE=$(brew --cache 2>/dev/null)

echo "  ${BOLD}User caches (top 10):${RST}"
du -sk "$C"/* 2>/dev/null | sort -rn | head -10 | while read -r K P; do
  printf '    %9s  %s\n' "$(human "$K")" "$P"
done

# Caches, excluding Homebrew's, which is its own finding below — one pile of
# bytes, one finding, one deduction.
CHECK=caches
CACHE_K=0
TOP3=""
if [ -d "$C" ]; then
  CACHE_K=$(du -sk "$C"/* 2>/dev/null | awk -v skip="$BREW_CACHE" '$2 != skip {s += $1} END {print s + 0}')
  TOP3=$(du -sk "$C"/* 2>/dev/null | awk -v skip="$BREW_CACHE" '$2 != skip' | sort -rn | head -3 | while read -r K P; do
    printf '%s (%s), ' "$(basename "$P")" "$(human "$K")"; done | sed 's/, $//')
fi
if [ "$CACHE_K" -gt $((2 * GIB)) ]; then
  warn "User caches take $(human "$CACHE_K") — largest: $TOP3"
else
  pass "User caches are a reasonable size ($(human "$CACHE_K"))"
fi

CHECK=brew-cache
if [ -n "$BREW_CACHE" ] && [ -d "$BREW_CACHE" ]; then
  BK=$(kib "$BREW_CACHE")
  if [ "$BK" -gt "$GIB" ]; then
    warn "Homebrew's download cache holds $(human "$BK") that installed software does not need"
  else
    pass "Homebrew's download cache is small ($(human "$BK"))"
  fi
fi

# Regenerable developer data. Xcode Archives are deliberately NOT here: those are
# builds someone may need to re-sign or re-submit, not a cache.
CHECK=dev-junk
DEV=""
DEV_K=0
for D in "$HOME/Library/Developer/Xcode/DerivedData" \
         "$HOME/Library/Developer/Xcode/iOS DeviceSupport" \
         "$HOME/Library/Developer/Xcode/watchOS DeviceSupport" \
         "$HOME/Library/Developer/CoreSimulator/Caches"; do
  [ -d "$D" ] || continue
  K=$(kib "$D")
  DEV_K=$((DEV_K + K))
  [ "$K" -gt 102400 ] && DEV="${DEV:+$DEV, }$(basename "$D") ($(human "$K"))"
done
if [ "$DEV_K" -gt $((2 * GIB)) ]; then
  warn "Developer build caches take $(human "$DEV_K"), all regenerable: $DEV"
else
  pass "Developer build caches are small or absent ($(human "$DEV_K"))"
fi

CHECK=logs
LOG_K=$(kib "$HOME/Library/Logs")
if [ "$LOG_K" -gt "$GIB" ]; then
  warn "Your log folder has grown to $(human "$LOG_K") — usually one app logging too much"
else
  pass "Log folders are a normal size ($(human "$LOG_K"))"
fi

echo
echo "  ${BOLD}Application Support (top 10):${RST}"
du -sk "$HOME/Library/Application Support/"* 2>/dev/null | sort -rn | head -10 | while read -r K P; do
  printf '    %9s  %s\n' "$(human "$K")" "$P"
done
echo
echo "  ${BOLD}System-level (needs sudo):${RST}"
sudo du -sk /Library/Caches /private/var/folders /private/var/log 2>/dev/null | while read -r K P; do
  printf '    %9s  %s\n' "$(human "$K")" "$P"
done
echo
echo "  ${BOLD}Biggest items in your home folder (top 10):${RST}"
du -sk "$HOME"/* 2>/dev/null | sort -rn | head -10 | while read -r K P; do
  printf '    %9s  %s\n' "$(human "$K")" "$P"
done

echo
echo "${BOLD}Audit complete.${RST} Read-only — nothing was changed."
echo "To reclaim cache space safely:  ./clean_caches.sh   (lists first; changes nothing"
echo "until you run it with --apply, pick items, and confirm)."
exit 0
