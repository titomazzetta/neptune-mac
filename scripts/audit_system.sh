#!/bin/bash
#
# audit_system.sh — Process, persistence, and bloat audit for macOS
#
# Read-only: changes nothing, deletes nothing. Reports:
#   1. Top CPU and memory consumers right now
#   2. Every third-party (non-Apple) launch agent/daemon, with code-signing status
#   3. System extensions and third-party kernel extensions
#   4. Biggest space consumers in common bloat locations
#
# Usage:  ./audit_system.sh          (sudo prompted once, for system dirs)

set -u

BOLD=$(tput bold 2>/dev/null || true)
RED=$(tput setaf 1 2>/dev/null || true)
GRN=$(tput setaf 2 2>/dev/null || true)
YEL=$(tput setaf 3 2>/dev/null || true)
CYN=$(tput setaf 6 2>/dev/null || true)
RST=$(tput sgr0 2>/dev/null || true)

section() { echo; echo "${BOLD}${CYN}== $* ==${RST}"; }

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
# 2. Third-party persistence, with signing verification
############################################################
check_plists() {
  local DIR=$1
  [ -d "$DIR" ] || return 0
  local PLIST LABEL PROG SIGN
  for PLIST in "$DIR"/*.plist; do
    [ -e "$PLIST" ] || continue
    LABEL=$(basename "$PLIST" .plist)
    # Skip Apple's own
    case "$LABEL" in com.apple.*) continue ;; esac

    # Resolve the executable the plist launches
    PROG=$(defaults read "$PLIST" ProgramArguments 2>/dev/null | sed -n 's/^[[:space:]]*"\{0,1\}\([^",]*\).*/\1/p' | head -2 | tail -1)
    [ -z "$PROG" ] && PROG=$(defaults read "$PLIST" Program 2>/dev/null)

    # A plist may name a bare command ("launchctl", "open") rather than a path.
    # Without this, such entries were reported as "TARGET MISSING (orphaned
    # plist)" — a false alarm on Apple's own limit.maxfiles/limit.maxproc.
    # redflag_scan.sh already resolved these; the two scripts disagreed on the
    # same plist. Keep them in step.
    if [ -n "$PROG" ] && [ ! -e "$PROG" ] && command -v "$PROG" >/dev/null 2>&1; then
      PROG=$(command -v "$PROG")
    fi

    # Signing status of the executable
    if [ -n "$PROG" ] && [ -e "$PROG" ]; then
      if codesign -v "$PROG" 2>/dev/null; then
        SIGNER=$(codesign -dvv "$PROG" 2>&1 | grep -m1 '^Authority=' | cut -d= -f2)
        SIGN="${GRN}signed${RST} (${SIGNER:-unknown authority})"
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

section "User launch agents (~/Library/LaunchAgents)"
check_plists "$HOME/Library/LaunchAgents"

section "Global launch agents (/Library/LaunchAgents)"
check_plists "/Library/LaunchAgents"

section "Global launch daemons (/Library/LaunchDaemons)"
check_plists "/Library/LaunchDaemons"

section "Privileged helper tools (/Library/PrivilegedHelperTools)"
if [ -d /Library/PrivilegedHelperTools ]; then
  for H in /Library/PrivilegedHelperTools/*; do
    [ -e "$H" ] || continue
    if codesign -v "$H" 2>/dev/null; then
      SIGNER=$(codesign -dvv "$H" 2>&1 | grep -m1 '^Authority=' | cut -d= -f2)
      echo "  $(basename "$H") — ${GRN}signed${RST} (${SIGNER:-?})"
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
KEXTS=$(kextstat 2>/dev/null | grep -v com.apple || true)
if [ -n "$KEXTS" ]; then echo "$KEXTS" | sed 's/^/  /'; else echo "  none — good"; fi

############################################################
# 4. Disk bloat
############################################################
section "Space consumers"
echo "  ${BOLD}User caches (top 10):${RST}"
du -sh "$HOME/Library/Caches/"* 2>/dev/null | sort -rh | head -10 | sed 's/^/    /'
echo
echo "  ${BOLD}Application Support (top 10):${RST}"
du -sh "$HOME/Library/Application Support/"* 2>/dev/null | sort -rh | head -10 | sed 's/^/    /'
echo
echo "  ${BOLD}Logs:${RST}"
du -sh "$HOME/Library/Logs" /Library/Logs 2>/dev/null | sed 's/^/    /'
echo
echo "  ${BOLD}System-level (needs sudo):${RST}"
sudo du -sh /Library/Caches /private/var/folders /private/var/log 2>/dev/null | sed 's/^/    /'
echo
echo "  ${BOLD}Biggest items in home folder (top 10):${RST}"
du -sh "$HOME"/* 2>/dev/null | sort -rh | head -10 | sed 's/^/    /'

echo
echo "${BOLD}Audit complete.${RST} Read-only — nothing was changed."
echo "Red items above (unsigned binaries, orphaned plists) are worth investigating."
echo "Large caches are usually safe to clear per-app, but don't blanket-delete:"
echo "audio apps (Ableton, Splice, plugin scanners) rebuild caches slowly."
