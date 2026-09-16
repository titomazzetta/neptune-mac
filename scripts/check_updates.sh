#!/bin/bash
#
# check_updates.sh — Scan for outdated software across macOS, Homebrew, and App Store
#
# Usage:
#   ./check_updates.sh            scan only (default — changes nothing)
#   ./check_updates.sh --upgrade  scan, then interactively upgrade each source
#
# Covers:
#   1. macOS system updates        (softwareupdate)
#   2. Homebrew formulae + casks   (brew, if installed)
#   3. Mac App Store apps          (mas, if installed)
#   4. Inventory of /Applications apps NOT managed by any of the above,
#      so you know what still relies on its own updater.

set -u

BOLD=$(tput bold 2>/dev/null || true)
GRN=$(tput setaf 2 2>/dev/null || true)
YEL=$(tput setaf 3 2>/dev/null || true)
CYN=$(tput setaf 6 2>/dev/null || true)
RST=$(tput sgr0 2>/dev/null || true)

section() { echo; echo "${BOLD}${CYN}== $* ==${RST}"; }
ok()      { echo "  ${GRN}[ok]${RST} $*"; }
upd()     { echo "  ${YEL}[update]${RST} $*"; }
note()    { echo "  $*"; }

UPGRADE=false
[ "${1:-}" = "--upgrade" ] && UPGRADE=true

confirm() {
  read -r -p "  ${BOLD}$1 [y/N]${RST} " R
  case "$R" in [yY]|[yY][eE][sS]) return 0 ;; *) return 1 ;; esac
}

echo "${BOLD}Software update scan — $(date '+%Y-%m-%d %H:%M')${RST}"
$UPGRADE && echo "Mode: scan + interactive upgrade" || echo "Mode: scan only (run with --upgrade to install)"

############################################################
# 1. macOS system updates
############################################################
section "macOS system updates"
SU_OUT=$(softwareupdate -l 2>&1)
if echo "$SU_OUT" | grep -q "No new software available"; then
  ok "macOS is up to date"
else
  echo "$SU_OUT" | grep -E '^\s*\*|Title:' | sed 's/^/  /'
  if $UPGRADE && confirm "Install all macOS updates now? (may require restart)"; then
    sudo softwareupdate -ia
  fi
fi

############################################################
# 2. Homebrew
############################################################
section "Homebrew"
if command -v brew >/dev/null 2>&1; then
  note "Updating package index..."
  brew update >/dev/null 2>&1

  OUTDATED_FORMULAE=$(brew outdated --formula 2>/dev/null)
  OUTDATED_CASKS=$(brew outdated --cask --greedy-auto-updates 2>/dev/null)

  if [ -z "$OUTDATED_FORMULAE" ] && [ -z "$OUTDATED_CASKS" ]; then
    ok "All Homebrew packages up to date"
  else
    [ -n "$OUTDATED_FORMULAE" ] && { upd "Outdated formulae:"; echo "$OUTDATED_FORMULAE" | sed 's/^/      /'; }
    [ -n "$OUTDATED_CASKS" ]    && { upd "Outdated casks:";    echo "$OUTDATED_CASKS"    | sed 's/^/      /'; }
    if $UPGRADE && confirm "Upgrade all Homebrew packages?"; then
      brew upgrade
      brew upgrade --cask --greedy-auto-updates
    fi
  fi

  # Health check
  note "brew doctor: $(brew doctor 2>&1 | head -1)"
else
  note "Homebrew not installed. To install:"
  note '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'
fi

############################################################
# 3. Mac App Store (mas)
############################################################
section "Mac App Store"
if command -v mas >/dev/null 2>&1; then
  MAS_OUT=$(mas outdated 2>/dev/null)
  if [ -z "$MAS_OUT" ]; then
    ok "All App Store apps up to date"
  else
    upd "Outdated App Store apps:"
    echo "$MAS_OUT" | sed 's/^/      /'
    if $UPGRADE && confirm "Upgrade all App Store apps?"; then
      mas upgrade
    fi
  fi
else
  if command -v brew >/dev/null 2>&1; then
    note "mas not installed (App Store CLI). Install with: brew install mas"
  else
    note "mas not installed — requires Homebrew first"
  fi
fi

############################################################
# 4. Unmanaged applications inventory
############################################################
section "Apps NOT managed by brew/App Store (rely on their own updaters)"

# Build list of brew-cask-managed app names
CASK_APPS=""
if command -v brew >/dev/null 2>&1; then
  for CASK in $(brew list --cask 2>/dev/null); do
    ART=$(brew info --cask "$CASK" 2>/dev/null | grep -m1 '\.app' | sed 's/ (App)//' | xargs)
    [ -n "$ART" ] && CASK_APPS="$CASK_APPS|$ART"
  done
fi

# App Store apps carry an App Store receipt
UNMANAGED=()
while IFS= read -r APP; do
  NAME=$(basename "$APP")
  # Skip if brew-managed
  if [ -n "$CASK_APPS" ] && echo "$CASK_APPS" | grep -qF "$NAME"; then continue; fi
  # Skip if App Store (has receipt)
  [ -e "$APP/Contents/_MASReceipt/receipt" ] && continue
  # Skip Apple's own apps
  if codesign -dvv "$APP" 2>&1 | grep -q "Authority=Apple Root CA"; then
    SIGNER=$(codesign -dvv "$APP" 2>&1 | grep -m1 'Authority=' | cut -d= -f2)
    case "$SIGNER" in *"Software Signing"*) continue ;; esac
  fi
  VER=$(defaults read "$APP/Contents/Info" CFBundleShortVersionString 2>/dev/null || echo "?")
  UNMANAGED+=("$NAME  (v$VER)")
done < <(find /Applications -maxdepth 1 -name "*.app" | sort)

if [ ${#UNMANAGED[@]} -eq 0 ]; then
  ok "Every app is managed by brew or the App Store"
else
  note "These update through their own mechanisms — check them periodically:"
  for A in "${UNMANAGED[@]}"; do echo "      $A"; done
  echo
  note "${BOLD}Tip:${RST} many of these have Homebrew casks. Adopt an existing app with:"
  note "  brew install --cask --adopt <name>"
  note "Do NOT adopt license-managed pro-audio software (Waves, Arturia, iLok,"
  note "Sonarworks, Elektron) — keep those on their vendor updaters."
fi

echo
echo "${BOLD}Scan complete.${RST}"
$UPGRADE || echo "Run again with --upgrade to install anything flagged above."
