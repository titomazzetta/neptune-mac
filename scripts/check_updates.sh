#!/bin/bash
#
# check_updates.sh — Outdated software across macOS, Homebrew, and the App Store
#
# Usage:
#   ./check_updates.sh            scan only (default — changes nothing)
#   ./check_updates.sh --upgrade  scan, then offer each source's upgrade in turn
#
# Covers:
#   1. macOS updates               (softwareupdate — minor updates and major
#                                   upgrades are reported separately)
#   2. Homebrew formulae + casks   (brew, if installed)
#   3. Mac App Store apps          (mas, if installed)
#   4. Apps that update themselves — so you know what nothing here covers
#
# Neptune never installs anything unasked. With --upgrade every source asks
# first, and a MAJOR macOS upgrade is never part of "install updates": it is
# listed, and you start it yourself from System Settings when you choose to.

set -u
export LC_ALL=C   # byte-safe text tools on macOS — see the note in neptune.sh

# Homebrew phones home with install analytics by default. A tool whose premise
# is "no telemetry" should not cause any on your behalf, so every brew call here
# runs with analytics and the automatic index update off (the update is done
# once, explicitly, with a timeout).
export HOMEBREW_NO_ANALYTICS=1 HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ENV_HINTS=1

BOLD=$(tput bold 2>/dev/null || true)
GRN=$(tput setaf 2 2>/dev/null || true)
YEL=$(tput setaf 3 2>/dev/null || true)
CYN=$(tput setaf 6 2>/dev/null || true)
RST=$(tput sgr0 2>/dev/null || true)

section() { echo; echo "${BOLD}${CYN}== $* ==${RST}"; }

# Structured result records — see the record format in neptune.sh.
SCAN=updates
CATEGORY=maintenance
CHECK=""
record() {
  [ -n "${NEPTUNE_FINDINGS:-}" ] || return 0
  printf '%s|%s|%s|%s|%s\n' "$1" "$CATEGORY" "$SCAN" "$CHECK" \
    "$(printf '%s' "$2" | tr '|\t\n' '/  ')" >> "$NEPTUNE_FINDINGS"
}
note()    { echo "  $*"; }
pass()    { echo "  ${GRN}[ok]${RST} $*"; record pass "$*"; }
upd()     { echo "  ${YEL}[update]${RST} $*"; record notice "$*"; }
info()    { echo "  ${CYN}[info]${RST} $*"; record info "$*"; }
unknown() { echo "  ${YEL}[??]${RST} $*"; record unknown "$*"; }

# with_timeout <seconds> <command...> — macOS has no `timeout`. Runs the command
# with a watcher that sends SIGTERM when time is up; returns the command's own
# status, or 143 when the watcher killed it. The watcher's output goes to
# /dev/null so a caller's $(...) is not held open waiting for it.
with_timeout() {
  local SECS=$1 PID W RC
  shift
  "$@" &
  PID=$!
  ( i=0
    while [ "$i" -lt "$SECS" ]; do
      sleep 1
      kill -0 "$PID" 2>/dev/null || exit 0
      i=$((i + 1))
    done
    kill -TERM "$PID" 2>/dev/null ) >/dev/null 2>&1 &
  W=$!
  wait "$PID"; RC=$?
  kill "$W" 2>/dev/null; wait "$W" 2>/dev/null
  return "$RC"
}

# su_parse <current-major> — reads `softwareupdate -l` output on stdin and prints
#   update<TAB><label><TAB><title> <version>     a minor update or app update
#   upgrade<TAB><label><TAB><title> <version>    a newer MAJOR macOS release
# A "macOS" title whose major version is above the running one is an upgrade:
# that is a decision (app compatibility, plug-ins, drivers), not maintenance, so
# it is reported as information and never installed by --upgrade.
su_parse() {
  awk -v cur="$1" '
    /^[ \t]*\* Label: / { label = $0; sub(/^[ \t]*\* Label: /, "", label); next }
    /^[ \t]*Title: / {
      line = $0; sub(/^[ \t]*Title: /, "", line)
      title = line; sub(/, Version: .*/, "", title)
      ver = ""
      if (match(line, /Version: [^,]*/)) ver = substr(line, RSTART + 9, RLENGTH - 9)
      major = ver; sub(/\..*/, "", major)
      kind = "update"
      if (title ~ /^macOS/ && major ~ /^[0-9]+$/ && cur ~ /^[0-9]+$/ && major + 0 > cur + 0) kind = "upgrade"
      name = title
      if (ver != "" && index(title, ver) == 0) name = title " " ver
      printf "%s\t%s\t%s\n", kind, label, name
      label = ""
    }'
}

# clip <bytes> — the first words of stdin that fit in <bytes>, on one line.
# Whole words only: a byte-slice (cut -c) can split a multibyte character and
# leave invalid UTF-8 behind (CLAUDE.md constraint 1, DEVLOG Bugs 10 and 12).
clip() {
  tr '\n\t' '  ' | awk -v max="$1" '{
    for (i = 1; i <= NF; i++) {
      c = (s == "" ? $i : s " " $i)
      if (length(c) > max) { s = (s == "" ? "..." : s " ..."); break }
      s = c
    }
  } END { print s }'
}

# join_names — newline-separated names to "a, b, c and 4 more" (at most five
# named, so a finding title stays readable).
join_names() {
  awk 'NF { n++; if (n <= 5) s = (s == "" ? $0 : s ", " $0) }
       END { if (n > 5) s = s " and " (n - 5) " more"; print s }'
}

[ "${NEPTUNE_LIB:-}" = "1" ] && return 0

UPGRADE=false
case "${1:-}" in
  "") ;;
  --upgrade) UPGRADE=true ;;
  -h|--help) sed -n '3,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  *) echo "Unknown option: $1  (try --help)"; exit 64 ;;
esac

# Refuse to run wholesale as root (CLAUDE.md constraint 5). Homebrew refuses to
# operate as root, and `mas` needs the user's own session.
if [ "$(id -u)" -eq 0 ]; then
  echo "Run as your normal user, not with sudo."; exit 1
fi

confirm() {
  local R
  read -r -p "  ${BOLD}$1 [y/N]${RST} " R
  case "$R" in [yY]|[yY][eE][sS]) return 0 ;; *) return 1 ;; esac
}

echo "${BOLD}Software update scan — $(date '+%Y-%m-%d %H:%M')${RST}"
if $UPGRADE; then echo "Mode: scan, then ask before each upgrade"
else echo "Mode: scan only (run with --upgrade to install)"; fi

############################################################
# 1. macOS
############################################################
section "macOS updates"
CHECK=macos-updates
CUR=$(sw_vers -productVersion 2>/dev/null)
CUR_MAJOR=${CUR%%.*}
note "Running macOS ${CUR:-unknown}"

SU_OUT=$(with_timeout 180 softwareupdate -l 2>&1); SU_RC=$?
SU_PARSED=$(printf '%s\n' "$SU_OUT" | su_parse "$CUR_MAJOR")
UPDATES=$(printf '%s\n' "$SU_PARSED" | awk -F'\t' '$1 == "update" {print $3}')
UPGRADES=$(printf '%s\n' "$SU_PARSED" | awk -F'\t' '$1 == "upgrade" {print $3}')

if [ "$SU_RC" -eq 143 ]; then
  unknown "Apple's update server did not answer within 3 minutes — macOS update status unknown"
elif [ -n "$UPDATES" ]; then
  N=$(printf '%s\n' "$UPDATES" | grep -c .)
  upd "Apple software updates are pending ($N): $(printf '%s\n' "$UPDATES" | join_names)"
elif printf '%s' "$SU_OUT" | grep -q "No new software available"; then
  pass "macOS and Apple apps are up to date"
elif [ -n "$UPGRADES" ]; then
  pass "No minor macOS or Apple app updates are pending"
else
  # Neither a list nor the all-clear sentence: offline, or Apple changed the
  # output. Saying "up to date" here would be the silent all-clear (Bug 13).
  unknown "Could not read the result of softwareupdate: $(printf '%s' "$SU_OUT" | clip 80)"
fi

CHECK=macos-upgrade
if [ -n "$UPGRADES" ]; then
  info "A new major macOS release is available: $(printf '%s\n' "$UPGRADES" | join_names) — upgrade when your apps support it"
fi

if $UPGRADE && [ -n "$UPDATES" ]; then
  echo
  printf '%s\n' "$UPDATES" | sed 's/^/      /'
  if confirm "Install these updates (not the major upgrade)? Some need a restart"; then
    # By label, one at a time. `softwareupdate -ia` would include the major
    # upgrade listed above — "install updates" must never mean that.
    printf '%s\n' "$SU_PARSED" | awk -F'\t' '$1 == "update" && $2 != "" {print $2}' |
      while IFS= read -r LABEL; do
        echo "  Installing: $LABEL"
        # stdin from the terminal, not the label list this loop is reading.
        # shellcheck disable=SC2024
        sudo softwareupdate -i "$LABEL" </dev/tty
      done
  fi
fi

############################################################
# 2. Homebrew
############################################################
section "Homebrew"
if command -v brew >/dev/null 2>&1; then
  note "Refreshing the package index (up to 2 minutes)..."
  BREW_FRESH=true
  with_timeout 120 brew update >/dev/null 2>&1 || BREW_FRESH=false

  # Casks that update themselves (Chrome, Docker, ...) are NOT listed as out of
  # date: their own updater owns them, and `--greedy` would report every one of
  # them on every run — noise that trains people to skip this section.
  OUT_F=$(brew outdated --formula --quiet 2>/dev/null)
  OUT_C=$(brew outdated --cask --quiet 2>/dev/null)
  NF=$(printf '%s' "$OUT_F" | grep -c .)
  NC=$(printf '%s' "$OUT_C" | grep -c .)

  CHECK=brew-outdated
  if [ "$NF" -gt 0 ] || [ "$NC" -gt 0 ]; then
    upd "$NF Homebrew formulae and $NC casks have updates available"
    [ "$NF" -gt 0 ] && { note "  formulae: $(printf '%s\n' "$OUT_F" | tr '\n' ' ')"; }
    [ "$NC" -gt 0 ] && { note "  casks:    $(printf '%s\n' "$OUT_C" | tr '\n' ' ')"; }
    $BREW_FRESH || note "  (the index could not be refreshed, so there may be more)"
    if $UPGRADE && confirm "Upgrade these Homebrew packages?"; then
      brew upgrade
    fi
  elif $BREW_FRESH; then
    pass "Homebrew packages are up to date"
  else
    unknown "Could not refresh Homebrew's package index — 'up to date' would be a guess"
  fi

  # brew doctor exits non-zero when it has warnings. Most are advisory, so this
  # is a notice with a count, never a red flag.
  CHECK=brew-doctor
  DOC=$(with_timeout 60 brew doctor 2>&1); DOC_RC=$?
  NW=$(printf '%s\n' "$DOC" | grep -c '^Warning:')
  if [ "$DOC_RC" -eq 0 ]; then
    pass "brew doctor reports no problems"
  elif [ "$DOC_RC" -eq 143 ]; then
    unknown "brew doctor did not finish within a minute"
  elif [ "$NW" -gt 0 ]; then
    upd "brew doctor has $NW warnings about this Homebrew install"
    printf '%s\n' "$DOC" | grep '^Warning:' | while IFS= read -r L; do
      printf '      %s\n' "$(printf '%s' "$L" | clip 110)"
    done
  else
    unknown "brew doctor failed without a readable warning (exit $DOC_RC)"
  fi
else
  note "Homebrew is not installed — nothing to check. (https://brew.sh)"
fi

############################################################
# 3. Mac App Store
############################################################
section "Mac App Store"
CHECK=mas-outdated
if command -v mas >/dev/null 2>&1; then
  MAS_OUT=$(with_timeout 60 mas outdated 2>/dev/null); MAS_RC=$?
  NM=$(printf '%s' "$MAS_OUT" | grep -c .)
  if [ "$MAS_RC" -eq 143 ]; then
    unknown "mas outdated did not finish within a minute"
  elif [ "$NM" -gt 0 ]; then
    upd "$NM App Store apps have updates available"
    printf '%s\n' "$MAS_OUT" | sed 's/^/      /'
    if $UPGRADE && confirm "Upgrade these App Store apps?"; then mas upgrade; fi
  else
    pass "App Store apps are up to date"
  fi
else
  note "mas (the App Store command line) is not installed; check the App Store's"
  note "Updates tab instead, or install it with: brew install mas"
fi

############################################################
# 4. Apps that update themselves
############################################################
section "Apps not managed by Homebrew or the App Store"

# One JSON call instead of one `brew info` per cask. The app names are the
# quoted strings ending in .app — good enough for an inventory that records
# nothing and only tells you what to keep an eye on.
CASK_APPS=""
if command -v brew >/dev/null 2>&1; then
  CASK_APPS=$(brew info --cask --installed --json=v2 2>/dev/null | grep -o '"[^"/]*\.app"' | tr -d '"' | sort -u)
fi

UNMANAGED=()
while IFS= read -r APP; do
  [ -n "$APP" ] || continue
  NAME=$(basename "$APP")
  printf '%s\n' "$CASK_APPS" | grep -qxF "$NAME" && continue
  [ -e "$APP/Contents/_MASReceipt/receipt" ] && continue
  # Apple's own: by bundle id, with the signing authority as a second test —
  # macOS 26 renamed it "macOS Software Signing", and Safari was listed here as
  # an app nothing updates (Bug 20).
  case "$(defaults read "$APP/Contents/Info" CFBundleIdentifier 2>/dev/null)" in com.apple.*) continue ;; esac
  AUTH=$(codesign -dvv "$APP" 2>&1 | grep -m1 '^Authority=' | cut -d= -f2)
  case "$AUTH" in "Software Signing"|"macOS Software Signing") continue ;; esac
  VER=$(defaults read "$APP/Contents/Info" CFBundleShortVersionString 2>/dev/null || echo "?")
  UNMANAGED+=("$NAME  (v$VER)")
done < <(find /Applications -maxdepth 1 -name "*.app" 2>/dev/null | sort)

if [ ${#UNMANAGED[@]} -eq 0 ]; then
  note "Every third-party app is managed by Homebrew or the App Store."
else
  note "These rely on their own updaters — open them now and then, or check the vendor:"
  for A in ${UNMANAGED[@]:+"${UNMANAGED[@]}"}; do echo "      $A"; done
  echo
  note "Many have Homebrew casks; to hand one over:  brew install --cask --adopt <name>"
  note "Leave license-managed software (plug-in managers, iLok and similar) on the"
  note "vendor's own updater — adopting it can break activation."
fi

echo
echo "${BOLD}Scan complete.${RST}"
$UPGRADE || echo "Nothing was installed. Run with --upgrade to be asked about each source."
exit 0
