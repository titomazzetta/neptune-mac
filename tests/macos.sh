#!/bin/bash
#
# macos.sh — the tests that only mean something on a real Mac.
#
# unit.sh proves the parsing against captured output, anywhere. This file
# proves the assumptions underneath it on the platform itself: that /bin/bash
# really is 3.2, that awk really is BWK and really does abort on half a UTF-8
# character outside the C locale, that codesign classifies a binary we signed
# ad hoc as ad hoc, and that PlistBuddy resolves launchd targets the way
# redflag_scan.sh expects. Run by the macOS CI job; runnable on any Mac.
#
# Usage:  ./tests/macos.sh

set -u
cd "$(dirname "$0")/.." || exit 1

if [ "$(uname -s)" != "Darwin" ]; then
  echo "macos.sh: not macOS — nothing to test here (unit.sh covers the portable layer)."
  exit 0
fi

T=$(mktemp -d "${TMPDIR:-/tmp}/neptune-macos.XXXXXX")
trap 'rm -rf "$T"' EXIT
TALLY="$T/tally"; : > "$TALLY"
t_ok()   { echo pass >> "$TALLY"; printf '  ok    %s\n' "$1"; }
t_fail() { echo fail >> "$TALLY"; printf '  FAIL  %s\n' "$1"
           printf '          expected: [%s]\n          actual:   [%s]\n' "$2" "$3"; }
t_is()   { if [ "$2" = "$3" ]; then t_ok "$1"; else t_fail "$1" "$2" "$3"; fi; }
t_section() { printf '\n== %s ==\n' "$1"; }

############################################################
t_section "The platform is the one the constraints are written for"
############################################################
BV=$(/bin/bash -c 'echo "${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]}"')
t_is "/bin/bash is 3.2" "3.2" "$BV"
AV=$(awk --version 2>&1 | head -1)
case "$AV" in
  "awk version 2"*) t_ok "awk is BWK awk ($AV)" ;;
  *) t_fail "awk is BWK awk" "awk version 2xxxxxxx" "$AV" ;;
esac
t_is "and this suite is itself running under bash 3.2" "3" "${BASH_VERSINFO[0]}"

BAD=""
for F in scripts/*.sh tests/*.sh; do /bin/bash -n "$F" 2>/dev/null || BAD="$BAD $F"; done
t_is "every script and test PARSES under /bin/bash 3.2 (the real gate for rule 1)" "" "$BAD"

############################################################
t_section "Why every script sets LC_ALL=C (DEVLOG Bug 13)"
############################################################
PROBE='BEGIN { print "before"; s = substr("x\342\200\224y", 1, 2); sub(/q/, "r", s); print "after" }'
C_OUT=$(LC_ALL=C awk "$PROBE" 2>/dev/null | tr '\n' ' ')
t_is "in the C locale, awk survives half a character" "before after " "$C_OUT"
U_OUT=$(LC_ALL=en_US.UTF-8 awk "$PROBE" 2>/dev/null | tr '\n' ' ')
if [ "$U_OUT" = "before " ]; then
  t_ok "in a UTF-8 locale, BWK awk still aborts mid-program (the reason for the rule)"
else
  # Reported, not failed: if Apple fixes awk, the rule stays harmless.
  t_ok "in a UTF-8 locale this awk no longer aborts ($U_OUT) — LC_ALL=C remains harmless"
fi

############################################################
t_section "sig() against the real codesign"
############################################################
for S in redflag_scan.sh sentry.sh; do
  CLASS=$( export HOME="$T/h-$S"; mkdir -p "$HOME"
           # shellcheck source=/dev/null
           NEPTUNE_LIB=1 . "scripts/$S" >/dev/null 2>&1; sig /bin/ls )
  t_is "$S: /bin/ls is apple" "apple" "$CLASS"
  cp /bin/ls "$T/adhoc-ls"
  codesign --remove-signature "$T/adhoc-ls" 2>/dev/null
  codesign -s - -f "$T/adhoc-ls" 2>/dev/null
  CLASS=$( export HOME="$T/h-$S"
           # shellcheck source=/dev/null
           NEPTUNE_LIB=1 . "scripts/$S" >/dev/null 2>&1; sig "$T/adhoc-ls" )
  t_is "$S: a binary we signed ad hoc is adhoc, not signed (Bug 16)" "adhoc" "$CLASS"
  printf '#!/bin/sh\necho hi\n' > "$T/unsigned.sh"; chmod +x "$T/unsigned.sh"
  CLASS=$( export HOME="$T/h-$S"
           # shellcheck source=/dev/null
           NEPTUNE_LIB=1 . "scripts/$S" >/dev/null 2>&1; sig "$T/unsigned.sh" )
  t_is "$S: an unsigned script is unsigned" "unsigned" "$CLASS"
done

############################################################
t_section "plist_target() with the real PlistBuddy"
############################################################
PB=/usr/libexec/PlistBuddy
"$PB" -c 'Add :Label string t.one' -c 'Add :Program string /usr/bin/true' \
      -c 'Add :ProgramArguments array' -c 'Add :ProgramArguments:0 string /bin/false' "$T/one.plist" >/dev/null
"$PB" -c 'Add :Label string t.two' -c 'Add :ProgramArguments array' \
      -c 'Add :ProgramArguments:0 string /bin/echo' "$T/two.plist" >/dev/null
"$PB" -c 'Add :Label string t.three' -c 'Add :ProgramArguments array' \
      -c 'Add :ProgramArguments:0 string launchctl' "$T/three.plist" >/dev/null
plutil -convert binary1 "$T/two.plist"
R=$( export HOME="$T/h-pt"; mkdir -p "$HOME"
     # shellcheck source=/dev/null
     NEPTUNE_LIB=1 . scripts/redflag_scan.sh >/dev/null 2>&1
     printf '%s|%s|%s' "$(plist_target "$T/one.plist")" "$(plist_target "$T/two.plist")" "$(plist_target "$T/three.plist")" )
t_is "Program wins over ProgramArguments; binary plists read; bare names resolve" \
   "/usr/bin/true|/bin/echo|$(command -v launchctl)" "$R"

############################################################
t_section "The optional-python probe"
############################################################
R=$( # shellcheck source=/dev/null
     NEPTUNE_LIB=1 . scripts/neptune.sh; python_ok && echo usable || echo unusable )
if xcode-select -p >/dev/null 2>&1; then
  t_is "with the Command Line Tools present, python is usable" "usable" "$R"
else
  t_ok "no Command Line Tools here; python_ok says $R (the stub is never run)"
fi

PASS=$(grep -c '^pass$' "$TALLY"); FAIL=$(grep -c '^fail$' "$TALLY")
printf '\n================================================\n'
printf '  %d passed, %d failed\n' "$PASS" "$FAIL"
printf '================================================\n'
[ "$FAIL" -eq 0 ]
