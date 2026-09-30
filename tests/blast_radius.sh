#!/bin/bash
#
# blast_radius.sh — What do the destructive scripts actually delete?
#
# uninstall.sh and remove_mackeeper.sh are the only things in Neptune that run
# `rm -rf` as root (clean_caches.sh, the third destructive script, runs it as
# you, on your own caches — and is tested here the same way), and until this file existed the only automated check on them
# was "the source contains a confirmation prompt". That verifies the safety gate
# exists; it says nothing about what is behind it. The risk in these scripts was
# never a missing prompt — it is a glob that matches one character too many.
#
# So: build a fake macOS layout in a temp directory, point the scripts at it
# with NEPTUNE_ROOT, and assert two things about the set of paths they would
# remove.
#
#   1. Everything belonging to the target app IS in the set.  (completeness)
#   2. Nothing else is.                                       (blast radius)
#
# The second is the one that matters. The fixture is deliberately hostile: the
# decoys share prefixes, suffixes and vendor names with the target, because
# "Spotify" vs "SpotifyEncoder" and "com.acme.target" vs "com.acme.other" is
# exactly the shape of an over-matching glob. A test whose fixture cannot fail
# is decoration.
#
# Both scripts also get an end-to-end run in the sandbox — actually deleting,
# for real, inside the temp directory — because a --dry-run listing that does
# not match what the delete stage does would be the worst possible bug here.
#
# Usage:  ./tests/blast_radius.sh
# No macOS required, and nothing outside its own temp directory is touched.

set -u
cd "$(dirname "$0")/.." || exit 1
REPO=$(pwd)

PASS=0; FAIL=0
t_ok()   { PASS=$((PASS + 1)); printf '  ok    %s\n' "$1"; }
t_fail() { FAIL=$((FAIL + 1)); printf '  FAIL  %s\n' "$1"
           printf '          expected: [%s]\n          actual:   [%s]\n' "$2" "$3"; }
t_is()   { if [ "$2" = "$3" ]; then t_ok "$1"; else t_fail "$1" "$2" "$3"; fi; }
t_section() { printf '\n== %s ==\n' "$1"; }

SANDBOX=$(mktemp -d "${TMPDIR:-/tmp}/neptune-blast.XXXXXX")
SANDBOX_BIN=$(mktemp -d "${TMPDIR:-/tmp}/neptune-stubs.XXXXXX")
trap 'rm -rf "$SANDBOX" "$SANDBOX_BIN"' EXIT
FAKE_HOME="$SANDBOX/Users/tester"

# ---------------------------------------------------------------------------
# The fixture.
#
# TARGET is the app under removal. Every DECOY is something a careless match
# would sweep up with it, and every one is modelled on a real collision:
#   - a longer app name containing the target's name
#   - a different app from the SAME vendor (the --deep failure mode)
#   - a bundle id that shares the target's prefix
#   - an unrelated app whose name contains the target's as a substring
# ---------------------------------------------------------------------------
build_fixture() {
  rm -rf "$SANDBOX"; mkdir -p "$SANDBOX"
  mkdir -p "$FAKE_HOME/Library/Application Support" \
           "$FAKE_HOME/Library/Caches" \
           "$FAKE_HOME/Library/Preferences" \
           "$FAKE_HOME/Library/Logs" \
           "$FAKE_HOME/Library/Containers" \
           "$FAKE_HOME/Library/LaunchAgents" \
           "$SANDBOX/Applications" \
           "$SANDBOX/Library/LaunchAgents" \
           "$SANDBOX/Library/LaunchDaemons" \
           "$SANDBOX/Library/PrivilegedHelperTools" \
           "$SANDBOX/Library/Application Support" \
           "$SANDBOX/Library/Preferences"

  # --- the target: Dovetail.app, com.acme.dovetail ---
  mkdir -p "$SANDBOX/Applications/Dovetail.app/Contents"
  cat > "$SANDBOX/Applications/Dovetail.app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.acme.dovetail</string>
</dict></plist>
PLIST
  mkdir -p "$FAKE_HOME/Library/Application Support/Dovetail"
  echo data > "$FAKE_HOME/Library/Application Support/Dovetail/state.db"
  echo cache > "$FAKE_HOME/Library/Caches/com.acme.dovetail"
  echo prefs > "$FAKE_HOME/Library/Preferences/com.acme.dovetail.plist"
  mkdir -p "$FAKE_HOME/Library/Containers/com.acme.dovetail"
  cat > "$SANDBOX/Library/LaunchDaemons/com.acme.dovetail.helper.plist" <<'PLIST'
<plist><dict><key>Label</key><string>com.acme.dovetail.helper</string></dict></plist>
PLIST

  # --- decoys: none of these may ever be deleted ---
  # 1. longer app name that CONTAINS the target name
  mkdir -p "$SANDBOX/Applications/DovetailPro.app/Contents"
  echo keep > "$SANDBOX/Applications/DovetailPro.app/Contents/Info.plist"
  echo keep > "$FAKE_HOME/Library/Preferences/com.acme.dovetailpro.plist"
  # 2. a DIFFERENT app from the SAME vendor — the --deep blast radius
  mkdir -p "$SANDBOX/Applications/Keystone.app/Contents"
  echo keep > "$FAKE_HOME/Library/Preferences/com.acme.keystone.plist"
  mkdir -p "$FAKE_HOME/Library/Application Support/Keystone"
  # 3. a bundle id sharing the prefix but not the app
  echo keep > "$FAKE_HOME/Library/Caches/com.acmecorp.dovetailer"
  # 4. unrelated software, plus the things a broken glob reaches for
  mkdir -p "$FAKE_HOME/Library/Application Support/Firefox"
  echo keep > "$FAKE_HOME/Library/Preferences/com.apple.finder.plist"
  echo keep > "$SANDBOX/Library/LaunchDaemons/com.apple.something.plist"
  mkdir -p "$SANDBOX/Library/PrivilegedHelperTools"
  echo keep > "$SANDBOX/Library/PrivilegedHelperTools/com.other.helper"
  # 5. the target name continued by a NON-ASCII letter — one word, not two.
  #    Under LC_ALL=C those are bytes above 0x7F, which must not read as a
  #    word boundary.
  mkdir -p "$FAKE_HOME/Library/Application Support/Dovetailé"
}

# Every path in the fixture that must still exist afterwards.
survivors() {
  cat <<EOF
$SANDBOX/Applications/DovetailPro.app/Contents/Info.plist
$SANDBOX/Applications/Keystone.app
$SANDBOX/Library/LaunchDaemons/com.apple.something.plist
$SANDBOX/Library/PrivilegedHelperTools/com.other.helper
$FAKE_HOME/Library/Preferences/com.acme.dovetailpro.plist
$FAKE_HOME/Library/Preferences/com.acme.keystone.plist
$FAKE_HOME/Library/Preferences/com.apple.finder.plist
$FAKE_HOME/Library/Application Support/Keystone
$FAKE_HOME/Library/Application Support/Firefox
$FAKE_HOME/Library/Caches/com.acmecorp.dovetailer
$FAKE_HOME/Library/Application Support/Dovetailé
EOF
}

# `defaults` is a macOS command and the scripts use it to read a bundle ID.
# Rather than add a Linux fallback to the script purely so a test can run — test
# scaffolding leaking into the thing under test — the harness provides a stub
# that honours the same contract: read CFBundleIdentifier from an Info.plist, or
# exit non-zero. The script itself is unchanged and unaware.
STUBS="$SANDBOX_BIN"
make_stubs() {
  mkdir -p "$STUBS"
  cat > "$STUBS/defaults" <<'STUB'
#!/bin/bash
# Minimal stand-in for macOS `defaults read <plist-without-extension> <key>`
[ "${1:-}" = "read" ] || exit 1
PLIST="$2.plist"; KEY="${3:-}"
[ -f "$PLIST" ] || exit 1
V=$(tr -d '\n' < "$PLIST" | sed -n "s|.*<key>$KEY</key>[[:space:]]*<string>\([^<]*\)</string>.*|\1|p")
[ -n "$V" ] || exit 1
printf '%s\n' "$V"
STUB
  chmod +x "$STUBS/defaults"
}

delete_set() { # <script> <args...> -> the machine-readable block, sorted
  local S=$1; shift
  PATH="$STUBS:$PATH" NEPTUNE_ROOT="$SANDBOX" HOME="$FAKE_HOME" "$REPO/scripts/$S" "$@" 2>/dev/null \
    | sed -n '/^DELETE-SET BEGIN$/,/^DELETE-SET END$/p' \
    | sed '1d;$d' | sort
}

make_stubs

############################################################
t_section "uninstall.sh — completeness"
############################################################
build_fixture
SET=$(delete_set uninstall.sh Dovetail --dry-run)

for MUST in \
  "$SANDBOX/Applications/Dovetail.app" \
  "$FAKE_HOME/Library/Application Support/Dovetail" \
  "$FAKE_HOME/Library/Caches/com.acme.dovetail" \
  "$FAKE_HOME/Library/Preferences/com.acme.dovetail.plist" \
  "$FAKE_HOME/Library/Containers/com.acme.dovetail" \
  "$SANDBOX/Library/LaunchDaemons/com.acme.dovetail.helper.plist"
do
  if printf '%s\n' "$SET" | grep -qF "	$MUST"; then
    t_ok "finds $(basename "$MUST")"
  else
    t_fail "finds $(basename "$MUST")" "in delete set" "missing"
  fi
done

############################################################
t_section "uninstall.sh — blast radius"
############################################################
# The assertion that matters: no decoy appears in the delete set.
LEAKED=""
while IFS= read -r KEEP; do
  [ -z "$KEEP" ] && continue
  printf '%s\n' "$SET" | grep -qF "	$KEEP" && LEAKED="$LEAKED$KEEP
"
done <<EOF
$(survivors)
EOF
t_is "no unrelated path is in the delete set" "" "$LEAKED"

# And specifically the substring collision, called out by name because it is the
# single most likely way this script goes wrong.
t_is "DovetailPro is not swept up with Dovetail" "" \
   "$(printf '%s\n' "$SET" | grep -F 'DovetailPro' || true)"

############################################################
t_section "uninstall.sh — --deep widens the net, and says so"
############################################################
build_fixture
DEEPSET=$(delete_set uninstall.sh Dovetail --deep --dry-run)
# --deep matches the VENDOR (acme), so same-vendor files are expected to appear.
# That is the documented trade-off; the test pins it so it cannot happen
# silently in normal mode.
t_is "deep mode does reach same-vendor files" "yes" \
   "$(printf '%s\n' "$DEEPSET" | grep -qF 'com.acme.keystone' && echo yes || echo no)"
t_is "normal mode does NOT" "no" \
   "$(printf '%s\n' "$SET" | grep -qF 'com.acme.keystone' && echo yes || echo no)"
# Even in deep mode, another vendor is still out of scope.
t_is "deep mode still does not reach a different vendor" "" \
   "$(printf '%s\n' "$DEEPSET" | grep -F 'com.acmecorp.dovetailer' || true)"

############################################################
t_section "uninstall.sh — dry run changes nothing"
############################################################
build_fixture
BEFORE=$(find "$SANDBOX" | sort)
delete_set uninstall.sh Dovetail --dry-run >/dev/null
AFTER=$(find "$SANDBOX" | sort)
t_is "the filesystem is byte-identical after a dry run" "" "$(diff <(echo "$BEFORE") <(echo "$AFTER"))"

############################################################
t_section "uninstall.sh — the real delete matches the dry run"
############################################################
# A dry run that disagrees with the delete stage would be worse than no dry run
# at all, so the two are compared directly: run for real in the sandbox, then
# check that exactly the dry-run paths are gone and everything else survived.
build_fixture
PLANNED=$(delete_set uninstall.sh Dovetail --dry-run | awk -F'\t' '$1!="process"{print $2}' | sort)
echo y | PATH="$STUBS:$PATH" NEPTUNE_ROOT="$SANDBOX" HOME="$FAKE_HOME" \
  "$REPO/scripts/uninstall.sh" Dovetail >/dev/null 2>&1

STILL_THERE=""
while IFS= read -r P; do
  [ -z "$P" ] && continue
  [ -e "$P" ] && STILL_THERE="$STILL_THERE$P
"
done <<EOF
$PLANNED
EOF
t_is "everything the dry run listed is gone" "" "$STILL_THERE"

GONE=""
while IFS= read -r KEEP; do
  [ -z "$KEEP" ] && continue
  [ -e "$KEEP" ] || GONE="$GONE$KEEP
"
done <<EOF
$(survivors)
EOF
t_is "every unrelated path survived a real removal" "" "$GONE"

############################################################
t_section "remove_mackeeper.sh — fixed target list"
############################################################
build_fixture
mkdir -p "$SANDBOX/Applications/MacKeeper.app" \
         "$SANDBOX/Library/Application Support/MacKeeper" \
         "$FAKE_HOME/Library/Application Support/MacKeeper"
echo x > "$SANDBOX/Library/LaunchDaemons/com.mackeeper.MacKeeperPrivilegedHelper.plist"
echo x > "$SANDBOX/Library/PrivilegedHelperTools/com.mackeeper.MacKeeperPrivilegedHelper"
echo x > "$FAKE_HOME/Library/LaunchAgents/com.mackeeper.MacKeeperAgent.plist"
echo x > "$FAKE_HOME/Library/Preferences/com.mackeeper.plist"
# Decoys that share the vendor-ish prefix but are NOT MacKeeper.
echo keep > "$FAKE_HOME/Library/Preferences/com.mackeeperfan.notes.plist"
mkdir -p "$SANDBOX/Applications/MacKeeperViewer.app"

MKSET=$(delete_set remove_mackeeper.sh --dry-run)
for MUST in \
  "$SANDBOX/Applications/MacKeeper.app" \
  "$SANDBOX/Library/PrivilegedHelperTools/com.mackeeper.MacKeeperPrivilegedHelper" \
  "$FAKE_HOME/Library/LaunchAgents/com.mackeeper.MacKeeperAgent.plist" \
  "$FAKE_HOME/Library/Application Support/MacKeeper"
do
  if printf '%s\n' "$MKSET" | grep -qF "	$MUST"; then
    t_ok "finds $(basename "$MUST")"
  else
    t_fail "finds $(basename "$MUST")" "in delete set" "missing"
  fi
done

t_is "MacKeeperViewer.app is not swept up" "" \
   "$(printf '%s\n' "$MKSET" | grep -F 'MacKeeperViewer' || true)"
t_is "com.mackeeperfan is not swept up" "" \
   "$(printf '%s\n' "$MKSET" | grep -F 'mackeeperfan' || true)"
t_is "no Dovetail path is in the MacKeeper delete set" "" \
   "$(printf '%s\n' "$MKSET" | grep -iF 'dovetail' || true)"

############################################################
t_section "remove_mackeeper.sh — nothing to do is not an error"
############################################################
build_fixture   # no MacKeeper files at all
OUT=$(NEPTUNE_ROOT="$SANDBOX" HOME="$FAKE_HOME" "$REPO/scripts/remove_mackeeper.sh" --dry-run 2>&1); RC=$?
t_is "exits 0 on a clean machine" "0" "$RC"
t_is "says there is nothing to remove" "yes" \
   "$(printf '%s' "$OUT" | grep -q 'nothing to remove' && echo yes || echo no)"

############################################################
t_section "Both scripts refuse a half-redirected sandbox"
############################################################
# NEPTUNE_ROOT set but HOME outside it would mean discovery looks in the fake
# tree while deletion reaches the real home. Refuse rather than do half of it.
check_refusal() { # <script> <args...>
  local S=$1; shift
  local OUT RC
  OUT=$(NEPTUNE_ROOT="$SANDBOX" HOME="$SANDBOX/../elsewhere" "$REPO/scripts/$S" "$@" 2>&1)
  RC=$?
  if [ "$RC" -ne 0 ] && printf '%s' "$OUT" | grep -q 'Refusing to run'; then
    t_ok "$S refuses when HOME is outside NEPTUNE_ROOT"
  else
    t_fail "$S refuses when HOME is outside NEPTUNE_ROOT" "non-zero exit + refusal" "rc=$RC $OUT"
  fi
}
check_refusal uninstall.sh Dovetail --dry-run
check_refusal remove_mackeeper.sh --dry-run
check_refusal clean_caches.sh

############################################################
t_section "clean_caches.sh — what 'all' can reach"
############################################################
# The cache cleaner is the one destructive script whose targets the user picks
# by NUMBER, so the hostile cases are about what gets numbered at all: Apple's
# caches, iCloud state, Homebrew's cache, and — the dangerous one — a "cache"
# folder that is really a symlink into Documents. "all" must reach none of them.
mb() { mkdir -p "$(dirname "$1")"; dd if=/dev/zero of="$1" bs=1024 count="$2" 2>/dev/null; }
build_caches() {
  build_fixture
  local C="$FAKE_HOME/Library/Caches"
  mb "$C/com.example.editor/blob" 2048
  mb "$C/com.example.big/a/b/blob" 3072
  mb "$C/com.example.linky/blob" 2048
  mb "$C/com.apple.Safari/blob" 2048
  mb "$C/CloudKit/blob" 2048
  mb "$C/Homebrew/downloads/blob" 2048
  mb "$C/com.example.tiny/blob" 8
  mb "$FAKE_HOME/Documents/precious.txt" 2048
  ln -s "$FAKE_HOME/Documents" "$C/com.example.escape"
  # a link INSIDE a cache that points out of it: rm -rf must remove the link,
  # never follow it
  ln -s "$FAKE_HOME/Documents" "$C/com.example.linky/docs-link"
}
clean() { # <stdin-script> <args...>
  local IN=$1; shift
  printf '%b' "$IN" | NEPTUNE_ROOT="$SANDBOX" HOME="$FAKE_HOME" "$REPO/scripts/clean_caches.sh" "$@" 2>&1
}
C="$FAKE_HOME/Library/Caches"

build_caches
BEFORE=$(find "$SANDBOX" | sort)
clean '' >/dev/null; RC=$?
AFTER=$(find "$SANDBOX" | sort)
t_is "report mode exits 0" "0" "$RC"
t_is "report mode changes nothing" "" "$(diff <(echo "$BEFORE") <(echo "$AFTER"))"

CSET=$(clean 'all\n' --apply --dry-run | sed -n '/^DELETE-SET BEGIN$/,/^DELETE-SET END$/p' | sed '1d;$d' | cut -f2 | sort)
t_is "'all' selects exactly the third-party caches over 1 MB" \
  "$(printf '%s\n' "$C/com.example.big" "$C/com.example.editor" "$C/com.example.linky" | sort)" "$CSET"
AFTER=$(find "$SANDBOX" | sort)
t_is "--apply --dry-run changes nothing" "" "$(diff <(echo "$BEFORE") <(echo "$AFTER"))"

############################################################
t_section "clean_caches.sh — the real clear"
############################################################
build_caches
clean '9\n' --apply >/dev/null; RC=$?
t_is "an out-of-range selection is refused" "1" "$RC"
t_is "...and changes nothing" "yes" "$([ -f "$C/com.example.big/a/b/blob" ] && echo yes || echo no)"
clean 'all\nno\n' --apply >/dev/null
t_is "anything but 'yes' changes nothing" "yes" "$([ -f "$C/com.example.editor/blob" ] && echo yes || echo no)"
clean 'all\ny\n' --apply >/dev/null
t_is "a bare 'y' is not 'yes'" "yes" "$([ -f "$C/com.example.editor/blob" ] && echo yes || echo no)"

clean 'all\nyes\n' --apply >/dev/null
for D in com.example.editor com.example.big com.example.linky; do
  t_is "$D is emptied, and the folder itself kept" "dir:0" \
    "$([ -d "$C/$D" ] && echo dir || echo gone):$(find "$C/$D" -mindepth 1 | wc -l | tr -d ' ')"
done
for K in "$C/com.apple.Safari/blob" "$C/CloudKit/blob" "$C/Homebrew/downloads/blob" \
         "$C/com.example.tiny/blob" "$FAKE_HOME/Documents/precious.txt"; do
  t_is "survives: ${K#"$FAKE_HOME"/}" "yes" "$([ -f "$K" ] && echo yes || echo no)"
done
t_is "the symlinked 'cache' is still a symlink to Documents" "yes" \
  "$([ -L "$C/com.example.escape" ] && echo yes || echo no)"

build_caches
rm -rf "$C"; mkdir -p "$FAKE_HOME/Documents"; ln -s "$FAKE_HOME/Documents" "$C"
OUT=$(clean 'all\nyes\n' --apply); RC=$?
t_is "refuses when ~/Library/Caches itself is a symlink" "1" "$RC"
t_is "...and Documents is untouched" "yes" "$([ -f "$FAKE_HOME/Documents/precious.txt" ] && echo yes || echo no)"

############################################################
printf '\n================================================\n'
printf '  %d passed, %d failed\n' "$PASS" "$FAIL"
printf '================================================\n'
[ "$FAIL" -eq 0 ]
