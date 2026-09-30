#!/bin/bash
#
# unit.sh — Tests for Neptune's parsing, scoring and verdict layer.
#
# Every bug in the 2026-09 audits lived in text processing: a codesign query at
# the wrong verbosity, a MAC pattern that assumed zero-padded octets, an awk that
# aborted on half a UTF-8 character, a scoring step whose failure read as "no
# findings". None of them needed macOS to reproduce — only saved output.
#
# THE RULE THIS FILE FOLLOWS: it tests the code that ships, never a copy of it.
# It sources the real scripts with NEPTUNE_LIB=1, which loads their functions
# and stops before anything runs. The previous version carried transcriptions of
# the scoring awk, and a transcription that drifts from its original tests
# nothing — one of them had drifted.
#
# It runs anywhere bash 3.2+ and awk do. On the macOS CI job it runs under
# /bin/bash 3.2 and BWK awk, which is where the bugs actually were.
#
# Usage:  ./tests/unit.sh

set -u
cd "$(dirname "$0")/.." || exit 1
REPO=$(pwd)
FIX="$REPO/tests/fixtures"

T=$(mktemp -d "${TMPDIR:-/tmp}/neptune-unit.XXXXXX")
trap 'rm -rf "$T"' EXIT

# t_-prefixed on purpose: the sourced scripts define their own ok()/warn()/
# pass(), and unprefixed harness helpers were once silently replaced by them —
# 27 assertions printed results and none of them counted.
#
# The tally is a FILE, not a variable, because each script is sourced in its
# own subshell (they define functions with the same names) and a counter
# incremented in a subshell is lost when it exits — the same "results printed,
# never counted" failure by another route.
TALLY="$T/tally"; : > "$TALLY"
t_ok()   { echo pass >> "$TALLY"; printf '  ok    %s\n' "$1"; }
t_fail() { echo fail >> "$TALLY"; printf '  FAIL  %s\n' "$1"
           printf '          expected: [%s]\n          actual:   [%s]\n' "$2" "$3"; }
t_is()   { if [ "$2" = "$3" ]; then t_ok "$1"; else t_fail "$1" "$2" "$3"; fi; }
t_section() { printf '\n== %s ==\n' "$1"; }
STUBS="$T/bin"; mkdir -p "$STUBS"

# The real pipeline. Sourcing also sets LC_ALL=C for this whole shell, exactly
# as a real run does.
# shellcheck source=/dev/null
NEPTUNE_LIB=1 . scripts/neptune.sh

############################################################
t_section "Every script runs in the C locale (DEVLOG Bug 13)"
############################################################
MISSING=""
for F in scripts/*.sh; do
  grep -q '^export LC_ALL=C' "$F" || MISSING="$MISSING $F"
done
t_is "every script exports LC_ALL=C" "" "$MISSING"
t_is "and sourcing the runner set it here" "C" "${LC_ALL:-}"

############################################################
t_section "sig() — five signing classes, both copies (Bugs 7 and 16)"
############################################################
# A stub codesign that replays captured output. -v succeeds or fails on
# CS_VALID; -dvv prints the fixture to stderr, as the real one does.
cat > "$STUBS/codesign" <<'STUB'
#!/bin/bash
case "$1" in
  -v)   exit "${CS_VALID:-0}" ;;
  -dvv) cat "$CS_FIXTURE" >&2; exit 0 ;;
esac
exit 1
STUB
chmod +x "$STUBS/codesign"

sig_in() { # <script> <fixture> <valid 0|1> [path]
  ( export HOME="$T/home-$1"; mkdir -p "$HOME"
    export PATH="$STUBS:$PATH" CS_FIXTURE="$2" CS_VALID="$3"
    # shellcheck source=/dev/null
    NEPTUNE_LIB=1 . "scripts/$1" >/dev/null 2>&1
    sig "${4:-/bin/sh}" )
}
for S in redflag_scan.sh sentry.sh; do
  t_is "$S: Apple binary -> apple" "apple" "$(sig_in "$S" "$FIX/codesign-apple.txt" 0)"
  t_is "$S: macOS 26 authority name -> apple (Bug 20)" "apple" "$(sig_in "$S" "$FIX/codesign-apple-macos26.txt" 0)"
  t_is "$S: Developer ID -> signed, signer named" \
     "signed:Developer ID Application: Distributed Creation Inc (9962T6AKMH)" \
     "$(sig_in "$S" "$FIX/codesign-developer-id.txt" 0)"
  t_is "$S: Signature=adhoc -> adhoc, NOT signed" "adhoc" "$(sig_in "$S" "$FIX/codesign-adhoc.txt" 0)"
  t_is "$S: valid but no Authority line -> adhoc" "adhoc" "$(sig_in "$S" "$FIX/codesign-dv-no-authority.txt" 0)"
  t_is "$S: invalid signature -> unsigned" "unsigned" "$(sig_in "$S" "$FIX/codesign-apple.txt" 1)"
  t_is "$S: no such file -> missing" "missing" "$(sig_in "$S" "$FIX/codesign-apple.txt" 0 /nonexistent/x)"
done
n=$(grep -l 'codesign -dv "' scripts/*.sh 2>/dev/null | wc -l | tr -d ' ')
t_is "no script queries codesign at -dv, which prints no Authority (Bug 7)" "0" "$n"

############################################################
t_section "redflag_scan.sh helpers"
############################################################
(
  export HOME="$T/home-rf"; mkdir -p "$HOME"
  # shellcheck source=/dev/null
  NEPTUNE_LIB=1 . scripts/redflag_scan.sh >/dev/null 2>&1
  t_is "port 22 is Remote Login, a remote-access service" "Remote Login (SSH)|remote" "$(port_label 22)"
  t_is "port 5000 is AirPlay, labelled only" "AirPlay Receiver|label" "$(port_label 5000)"
  t_is "an unknown port has no label" "" "$(port_label 6985)"
  t_is "ad-hoc reads as AD-HOC SIGNED in a title" "AD-HOC SIGNED" "$(sig_word adhoc)"
  if is_system_path /usr/libexec/x; then t_ok "/usr/libexec is a system path"; else t_fail "/usr/libexec is a system path" yes no; fi
  # shellcheck disable=SC2034  # read by the sourced covered_by_flag()
  FLAGGED_BINS="
/Library/PrivilegedHelperTools/com.docker.socket
/Library/PrivilegedHelperTools/licenseDaemon.app/Contents/MacOS/licenseDaemon"
  t_is "a helper already reported as a launch item is not reported twice (Bug 17)" "yes yes no" \
     "$(for h in com.docker.socket licenseDaemon.app com.docker; do
          covered_by_flag "/Library/PrivilegedHelperTools/$h" && printf 'yes ' || printf 'no '; done | sed 's/ $//')"
  if is_system_path /usr/local/bin/x; then t_fail "/usr/local is NOT a system path" no yes; else t_ok "/usr/local is NOT a system path"; fi
)

# Proxy pattern — the one the script ships, extracted, not a copy.
PROXY_RE=$(grep -oE "grep -qE '[^']*HTTPEnable[^']*'" scripts/redflag_scan.sh | head -1 | sed "s/^grep -qE '//; s/'\$//")
t_is "the proxy pattern was found in the script" "yes" "$([ -n "$PROXY_RE" ] && echo yes || echo no)"
t_is "an ACTIVE proxy is detected" "yes" "$(grep -qE "$PROXY_RE" "$FIX/scutil-proxy-enabled.txt" && echo yes || echo no)"
t_is "no proxy configured -> no match" "no" "$(grep -qE "$PROXY_RE" "$FIX/scutil-proxy-disabled.txt" && echo yes || echo no)"

############################################################
t_section "network_check.sh — is_private() (Bug 5)"
############################################################
(
  # shellcheck source=/dev/null
  NEPTUNE_LIB=1 . scripts/network_check.sh >/dev/null 2>&1
  for c in 10.0.0.1:private 192.168.1.1:private 172.16.0.1:private 172.31.255.1:private \
           172.32.0.1:public 172.2.8.1:public 100.64.0.1:private 100.128.0.1:public \
           8.8.8.8:public 1.1.1.1:public; do
    ip=${c%%:*}; want=${c#*:}
    if is_private "$ip"; then got=private; else got=public; fi
    t_is "$ip is $want" "$want" "$got"
  done
)

############################################################
t_section "sentry.sh — listener_entries() ephemeral-port collapse"
############################################################
(
  export HOME="$T/home-se"; mkdir -p "$HOME"
  # shellcheck source=/dev/null
  NEPTUNE_LIB=1 . scripts/sentry.sh >/dev/null 2>&1
  t_is "sourcing sentry.sh creates nothing in HOME" "" "$(ls -A "$HOME")"
  OUT=$(listener_entries < "$FIX/lsof-listeners.txt")
  t_is "fixed low port kept" "listener:ControlCe:*:5000" "$(echo "$OUT" | grep '^listener:ControlCe')"
  t_is "port 49152 collapses" "listener:Focusrite:*:ephemeral" "$(echo "$OUT" | grep '^listener:Focusrite')"
  t_is "IPv6 bracket address parses" "listener:launchd:[::1]:8021" "$(echo "$OUT" | grep '^listener:launchd')"
  sed 's/:61505/:62310/; s/:49177/:51002/' "$FIX/lsof-listeners.txt" > "$T/boot2.txt"
  t_is "new ephemeral ports next boot -> no diff" "" \
     "$(diff <(listener_entries < "$FIX/lsof-listeners.txt") <(listener_entries < "$T/boot2.txt"))"
  printf 'evil_bd 9999 u 3u IPv4 0xfff 0t0 TCP *:53201 (LISTEN)\n' >> "$T/boot2.txt"
  t_is "a NEW listening process is still caught" "listener:evil_bd:*:ephemeral" \
     "$(comm -13 <(listener_entries < "$FIX/lsof-listeners.txt") <(listener_entries < "$T/boot2.txt"))"
  sed 's|TCP \[::1\]:6985|TCP *:6985|' "$FIX/lsof-listeners.txt" > "$T/exposed.txt"
  t_is "loopback -> all-interfaces is still caught" "listener:WavesLoca:*:6985" \
     "$(comm -13 <(listener_entries < "$FIX/lsof-listeners.txt") <(listener_entries < "$T/exposed.txt"))"
)

############################################################
t_section "netcheck_plus.sh — LAN census"
############################################################
(
  # shellcheck source=/dev/null
  NEPTUNE_LIB=1 . scripts/netcheck_plus.sh >/dev/null 2>&1
  MAC_RE=$(grep -oE "grep -oiE '[^']*\{1,2\}[^']*'" scripts/netcheck_plus.sh | head -1 | sed "s/^grep -oiE '//; s/'\$//")
  t_is "non-zero-padded MACs are matched (ether_ntoa)" \
     "3c:7c:3f:1a:2b:cc 8:0:27:a:b:c 0:1e:c2:9:f:3a a8:51:ab:1f:22:e0" \
     "$(grep -oiE "$MAC_RE" "$FIX/arp-an.txt" | tr '\n' ' ' | sed 's/ $//')"
  t_is "a randomized (locally administered) MAC is marked private" "private" "$(mac_kind da:a1:19:0:0:1)"
  t_is "...including an unpadded one" "private" "$(mac_kind 2:0:0:0:0:1)"
  t_is "a vendor MAC is not" "" "$(mac_kind 3c:7c:3f:1a:2b:cc)"
  if gt "" 10; then t_fail "gt with an empty value is false" false true; else t_ok "gt with an empty value is false"; fi
)

############################################################
t_section "check_updates.sh — softwareupdate parser and timeout"
############################################################
(
  # shellcheck source=/dev/null
  NEPTUNE_LIB=1 . scripts/check_updates.sh >/dev/null 2>&1
  P=$(su_parse 26 < "$FIX/softwareupdate-2026-09-18.txt")
  t_is "minor updates are updates" "Safari 27.0|macOS Tahoe 26.7" \
     "$(printf '%s\n' "$P" | awk -F'\t' '$1=="update"{print $3}' | tr '\n' '|' | sed 's/|$//')"
  t_is "a newer MAJOR macOS is an upgrade, never an update" "macOS 27" \
     "$(printf '%s\n' "$P" | awk -F'\t' '$1=="upgrade"{print $3}')"
  t_is "labels are kept, for installing by label" "macOS Tahoe 26.7-25G229" \
     "$(printf '%s\n' "$P" | awk -F'\t' '$3=="macOS Tahoe 26.7"{print $2}')"
  t_is "on macOS 27 itself, 27 is not an upgrade" "0" \
     "$(su_parse 27 < "$FIX/softwareupdate-2026-09-18.txt" | grep -c '^upgrade')"
  t_is "'No new software available' parses to nothing" "" "$(echo 'No new software available.' | su_parse 26)"
  t_is "join_names caps at five" "a, b, c, d, e and 2 more" "$(printf 'a\nb\nc\nd\ne\nf\ng\n' | join_names)"
  t_is "clip keeps whole words" "one two ..." "$(echo 'one two three four' | clip 9)"
  t_is "clip of one long word" "..." "$(echo 'abcdefghijkl' | clip 5)"
  CMP=$(printf 'Audacity.app\t3.7.8.0\nzoom.us.app\t7.1.9 (88375)\nSoulseekQt.app\t?\nUnknown.app\t1.0\n' \
        | catalog_compare "$FIX/cask-catalog.jws.json" "$(printf 'foo\nbar')")
  t_is "catalog: an app behind the cask version is 'behind'" "audacity 3.7.9 behind" \
     "$(printf '%s\n' "$CMP" | awk -F'\t' '$1=="Audacity.app"{print $2, $4, $5}')"
  t_is "catalog: '7.1.9 (88375)' vs '7.1.9.88375' is the same release, not behind" "current" \
     "$(printf '%s\n' "$CMP" | awk -F'\t' '$1=="zoom.us.app"{print $5}')"
  t_is "catalog: a version with no number is unknown, never behind" "unknown" \
     "$(printf '%s\n' "$CMP" | awk -F'\t' '$1=="SoulseekQt.app"{print $5}')"
  t_is "catalog: an app the catalog does not know is left out" "" \
     "$(printf '%s\n' "$CMP" | grep '^Unknown.app' || true)"
  t_is "catalog: an app already installed as a cask is left to brew outdated" "" \
     "$(printf 'Audacity.app\t3.7.8.0\n' | catalog_compare "$FIX/cask-catalog.jws.json" audacity)"
  START=$(date +%s)
  with_timeout 1 sleep 5; RC=$?
  ELAPSED=$(( $(date +%s) - START ))
  t_is "with_timeout kills a hung command with 143" "143" "$RC"
  t_is "...within a few seconds" "yes" "$([ "$ELAPSED" -le 3 ] && echo yes || echo no)"
  with_timeout 5 false; t_is "with_timeout passes the command's own status through" "1" "$?"
  START=$(date +%s)
  V=$(with_timeout 5 echo hi)
  t_is "a captured with_timeout returns output..." "hi" "$V"
  t_is "...without waiting out the timer" "yes" "$([ $(( $(date +%s) - START )) -le 2 ] && echo yes || echo no)"
)

############################################################
t_section "clean_caches.sh — selection parser"
############################################################
(
  # shellcheck source=/dev/null
  NEPTUNE_LIB=1 . scripts/clean_caches.sh >/dev/null 2>&1
  sel() { parse_selection "$1" "$2" 2>/dev/null | tr '\n' ' ' | sed 's/ $//'; parse_selection "$1" "$2" >/dev/null 2>&1 || echo ERR; }
  t_is "ranges and lists" "1 2 3 4 7" "$(sel 8 '2-4 1,7')"
  t_is "all" "1 2 3" "$(sel 3 all)"
  t_is "08 is eight" "8" "$(sel 8 08)"
  t_is "out of range is refused" "ERR" "$(sel 8 9)"
  t_is "zero is refused" "ERR" "$(sel 8 0)"
  t_is "a backwards range is refused" "ERR" "$(sel 8 5-2)"
  t_is "one bad token refuses the whole selection" "ERR" "$(sel 8 '1 2 x')"
  if never_offer com.apple.Safari && never_offer CloudKit && never_offer Homebrew; then
    t_ok "Apple, iCloud and Homebrew caches are never offered"
  else t_fail "Apple, iCloud and Homebrew caches are never offered" yes no; fi
)

############################################################
t_section "fix.sh — the guided fixer"
############################################################
(
  # shellcheck source=/dev/null
  NEPTUNE_LIB=1 . scripts/fix.sh >/dev/null 2>&1
  BAD=""
  for C in $(grep -ohE '\bCHECK=[a-z0-9-]+' scripts/*.sh | sed 's/CHECK=//' | sort -u) scan-failed unknown-thing; do
    plan_for "$C" "UNSIGNED persistence: x runs /Applications/Some App.app/Contents/MacOS/x (/Library/LaunchAgents/x.plist)"
    case "$KIND" in run|open|guide) ;; *) BAD="$BAD $C:kind=$KIND" ;; esac
    case "$CMD" in *'|'*|*';'*|*'&'*|*'>'*|*'<'*|*'`'*|*'$('*) BAD="$BAD $C:cmd" ;; esac
    [ "$KIND" = guide ] && [ -z "$GUIDE" ] && BAD="$BAD $C:no-guidance"
  done
  t_is "every check id gets a plan: a kind, a plain command, or guidance" "" "$BAD"
  plan_for firewall "x"
  t_is "the firewall fix is the documented one-liner" \
     "run|sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on" "$KIND|$CMD"
  plan_for macos-updates x; A1=$ACTION; plan_for brew-outdated x; A2=$ACTION; plan_for mas-outdated x
  t_is "one upgrade run covers macOS, brew and App Store findings" "upgrade upgrade upgrade" "$A1 $A2 $ACTION"
  plan_for persistence-launchd "UNSIGNED persistence: a runs /Applications/SoundID Reference.app/Contents/MacOS/x (/p.plist)"
  t_is "an unsigned app's finding offers its uninstall, name kept whole" "uninstall:SoundID Reference" "$ACTION"
  plan_for double-nat x
  t_is "no invented fix where there is none (double NAT is a router setting)" "guide" "$KIND"
  t_is "run_words: a ; is data, not a command separator" "a;b" "$(run_words 'printf %s a;b')"
  t_is "run_words: no globbing" "*" "$(cd "$T" && run_words 'printf %s *')"
)
t_is "fix.sh contains no eval and deletes nothing itself" "" \
   "$(grep -nE '^[^#]*\b(eval|rm)[[:space:]]' scripts/fix.sh || true)"
FH="$T/fixhome"; mkdir -p "$FH/.neptune"
W="$T/wfix"; mkdir -p "$W"
nep_run_pipeline "$FIX/findings-2026-09-18.txt" "$T/allow" "$W" "run 2026-09-18 09:00"
cp "$LISTING" "$FH/.neptune/last-listing.tsv"
PLANOUT=$(HOME="$FH" ./scripts/fix.sh --plan)
t_is "--plan covers every numbered item" "$(grep -vc '^#' "$LISTING")" "$(printf '%s\n' "$PLANOUT" | grep -vc '^#')"
t_is "--plan changes nothing and writes no log" "no" "$([ -e "$FH/.neptune/fix-log.tsv" ] && echo yes || echo no)"
mkdir -p "$T/nofix"
HOME="$T/nofix" ./scripts/fix.sh --plan >/dev/null 2>&1
t_is "no saved run yet: exit 64" "64" "$?"

############################################################
t_section "Every scan's record() writes one well-formed line"
############################################################
for S in sentry redflag_scan network_check audit_system check_updates; do
  (
    export HOME="$T/home-rec-$S"; mkdir -p "$HOME"
    # shellcheck source=/dev/null
    NEPTUNE_LIB=1 . "scripts/$S.sh" >/dev/null 2>&1
    export NEPTUNE_FINDINGS="$T/rec-$S.txt"; : > "$NEPTUNE_FINDINGS"
    # shellcheck disable=SC2034  # read by the sourced record()
    CHECK=probe
    record notice "$(printf 'a | b\tc\nd')"
  )
  t_is "$S: 5 fields, pipe escaped, no tab or newline" "notice|probe|a / b c d" \
     "$(awk -F'|' 'NF == 5 {print $1 "|" $4 "|" $5}' "$T/rec-$S.txt")"
done

############################################################
t_section "Pipeline on the real 2026-09-18 findings"
############################################################
: > "$T/allow"
W="$T/w1"; mkdir -p "$W"
nep_run_pipeline "$FIX/findings-2026-09-18.txt" "$T/allow" "$W" "unit"
t_is "integrity holds" "1" "$INTEGRITY"
t_is "scores" "security=52 network=80 bloat=100 maintenance=95" \
   "$(awk -F'|' '$1=="score"{printf "%s%s=%s", (n++ ? " " : ""), $2, $3}' "$SCORES")"
t_is "counts: pass/attention/notice/unknown/info" "15/11/4/0/2" \
   "$(nep_count "$SCORES" pass)/$N_ATTENTION/$N_NOTICE/$N_UNKNOWN/$N_INFO"
t_is "verdict" "needs_attention" "$VKEY"
t_is "exit status" "1" "$(nep_exit_status)"
t_is "the 4-field form from Neptune 0.x is still accepted" "7" \
   "$(W2="$T/w0"; mkdir -p "$W2"; nep_run_pipeline "$FIX/findings-realworld.txt" "$T/allow" "$W2" x; grep -c . "$SCORED")"

############################################################
t_section "Listing numbering (DEVLOG Bug 14)"
############################################################
nep_run_pipeline "$FIX/findings-2026-09-18.txt" "$T/allow" "$W" "unit"
t_is "one contiguous sequence, 1..N" "$(seq 1 15 | tr '\n' ' ')" \
   "$(grep -v '^#' "$LISTING" | cut -f1 | tr '\n' ' ')"
t_is "attention first, then minor" "attention" \
   "$(grep -v '^#' "$LISTING" | head -1 | cut -f2)"
t_is "passes and notes are not numbered" "0" \
   "$(grep -v '^#' "$LISTING" | cut -f2 | grep -cE '^(pass|info)$')"

############################################################
t_section "Fail closed: what loses results can never read HEALTHY"
############################################################
W="$T/w2"; mkdir -p "$W"
: > "$T/empty.txt"
nep_run_pipeline "$T/empty.txt" "$T/allow" "$W" x
t_is "no records at all -> integrity failure" "0" "$INTEGRITY"
t_is "...verdict incomplete, not healthy" "incomplete" "$VKEY"
t_is "...exit 2" "2" "$(nep_exit_status)"

printf 'pass|security|x|sip|SIP on\nthis is not a record\nbogus|security|x|y|z\n' > "$T/bad.txt"
nep_run_pipeline "$T/bad.txt" "$T/allow" "$W" x
t_is "malformed records become an unknown finding" "1" "$N_UNKNOWN"
t_is "...naming how many" "yes" \
   "$(grep -q '^unknown|security|neptune|record-format|2 result line' "$SCORED" && echo yes || echo no)"
t_is "...and the run exits 2, not 0" "2" "$(nep_exit_status)"

printf 'notice|bloat|a|b|same\nnotice|bloat|a|b|same\n' > "$T/dup.txt"
nep_run_pipeline "$T/dup.txt" "$T/allow" "$W" x
t_is "exact duplicates are dropped without tripping integrity" "1:1" "$INTEGRITY:$N_NOTICE"

# Half an em-dash, the shape lsof's byte-truncated COMMAND column produces.
# On macOS awk in a UTF-8 locale this ABORTED the scoring step (DEVLOG Bug 13).
printf 'attention|security|sentry|network-signing|Unsigned process: Caf\303 (pid 12) \342\200 x\n' > "$T/utf8.txt"
printf 'pass|security|redflag|sip|SIP is on\n' >> "$T/utf8.txt"
nep_run_pipeline "$T/utf8.txt" "$T/allow" "$W" x 2>"$T/utf8.err"
t_is "invalid UTF-8 in a title: both records survive" "2" "$(grep -c . "$SCORED")"
t_is "...integrity holds" "1" "$INTEGRITY"
t_is "...and awk printed nothing to stderr" "" "$(cat "$T/utf8.err")"

# Fail closed on a scoring crash: point the scorer at an unreadable input.
nep_run_pipeline "$T/does-not-exist" "$T/allow" "$W" x 2>/dev/null
t_is "a scoring step that cannot read its input -> integrity failure" "0" "$INTEGRITY"
t_is "...never healthy" "incomplete" "$VKEY"

############################################################
t_section "Acknowledge key (DEVLOG Bugs 10 and 12)"
############################################################
LONG='Unsigned process with network access: WavesLoca (pid 4500) — sig:UNSIGNED — outbound:3 — LISTENING on: [::1]:6985'
printf 'attention|security|sentry|network-signing|%s\n' "$LONG" > "$T/long.txt"
nep_run_pipeline "$T/long.txt" "$T/allow" "$W" x 2>"$T/key.err"
K=$(cut -d'|' -f6 "$SCORED")
t_is "the key is exactly what ~/.neptune/allow expects" \
   'unsigned process with network access: wavesloca (pid #) — sig:unsigned — outbound:#' "$K"
t_is "it fits the 90-byte budget" "yes" "$([ "$(printf '%s' "$K" | wc -c | tr -d ' ')" -le 90 ] && echo yes || echo no)"
t_is "the key builder is silent" "" "$(cat "$T/key.err")"
if command -v python3 >/dev/null 2>&1; then
  printf '%s' "$K" > "$T/key.txt"
  t_is "the key is valid UTF-8 (built from whole words, never sliced)" "ok" \
     "$(python3 -c 'import sys; open(sys.argv[1],"rb").read().decode("utf-8"); print("ok")' "$T/key.txt" 2>/dev/null)"
fi
printf 'attention|security|x|y|Unsigned process with network access: SoundID (pid 4574)\n' > "$T/p1.txt"
printf 'attention|security|x|y|Unsigned process with network access: SoundID (pid 9981)\n' > "$T/p2.txt"
nep_run_pipeline "$T/p1.txt" "$T/allow" "$W" x; K1=$(cut -d'|' -f6 "$SCORED")
nep_run_pipeline "$T/p2.txt" "$T/allow" "$W" x; K2=$(cut -d'|' -f6 "$SCORED")
t_is "the key survives a changed PID" "$K1" "$K2"

############################################################
t_section "Acknowledging: stays counted, stops deducting"
############################################################
W="$T/w3"; mkdir -p "$W"
nep_run_pipeline "$FIX/findings-2026-09-18.txt" "$T/allow" "$W" x
BEFORE=$(awk -F'|' '$1=="score"{printf "%s=%s ", $2, $3}' "$SCORES")
grep -v '^#' "$LISTING" | head -1 | cut -f4 > "$T/allow1"
nep_run_pipeline "$FIX/findings-2026-09-18.txt" "$T/allow1" "$W" x
t_is "one acknowledged" "1" "$N_ACK"
t_is "...still in the scored records" "32" "$(grep -c . "$SCORED")"
t_is "...security rises, nothing else moves" \
   "$(echo "$BEFORE" | sed 's/security=52/security=56/')" \
   "$(awk -F'|' '$1=="score"{printf "%s=%s ", $2, $3}' "$SCORES")"
t_is "...and it leaves the numbered list" "14" "$(grep -vc '^#' "$LISTING")"
printf 'pass|security|x|sip|sip is on\ninfo|security|x|baseline-diff|note\n' > "$T/pi.txt"
printf 'sip is on\nnote\n' > "$T/allow2"
nep_run_pipeline "$T/pi.txt" "$T/allow2" "$W" x
t_is "a pass or an info cannot be acknowledged" "0" "$N_ACK"
t_is "an info record costs nothing" "100" "$(awk -F'|' '$1=="score" && $2=="security"{print $3}' "$SCORES")"

############################################################
t_section "--acknowledge resolves the list you READ (DEVLOG Bug 14)"
############################################################
AH="$T/ackhome"; mkdir -p "$AH/.neptune"
nep_run_pipeline "$FIX/findings-2026-09-18.txt" "$T/allow" "$W" "run 2026-09-18 09:00"
cp "$LISTING" "$AH/.neptune/last-listing.tsv"
WANT=$(awk -F'\t' '$1 == 2 {print $4}' "$LISTING")
echo y | HOME="$AH" ./scripts/neptune.sh --acknowledge 2 >/dev/null 2>&1
t_is "item 2 of the saved listing is what gets acknowledged" "$WANT" "$(cat "$AH/.neptune/allow" 2>/dev/null)"
HOME="$AH" ./scripts/neptune.sh --acknowledge 99 >/dev/null 2>&1
t_is "a number not in the listing exits 64" "64" "$?"
echo n | HOME="$AH" ./scripts/neptune.sh --acknowledge 3 >/dev/null 2>&1
t_is "declining changes nothing" "1" "$(grep -c . "$AH/.neptune/allow")"
mkdir -p "$T/nohome"
HOME="$T/nohome" ./scripts/neptune.sh --acknowledge 1 >/dev/null 2>&1
t_is "no saved listing yet exits 64" "64" "$?"

############################################################
t_section "Vendor catalogue labels, never suppresses"
############################################################
QF=scripts/vendor-quirks.tsv
t_is "three tab-separated columns" "" \
   "$(grep -v '^#' "$QF" | grep -v '^[[:space:]]*$' | awk -F'\t' 'NF != 3 {print NR": "NF}')"
t_is "patterns are lowercase" "" "$(grep -v '^#' "$QF" | awk -F'\t' '$1 ~ /[A-Z]/ {print $1}')"
t_is "no duplicate patterns" "" "$(grep -v '^#' "$QF" | grep -v '^[[:space:]]*$' | cut -f1 | sort | uniq -d)"
t_is "no entry is shadowed by an earlier, broader one" "" "$(awk -F'\t' '
  !/^#/ && NF == 3 { n++; pat[n] = $1 }
  END { for (i = 1; i <= n; i++) for (j = i + 1; j <= n; j++)
          if (index(pat[j], pat[i]) > 0) print pat[j] " shadowed by " pat[i] }' "$QF")"

label_of() { printf 'attention|security|x|y|%s\n' "$1" > "$T/lab.txt"
             nep_run_pipeline "$T/lab.txt" "$T/allow" "$W" x; cut -d'|' -f8 "$SCORED"; }
t_is "Waves listener labelled" "Waves" "$(label_of 'Listener with unverifiable signature: WavesLoca (pid 4500) binary:/Library/Application Support/Waves/WavesLocalServer')"
t_is "Docker helper labelled" "Docker" "$(label_of 'UNSIGNED privileged helper (runs as root): /Library/PrivilegedHelperTools/com.docker.socket')"
t_is "a brew service labelled" "Homebrew" "$(label_of 'AD-HOC SIGNED persistence: homebrew.mxcl.redis runs /opt/homebrew/bin/redis-server')"
t_is "an impostor is not labelled" "" "$(label_of 'UNSIGNED persistence: com.evil.fakewaves runs /tmp/x')"
printf 'attention|security|x|y|UNSIGNED privileged helper (runs as root): /Library/PrivilegedHelperTools/com.docker.socket\n' > "$T/lab.txt"
nep_run_pipeline "$T/lab.txt" "$T/allow" "$W" x
t_is "a label changes neither severity nor score nor the acknowledged flag" "attention|0|88" \
   "$(cut -d'|' -f1,7 "$SCORED")|$(awk -F'|' '$1=="score" && $2=="security"{print $3}' "$SCORES")"

############################################################
t_section "Per-finding history (first seen, run count)"
############################################################
SF="$T/seen.tsv"
printf 'attention|security|x|y|unsigned helper x\nnotice|security|x|y|firewall is off\npass|security|x|y|sip on\n' > "$T/s1.txt"
printf 'attention|security|x|y|unsigned helper x\n' > "$T/s2.txt"
field() { awk -F'\t' -v k="$1" '$1 == k {print $'"$2"'}' "$SF"; }
nep_run_pipeline "$T/s1.txt" "$T/allow" "$W" x; nep_update_seen "$SCORED" "$SF" 2026-09-01
t_is "a new finding starts at one run" "1" "$(field 'unsigned helper x' 4)"
t_is "passes are not tracked" "" "$(field 'sip on' 4)"
nep_run_pipeline "$T/s2.txt" "$T/allow" "$W" x; nep_update_seen "$SCORED" "$SF" 2026-09-08
t_is "a recurring finding increments" "2" "$(field 'unsigned helper x' 4)"
t_is "first_seen does not move" "2026-09-01" "$(field 'unsigned helper x' 2)"
t_is "a finding that went away keeps its last-seen date" "2026-09-01" "$(field 'firewall is off' 3)"

############################################################
t_section "Command line and exit-code contract"
############################################################
./scripts/neptune.sh --help >/dev/null 2>&1;             t_is "--help exits 0" "0" "$?"
./scripts/neptune.sh --not-a-flag >/dev/null 2>&1;       t_is "unknown flag exits 64" "64" "$?"
./scripts/neptune.sh --sanitize >/dev/null 2>&1;         t_is "--sanitize alone exits 64" "64" "$?"
./scripts/neptune.sh --acknowledge nonsense >/dev/null 2>&1; t_is "malformed --acknowledge exits 64" "64" "$?"
t_is "the help documents 0, 1, 2, 64 and 77" "0 1 2 64 77" \
   "$(./scripts/neptune.sh --help | grep -oE '^ +(0|1|2|64|77)  ' | tr -d ' ' | tr '\n' ' ' | sed 's/ $//')"
for S in check_updates netcheck_plus clean_caches; do
  ./scripts/$S.sh --bogus >/dev/null 2>&1; t_is "$S.sh: unknown flag exits 64" "64" "$?"
  ./scripts/$S.sh --help >/dev/null 2>&1;  t_is "$S.sh: --help exits 0" "0" "$?"
done
t_is "every scan ends in an explicit exit 0 (a crash is then distinguishable)" "" \
   "$(for S in sentry redflag_scan network_check audit_system check_updates; do
        tail -3 "scripts/$S.sh" | grep -q '^exit 0' || echo "$S"; done)"

############################################################
t_section "Recorded titles must stand alone"
############################################################
# A title is printed where the next echo can finish the sentence, and recorded
# alone, where nothing does. network_check.sh once recorded "...daemons are NOT".
DANGLING='(NOT|not|and|or|but|the|a|an|is|are|was|were|to|of|in|on|for|with|that|which|than|—|-|,)'
FRAGMENTS=""
for F in scripts/*.sh; do
  HELPERS=$(grep -oE '^[a-z_]+\(\)[^#]*record ' "$F" | sed 's/().*//' | sort -u | tr '\n' '|' | sed 's/|$//')
  [ -n "$HELPERS" ] || continue
  HIT=$(grep -nE "^[[:space:]]*($HELPERS)[[:space:]]+\"[^\"]*\"" "$F" \
        | grep -E "[[:space:]]$DANGLING\"[[:space:]]*\$" || true)
  [ -n "$HIT" ] && FRAGMENTS="$FRAGMENTS$F:$HIT"
done
t_is "no recorded title ends mid-sentence" "" "$FRAGMENTS"

############################################################
PASS=$(grep -c '^pass$' "$TALLY"); FAIL=$(grep -c '^fail$' "$TALLY")
printf '\n================================================\n'
printf '  %d passed, %d failed\n' "$PASS" "$FAIL"
printf '================================================\n'
[ "$FAIL" -eq 0 ]
