#!/bin/bash
#
# unit.sh — Regression tests for Neptune's parsing layer.
#
# Every bug found in the 2026-09 audit lived in text processing: a codesign
# query at the wrong verbosity, a digest regex that matched its own summary
# lines, a MAC pattern that assumed zero-padded octets. None of them needed
# macOS to reproduce — only saved command output. That is what this file is.
#
# It runs anywhere bash and awk do, including the Linux CI runner, which is the
# point: the checks that CANNOT run on Linux (does `codesign` exist, is this
# really BSD grep) are exactly the ones a fixture cannot help with, and
# pretending otherwise is how you get a test suite that proves nothing.
#
# Usage:  ./tests/unit.sh
# Fixtures live in tests/fixtures/ and are real captured output, lightly
# sanitised.

set -u
cd "$(dirname "$0")/.." || exit 1

FIX="tests/fixtures"
PASS=0; FAIL=0

# NOTE: these are t_-prefixed on purpose. Sourcing a scan script for its pure
# functions also defines that script's ok()/warn()/bad() colour helpers, which
# silently replaced the unprefixed versions halfway through this file — 27
# assertions printed results and none of them counted. A harness that cannot
# report failure is the same bug as a CI gate that never fires.
t_ok()   { PASS=$((PASS + 1)); printf '  ok    %s\n' "$1"; }
t_fail() { FAIL=$((FAIL + 1)); printf '  FAIL  %s\n' "$1"
           printf '          expected: [%s]\n          actual:   [%s]\n' "$2" "$3"; }
t_is()   { # t_is <description> <expected> <actual>
           if [ "$2" = "$3" ]; then t_ok "$1"; else t_fail "$1" "$2" "$3"; fi; }

t_section() { printf '\n== %s ==\n' "$1"; }

############################################################
t_section "sig() — code-signing authority (DEVLOG Bug 7)"
############################################################
# The bug: `codesign -dv` emits no Authority= lines at all, so the grep matched
# nothing on every binary and sig()'s Apple branch was unreachable. These tests
# assert on the classification given each real authority chain.

classify() { # <fixture> — mirrors sig()'s case on the first Authority line
  AUTH=$(grep -m1 '^Authority=' "$1" | cut -d= -f2)
  case "$AUTH" in
    "Software Signing"|"Apple Mac OS Application Signing") echo "apple" ;;
    "") echo "UNCLASSIFIED" ;;
    *) echo "signed:$AUTH" ;;
  esac
}

t_is "Apple system binary classifies as apple" \
   "apple" "$(classify $FIX/codesign-apple.txt)"

t_is "Developer ID binary classifies as signed with its signer named" \
   "signed:Developer ID Application: Distributed Creation Inc (9962T6AKMH)" \
   "$(classify $FIX/codesign-developer-id.txt)"

# The regression guard. This fixture is what `codesign -dv` (one v) actually
# returns. If someone drops a v, every binary silently classifies as unknown
# again — which is precisely what shipped and went unnoticed for months.
t_is "codesign -dv output yields NO authority — the Bug 7 shape" \
   "UNCLASSIFIED" "$(classify $FIX/codesign-dv-no-authority.txt)"

# And assert the scripts still ask for the verbosity that returns a chain.
for s in sentry redflag_scan check_updates audit_system; do
  n=$(grep -c 'codesign -dvv' "scripts/$s.sh" 2>/dev/null || true)
  [ "${n:-0}" -gt 0 ] && t_ok "scripts/$s.sh uses codesign -dvv" \
                      || t_fail "scripts/$s.sh uses codesign -dvv" ">=1 occurrence" "0"
done
n=$(grep -rc 'codesign -dv "' scripts/ 2>/dev/null | grep -v ':0$' | wc -l | xargs)
t_is "no script has regressed to codesign -dv" "0" "$n"

############################################################
t_section "is_private() — NAT hop classification (DEVLOG Bug 5)"
############################################################
# Sourced for is_private(). This also pulls in that script's own helpers; the
# t_ prefix above is what keeps them from colliding with the harness.
# shellcheck source=/dev/null
NEPTUNE_LIB=1 . scripts/network_check.sh

check_priv() { if is_private "$1"; then echo private; else echo public; fi; }

t_is "10.0.0.1 is private"        "private" "$(check_priv 10.0.0.1)"
t_is "192.168.1.1 is private"     "private" "$(check_priv 192.168.1.1)"
t_is "172.16.0.1 is private"      "private" "$(check_priv 172.16.0.1)"
t_is "172.31.255.1 is private"    "private" "$(check_priv 172.31.255.1)"
t_is "172.32.0.1 is NOT private"  "public"  "$(check_priv 172.32.0.1)"
t_is "172.2.8.1 is NOT private"   "public"  "$(check_priv 172.2.8.1)"
t_is "100.64.0.1 is CGNAT/private" "private" "$(check_priv 100.64.0.1)"
t_is "100.128.0.1 is NOT CGNAT"   "public"  "$(check_priv 100.128.0.1)"
t_is "8.8.8.8 is public"          "public"  "$(check_priv 8.8.8.8)"
t_is "1.1.1.1 is public"          "public"  "$(check_priv 1.1.1.1)"

############################################################
t_section "Ephemeral listener-port collapse (ROADMAP #5)"
############################################################
collapse() {
  awk '$NF ~ /LISTEN/ {
        addr = $9
        n = split(addr, p, ":")
        if (p[n] + 0 >= 49152 && p[n] + 0 <= 65535) sub(/:[0-9]+$/, ":ephemeral", addr)
        print "listener:" $1 ":" addr
      }' "$1" | sort -u
}
OUT=$(collapse $FIX/lsof-listeners.txt)

t_is "fixed low port is kept verbatim" \
   "listener:ControlCe:*:5000" "$(echo "$OUT" | grep '^listener:ControlCe')"
t_is "port 49152 (range floor) collapses" \
   "listener:Focusrite:*:ephemeral" "$(echo "$OUT" | grep '^listener:Focusrite')"
t_is "rapportd churn collapses" \
   "listener:rapportd:*:ephemeral" "$(echo "$OUT" | grep '^listener:rapportd')"
t_is "IPv6 bracket address parses correctly" \
   "listener:launchd:[::1]:8021" "$(echo "$OUT" | grep '^listener:launchd')"
t_is "Splice's two ports collapse to one ephemeral + one fixed" \
   "listener:Splice:127.0.0.1:10011 listener:Splice:127.0.0.1:ephemeral" \
   "$(echo "$OUT" | grep '^listener:Splice' | tr '\n' ' ' | sed 's/ $//')"

# The property that matters: churn is suppressed, real change is not.
sed 's/:61505/:62310/; s/:49177/:51002/' $FIX/lsof-listeners.txt > /tmp/nt_boot2.txt
t_is "same processes, new ephemeral ports next boot -> no diff" \
   "" "$(diff <(collapse $FIX/lsof-listeners.txt) <(collapse /tmp/nt_boot2.txt))"

printf 'evil_bd 9999 tito 3u IPv4 0xfff 0t0 TCP *:53201 (LISTEN)\n' \
  >> /tmp/nt_boot2.txt
t_is "a NEW listening process is still caught" \
   "listener:evil_bd:*:ephemeral" \
   "$(comm -13 <(collapse $FIX/lsof-listeners.txt) <(collapse /tmp/nt_boot2.txt))"

sed 's|TCP \[::1\]:6985|TCP *:6985|' $FIX/lsof-listeners.txt > /tmp/nt_exposed.txt
t_is "loopback -> all-interfaces is still caught" \
   "listener:WavesLoca:*:6985" \
   "$(comm -13 <(collapse $FIX/lsof-listeners.txt) <(collapse /tmp/nt_exposed.txt))"

############################################################
t_section "LAN census MAC extraction"
############################################################
# macOS formats MACs with ether_ntoa(), which does NOT zero-pad. A fixed {17}
# match dropped every device with a single-digit octet — in the check whose
# whole purpose is spotting a device you can't place.
macs() { grep -oiE '([0-9a-f]{1,2}:){5}[0-9a-f]{1,2}' "$1" | tr '\n' ' ' | sed 's/ $//'; }
t_is "non-zero-padded MACs are matched" \
   "3c:7c:3f:1a:2b:cc 8:0:27:a:b:c 0:1e:c2:9:f:3a a8:51:ab:1f:22:e0" \
   "$(macs $FIX/arp-an.txt)"
t_is "the old {17} pattern would have dropped two of four" \
   "2" "$(grep -oE '[0-9a-f:]{17}' $FIX/arp-an.txt | wc -l | xargs)"
INC=$(grep '(incomplete)' $FIX/arp-an.txt | grep -oiE '([0-9a-f]{1,2}:){5}[0-9a-f]{1,2}' | wc -l | xargs)
t_is "(incomplete) entries yield no MAC" "0" "$INC"

############################################################
t_section "System-proxy detection — the previously untested positive case"
############################################################
# This pattern was never verified against a machine with a proxy configured;
# the live check only ever saw the disabled shape, where macOS omits the keys
# entirely. The fixture settles it permanently.
# Extract the pattern the script ACTUALLY uses and test that, rather than a
# copy. A copy drifts: an earlier version of this test asserted only that the
# key names were present, so reverting the whitespace class to the GNU-only \s
# passed cleanly. The test must fail when the shipped regex changes meaning.
PROXY_RE=$(grep -oE "grep -qE '[^']*HTTPEnable[^']*'" scripts/redflag_scan.sh \
           | head -1 | sed "s/^grep -qE '//; s/'\$//")
t_is "the proxy pattern was extracted from the script" \
   "yes" "$([ -n "$PROXY_RE" ] && echo yes || echo no)"

grep -qE "$PROXY_RE" $FIX/scutil-proxy-enabled.txt \
  && t_ok "an ACTIVE proxy is detected" \
  || t_fail "an ACTIVE proxy is detected" "match" "no match (pattern: $PROXY_RE)"
grep -qE "$PROXY_RE" $FIX/scutil-proxy-disabled.txt \
  && t_fail "no proxy configured -> no match" "no match" "matched" \
  || t_ok "no proxy configured -> no match"

# NOTE: deliberately NO assertion here about \s vs [[:space:]]. An earlier
# draft of this file required POSIX classes — encoding a claim this project
# investigated and RETRACTED (see docs/DEVLOG.md, "Correction — a bug that did
# not exist"). Apple ships GNU-compatible grep; \s works. Baking the withdrawn
# premise into CI would have made a false belief permanent and self-enforcing,
# which is worse than the original error.
#
# What IS asserted is behavioural and true on any grep: the shipped pattern
# matches a configured proxy and does not match an unconfigured one.

############################################################
t_section "grep -c semantics (the FLAGCOUNT doubled zero)"
############################################################
# `grep -c` prints 0 AND exits 1, so `|| echo 0` appended a second zero and a
# clean run rendered as "Digest (0\n0 ...)".
BROKEN=$(grep -cE 'nomatch' /dev/null 2>/dev/null || echo 0)
t_is "the old idiom really does produce two lines" "2" "$(printf '%s\n' "$BROKEN" | wc -l | xargs)"
FIXED=$(grep -cE 'nomatch' /dev/null 2>/dev/null); [ -n "$FIXED" ] || FIXED=0
t_is "the current idiom produces one" "1" "$(printf '%s\n' "$FIXED" | wc -l | xargs)"
t_is "and the value is 0" "0" "$FIXED"

############################################################
t_section "Scoring and verdict"
############################################################
score() { # <findings file> <allow file>
  awk -F'|' -v allowfile="$2" '
    BEGIN { while ((getline l < allowfile) > 0) if (l != "" && l !~ /^#/) allow[l] = 1
            n = split("security network bloat maintenance", C, " ")
            for (i = 1; i <= n; i++) score[C[i]] = 100 }
    NF >= 4 {
      sev = $1; cat = $2; title = $4
      key = tolower(title); gsub(/[0-9]+/, "#", key)
      if (key in allow) { next }
      if (sev == "info") next
      seen[cat "|" sev]++
      if (seen[cat "|" sev] == 1)
        w = (sev == "attention") ? 12 : (sev == "unknown") ? 8 : 4
      else
        w = (sev == "attention") ?  4 : (sev == "unknown") ? 3 : 1
      score[cat] -= w
    }
    END { for (i = 1; i <= n; i++) { c = C[i]; if (score[c] < 0) score[c] = 0
            printf "%s=%d ", c, score[c] } }
  ' "$1"
}
: > /tmp/nt_allow_empty.txt
t_is "scores from the real-world findings fixture" \
   "security=72 network=84 bloat=100 maintenance=96 " \
   "$(score $FIX/findings-realworld.txt /tmp/nt_allow_empty.txt)"

# Acknowledging the two unsigned-vendor findings should raise security only.
printf 'unsigned persistence: com.waves.wls.agent runs /library/application support/waves\n' > /tmp/nt_allow.txt
t_is "acknowledging a finding raises its category and nothing else" \
   "security=76 network=84 bloat=100 maintenance=96 " \
   "$(score $FIX/findings-realworld.txt /tmp/nt_allow.txt)"

# An 'info' record reports something NEPTUNE did, not something wrong with the
# machine. It is recorded so --json and the report agree, but it must cost zero.
# The 2026-09-18 run lost 4 security points to Neptune's own baseline-format
# migration, which is the tool billing the user for its own upgrade.
cp "$FIX/findings-realworld.txt" /tmp/nt_info.txt
printf 'info|security|sentry|Baseline format changed (v1 -> v2); baseline REPLACED, nothing diffed this run\n' >> /tmp/nt_info.txt
t_is "an info record changes no score" \
   "$(score "$FIX/findings-realworld.txt" /tmp/nt_allow_empty.txt)" \
   "$(score /tmp/nt_info.txt /tmp/nt_allow_empty.txt)"

# score() above is a transcription of the awk in neptune.sh. A transcription
# that drifts from its original tests nothing, so assert the weights are still
# character-identical in both files rather than trusting they are.
# Two distinct weight lines (first-of-kind, repeat) must appear in both files
# with identical text, so four matches collapse to two unique strings.
# Pattern assembled from pieces so these two lines do not match themselves.
W_PAT='w = (sev == "'"atten""tion"'")'
W_UNIQ=$(grep -hF "$W_PAT" scripts/neptune.sh tests/unit.sh \
           | sed 's/^[[:space:]]*//' | sort -u | wc -l | xargs)
W_TOTAL=$(grep -hcF "$W_PAT" scripts/neptune.sh tests/unit.sh \
           | awk '{s += $1} END {print s}')
t_is "both scoring copies exist"                     "4" "$W_TOTAL"
t_is "and their weights have not drifted apart"      "2" "$W_UNIQ"

# The key is digit-collapsed so it survives changing PIDs and ports.
KEY_A=$(echo "Unsigned process with network access: SoundID (pid 4574)" | tr 'A-Z' 'a-z' | sed 's/[0-9][0-9]*/#/g')
KEY_B=$(echo "Unsigned process with network access: SoundID (pid 9981)" | tr 'A-Z' 'a-z' | sed 's/[0-9][0-9]*/#/g')
t_is "acknowledge key survives a changed PID" "$KEY_A" "$KEY_B"

############################################################
t_section "Structured record format"
############################################################
# A pipe in a title must not break the 4-field format the renderer depends on.
rec() { printf '%s|%s|%s|%s\n' "$1" security test "$(printf '%s' "$2" | tr '|' '/' | tr -d '\n')"; }
t_is "a pipe in the title is escaped, format holds" \
   "attention|security|test|a / b" "$(rec attention 'a | b')"
t_is "field count stays 4" "4" "$(rec attention 'a | b | c' | awk -F'|' '{print NF}')"

############################################################
t_section "Recorded titles must stand alone"
############################################################
# A finding is printed in its scan's own output, where a following unprefixed
# echo can continue the sentence — and recorded as a single line, where nothing
# does. network_check.sh recorded "...root-owned daemons are NOT" and the master
# digest showed exactly that, mid-sentence, as item 15 of a real report.
#
# The heuristic: no recorded title may end on a word that cannot end an English
# sentence. A smell test, not a parser — and that is the right size for the
# problem, because the bug was always obvious to a human reading one line, and
# CI is the thing that does not get bored.
#
# The helper names are derived per file from which helpers actually call
# record(), rather than hardcoded. netcheck_plus.sh has a note() that only
# echoes, so a hardcoded list would fail on it — and would miss a recording
# helper added tomorrow under a name this file never heard of.
DANGLING='(NOT|not|and|or|but|the|a|an|is|are|was|were|to|of|in|on|for|with|that|which|than|—|-|,)'
FRAGMENTS=""
for F in scripts/*.sh; do
  HELPERS=$(grep -oE '^[a-z_]+\(\)[^#]*record ' "$F" | sed 's/().*//' \
            | sort -u | tr '\n' '|' | sed 's/|$//')
  [ -n "$HELPERS" ] || continue
  HIT=$(grep -nE "^[[:space:]]*($HELPERS)[[:space:]]+\"[^\"]*\"" "$F" \
        | grep -E "[[:space:]]$DANGLING\"[[:space:]]*\$" || true)
  [ -n "$HIT" ] && FRAGMENTS="$FRAGMENTS$F:$HIT"
done
t_is "no recorded finding title ends mid-sentence" "" "$FRAGMENTS"

############################################################
printf '\n================================================\n'
printf '  %d passed, %d failed\n' "$PASS" "$FAIL"
printf '================================================\n'
rm -f /tmp/nt_boot2.txt /tmp/nt_exposed.txt /tmp/nt_allow.txt /tmp/nt_allow_empty.txt
[ "$FAIL" -eq 0 ]
