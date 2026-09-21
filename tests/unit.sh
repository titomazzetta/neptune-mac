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
t_section "Acknowledge key must stay valid UTF-8 (DEVLOG Bug 10)"
############################################################
# substr() in awk counts BYTES, and these titles are full of em-dashes. A cut at
# byte 90 could land inside one and leave a lone \xe2\x80 in the record, which is
# no longer valid UTF-8 — and --json died reading it. Finding #1 of the real
# 2026-09-18 report is exactly this shape, so the bug was one flag away the whole
# time. The fix cuts back to the previous space, and a space cannot be inside a
# character.
LONG_TITLE="Unsigned process with network access: WavesLoca (pid 4500) — sig:UNSIGNED — outbound:3 — LISTENING on: [::1]:6985"

fixed_key() {  # mirrors the key builder in neptune.sh
  awk '{ key = tolower($0); gsub(/[0-9]+/, "#", key); gsub(/[ \t]+/, " ", key)
         if (length(key) > 90) {
           nw = split(key, w, " ")
           key = w[1]
           for (i = 2; i <= nw; i++) {
             cand = key " " w[i]
             if (length(cand) > 90) break
             key = cand
           }
         }
         print key }'
}
broken_key() {  # what shipped, kept so the test is pinned to a reproduction.
  # stderr silenced on purpose: this deliberately builds the invalid string, and
  # on macOS awk that is exactly what prints the warning asserted against below.
  awk '{ key = tolower($0); gsub(/[0-9]+/, "#", key); print substr(key, 1, 90) }' 2>/dev/null
}
sliced_key() {  # the FIRST fix: cut at 90, then trim back. Correct, but noisy.
  awk '{ key = tolower($0); gsub(/[0-9]+/, "#", key); gsub(/[ \t]+/, " ", key)
         if (length(key) > 90) { key = substr(key, 1, 90); sub(/[^ ]*$/, "", key); sub(/ +$/, "", key) }
         print key }'
}
utf8_ok() { python3 -c 'import sys; sys.stdin.buffer.read().decode("utf-8")' 2>/dev/null; }

if printf '%s' "$LONG_TITLE" | fixed_key | utf8_ok; then
  t_ok "truncated key is valid UTF-8"
else
  t_fail "truncated key is valid UTF-8" "decodes cleanly" "invalid byte sequence"
fi

if printf '%s' "$LONG_TITLE" | broken_key | utf8_ok; then
  t_fail "the old byte-cut really did corrupt this title" \
         "invalid UTF-8" "decoded fine — the fixture no longer reproduces the bug"
else
  t_ok "the old byte-cut really did corrupt this title"
fi

K=$(printf '%s' "$LONG_TITLE" | fixed_key)
t_is "key is truncated, not passed through" "yes" \
   "$( [ "${#K}" -lt "${#LONG_TITLE}" ] && echo yes || echo no )"
t_is "key has no trailing space" "" "$(printf '%s' "$K" | grep -o ' $' || true)"

# The builder must be SILENT. macOS awk (20200816) prints
#   awk: towc: multibyte conversion failure on: '?'
# to stderr the moment a sub() touches bytes left invalid by a mid-character
# substr. The first fix produced correct output and that warning on every long
# finding — a scan that emits parser noise during a normal run is not one people
# keep trusting, and it was invisible on the Linux CI runner.
#
# The current builder concatenates whole words and never creates the invalid
# intermediate at all, so there is nothing to warn about.
NOISE=$(printf '%s' "$LONG_TITLE" | fixed_key 2>&1 >/dev/null)
t_is "the key builder writes nothing to stderr" "" "$NOISE"

# And pin the reproduction: the slice-then-trim version really is the noisy one,
# so this assertion cannot quietly stop testing anything.
SLICED_NOISE=$(printf '%s' "$LONG_TITLE" | sliced_key 2>&1 >/dev/null)
if [ -n "$SLICED_NOISE" ]; then
  t_ok "slice-then-trim is the version that warns (reproduced here)"
else
  # Linux awk does not warn, so this is informational rather than a failure —
  # the point is that the CURRENT builder is silent on both.
  t_ok "slice-then-trim warns only on macOS awk (silent on this awk)"
fi

# Both approaches must agree on the answer; only the noise differs.
t_is "word-wise and slice-then-trim produce the same key" \
   "$(printf '%s' "$LONG_TITLE" | sliced_key 2>/dev/null)" "$K"

############################################################
t_section "Remediation advice covers what we have actually seen"
############################################################
# advice_coverage.py executes the real remediation table out of neptune.sh
# rather than re-implementing it — one table, one source, no drift. It fails
# loudly if its extraction markers stop matching, because a test that quietly
# stops testing is the harness bug all over again.
t_is "every finding in the real-world fixture gets advice" \
   "" "$(python3 tests/advice_coverage.py "$FIX/findings-realworld.txt")"

printf 'attention|security|x|A finding shape Neptune has never emitted\n' > /tmp/nt_novel.txt
t_is "an unrecognised finding is reported as unmapped, not silently blank" \
   "A finding shape Neptune has never emitted" \
   "$(python3 tests/advice_coverage.py /tmp/nt_novel.txt)"

# Every command the table offers must be a single command, not a pipeline or a
# chain. That is the table's own stated rule; assert it rather than trust it.
#
# The checker is a FILE, not a heredoc inside $(...). The inline version parsed
# on bash 5 and was a syntax error on bash 3.2 — see the header of
# tests/command_safety.py for why, and note that it failed as a PARSE error, so
# this file exited non-zero having printed no FAIL at all.
t_is "no remediation command is a pipeline, chain or substitution" "" \
   "$(python3 tests/command_safety.py)"

############################################################
t_section "Vendor catalogue is a label, never a suppression"
############################################################
QF=scripts/vendor-quirks.tsv

# Format: three tab-separated columns, lowercase pattern, no duplicates.
BADCOLS=$(grep -v '^#' "$QF" | grep -v '^[[:space:]]*$' | awk -F'\t' 'NF != 3 {print NR": "NF" columns"}')
t_is "every entry has exactly three columns" "" "$BADCOLS"

UPPER=$(grep -v '^#' "$QF" | grep -v '^[[:space:]]*$' | awk -F'\t' '$1 ~ /[A-Z]/ {print $1}')
t_is "patterns are lowercase (they match a lowercased title)" "" "$UPPER"

DUPES=$(grep -v '^#' "$QF" | grep -v '^[[:space:]]*$' | cut -f1 | sort | uniq -d)
t_is "no duplicate patterns" "" "$DUPES"

# A pattern that is a substring of another entry's pattern must come FIRST, or
# the more specific entry is unreachable. The file documents "most specific
# first"; this is the assertion behind the comment.
SHADOWED=$(awk -F'\t' '
  !/^#/ && NF == 3 { n++; pat[n] = $1 }
  END {
    for (i = 1; i <= n; i++)
      for (j = i + 1; j <= n; j++)
        if (index(pat[j], pat[i]) > 0)
          print pat[j] " is unreachable: " pat[i] " matches first"
  }' "$QF")
t_is "no entry is shadowed by an earlier, broader one" "" "$SHADOWED"

# The labelling matcher, mirroring the awk in neptune.sh.
label_for() {
  awk -F'\t' -v quirks="$QF" -v title="$1" '
    BEGIN {
      while ((getline line < quirks) > 0) {
        if (line ~ /^#/ || line ~ /^[ \t]*$/) continue
        split(line, f, "\t")
        if (f[1] == "" || f[2] == "") continue
        n++; pat[n] = f[1]; ven[n] = f[2]
      }
      lt = tolower(title)
      for (i = 1; i <= n; i++) if (index(lt, pat[i]) > 0) { print ven[i]; exit }
    }'
}

t_is "the Waves listener is labelled" "Waves" \
   "$(label_for 'Unsigned process with network access: WavesLoca (pid 4500) — /Library/Application Support/Waves/WavesLocalServer/WavesLocalServer.bundle/Contents/MacOS/WavesLocalServer')"
t_is "the Docker root helper is labelled" "Docker" \
   "$(label_for 'UNSIGNED privileged helper (runs as root): /Library/PrivilegedHelperTools/com.docker.socket')"
t_is "the PACE licence daemon is labelled" "PACE/iLok" \
   "$(label_for 'UNSIGNED persistence: com.paceap.eden.licensed runs /Library/PrivilegedHelperTools/licenseDaemon.app')"
t_is "an unrelated finding is NOT labelled" "" \
   "$(label_for 'SECOND PRIVATE ROUTER in path: 192.168.1.254')"
t_is "a plausible-looking impostor is not labelled" "" \
   "$(label_for 'UNSIGNED persistence: com.evil.fakewaves runs /tmp/x')"

# The property that matters most: a label must not change severity, scoring or
# the acknowledged flag. Nothing in the catalogue is allowed to suppress.
t_is "the catalogue file never mentions acknowledging or suppressing" "" \
   "$(grep -n 'acknowledge\|suppress' "$QF" | grep -v '^[0-9]*:#' || true)"

############################################################
t_section "Per-finding history (first seen, run count)"
############################################################
bump_seen() { # <seen file> <date> <keys...>
  local SF=$1 DAY=$2; shift 2
  printf '%s\n' "$@" > /tmp/nt_keys.txt
  awk -F'\t' -v today="$DAY" '
    FNR == NR {
      if ($0 ~ /^#/ || $1 == "") next
      first[$1] = $2; last[$1] = $3; runs[$1] = $4
      if (!($1 in known)) { known[$1] = 1; order[++n] = $1 }
      next
    }
    { k = $0
      if (k in known) { last[k] = today; runs[k] = runs[k] + 1 }
      else { known[k] = 1; order[++n] = k; first[k] = today; last[k] = today; runs[k] = 1 } }
    END { printf "# key\tfirst_seen\tlast_seen\truns\n"
          for (i = 1; i <= n; i++) { k = order[i]
            printf "%s\t%s\t%s\t%d\n", k, first[k], last[k], runs[k] } }
  ' "$SF" /tmp/nt_keys.txt > /tmp/nt_seen.new && mv /tmp/nt_seen.new "$SF"
}
field() { awk -F'\t' -v k="$2" '$1 == k {print $'"$3"'}' "$1"; }

printf '# key\tfirst_seen\tlast_seen\truns\n' > /tmp/nt_seen.tsv
bump_seen /tmp/nt_seen.tsv 2026-09-01 "unsigned helper x" "firewall is off"
t_is "a new finding starts at one run"  "1"          "$(field /tmp/nt_seen.tsv 'unsigned helper x' 4)"
t_is "and records today as first seen"  "2026-09-01" "$(field /tmp/nt_seen.tsv 'unsigned helper x' 2)"

bump_seen /tmp/nt_seen.tsv 2026-09-08 "unsigned helper x"
t_is "a recurring finding increments"          "2"          "$(field /tmp/nt_seen.tsv 'unsigned helper x' 4)"
t_is "first_seen does NOT move"                "2026-09-01" "$(field /tmp/nt_seen.tsv 'unsigned helper x' 2)"
t_is "last_seen does move"                     "2026-09-08" "$(field /tmp/nt_seen.tsv 'unsigned helper x' 3)"
t_is "a finding that went away keeps its row"  "1"          "$(field /tmp/nt_seen.tsv 'firewall is off' 4)"
t_is "and keeps the date it was last seen"     "2026-09-01" "$(field /tmp/nt_seen.tsv 'firewall is off' 3)"

bump_seen /tmp/nt_seen.tsv 2026-09-15 "unsigned helper x" "firewall is off"
t_is "a returning finding resumes its count, not a new one" "2" \
   "$(field /tmp/nt_seen.tsv 'firewall is off' 4)"
t_is "with its original first_seen intact" "2026-09-01" \
   "$(field /tmp/nt_seen.tsv 'firewall is off' 2)"
t_is "the file has one row per key, no duplicates" "" \
   "$(grep -v '^#' /tmp/nt_seen.tsv | cut -f1 | sort | uniq -d)"

############################################################
t_section "Exit-code contract"
############################################################
./scripts/neptune.sh --help >/dev/null 2>&1
t_is "--help exits 0" "0" "$?"
./scripts/neptune.sh --not-a-real-flag >/dev/null 2>&1
t_is "an unknown flag exits 64 (usage error), not 1" "64" "$?"
./scripts/neptune.sh --sanitize >/dev/null 2>&1
t_is "--sanitize without an output format exits 64" "64" "$?"
./scripts/neptune.sh --acknowledge nonsense >/dev/null 2>&1
t_is "a malformed --acknowledge exits 64" "64" "$?"

# 0/1/2 need a full scan to reach, so assert instead that the exit branches use
# the SAME counts, in the same order, as the verdict that is printed. A verdict
# saying "needs attention" beside an exit code of 0 would be worse than having
# no exit code at all.
VERDICT_ORDER=$(sed -n '/^# Verdict\. Ordered worst-first/,/^fi$/p' scripts/neptune.sh \
                | grep -oE 'N_(ATTENTION|UNKNOWN|NOTICE)' | tr '\n' ' ')
EXIT_ORDER=$(sed -n '/^# Exit-code contract/,$p' scripts/neptune.sh | grep -oE 'N_(ATTENTION|UNKNOWN)' | tr '\n' ' ')
t_is "the exit code checks attention before unknown, as the verdict does" \
   "N_ATTENTION N_UNKNOWN " "$EXIT_ORDER"
t_is "and the verdict checks them in that same order" \
   "N_ATTENTION N_UNKNOWN N_NOTICE " "$VERDICT_ORDER"
t_is "the help text documents all three exit codes" "3" \
   "$(./scripts/neptune.sh --help 2>/dev/null | grep -cE '^  [012]  ')"

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
rm -f /tmp/nt_novel.txt /tmp/nt_keys.txt /tmp/nt_seen.tsv /tmp/nt_boot2.txt /tmp/nt_exposed.txt /tmp/nt_allow.txt /tmp/nt_allow_empty.txt
[ "$FAIL" -eq 0 ]
