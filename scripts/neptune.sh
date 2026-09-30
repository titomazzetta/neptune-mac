#!/bin/bash
#
# neptune.sh — run the Neptune scans and turn them into ONE verdict
#
# Runs, in order:  sentry.sh -> redflag_scan.sh -> network_check.sh
#                  -> audit_system.sh -> check_updates.sh (scan only)
#
# Then: a verdict, four category scores, a numbered list of what needs doing,
# and one combined plain-text report. Optionally a readable HTML report and
# structured JSON.
#
# The scan is read-only throughout: no --upgrade, no deletions. Fixing is a
# separate, explicit step — ./neptune.sh --fix hands over to fix.sh, which asks
# before every change.
#
# Run ./neptune.sh --help for flags and exit codes.

set -u

# ---------------------------------------------------------------------------
# Every script in Neptune runs in the C locale, and this is not cosmetic.
#
# macOS awk (BWK, version 20200816) does not merely warn when a string function
# meets invalid UTF-8 — it ABORTS THE WHOLE PROGRAM:
#
#     awk 'BEGIN { print "before"; s = substr("x—y", 1, 2); sub(/q/, "r", s); print "after" }'
#     before
#     awk: towc: multibyte conversion failure on: '?'        (exit 2, no "after")
#
# The scans feed awk text from lsof, ps, plists and filenames, and lsof in
# particular truncates command names to a fixed number of BYTES — so a process
# with a non-ASCII name can hand awk exactly that half-character. In a UTF-8
# locale that kills the pipeline mid-run; the old scoring awk ran with
# 2>/dev/null, so the findings list came back empty, silently, and an empty
# findings list scored HEALTHY. See DEVLOG Bug 13.
#
# In the C locale every tool treats text as bytes: nothing aborts, nothing
# converts, BSD sed and tr stop throwing "illegal byte sequence", and awk's
# length()/substr() mean the same thing on macOS and on the Linux CI runner.
# The bytes pass through unchanged, so the terminal still shows em-dashes.
# ---------------------------------------------------------------------------
export LC_ALL=C

NEPTUNE_VERSION="1.1.0"

BOLD=$(tput bold 2>/dev/null || true)
CYN=$(tput setaf 6 2>/dev/null || true)
GRN=$(tput setaf 2 2>/dev/null || true)
YEL=$(tput setaf 3 2>/dev/null || true)
RED=$(tput setaf 1 2>/dev/null || true)
RST=$(tput sgr0 2>/dev/null || true)

DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"   # BASH_SOURCE: correct when sourced by tests too
QUIRKS="$DIR/vendor-quirks.tsv"
RENDERER="$DIR/neptune_render.py"

############################################################################
# PIPELINE FUNCTIONS
#
# Everything from "records written by the scans" to "verdict on screen" lives
# in these functions, and tests/unit.sh sources this file with NEPTUNE_LIB=1 to
# call them directly. The tests used to carry TRANSCRIPTIONS of this awk — four
# of them — and a transcription that drifts from its original tests nothing.
# Now there is one copy, and it is the one that runs.
############################################################################

# Record format, written by every scan's record() helper, one per line:
#
#     severity|category|scan|check|title
#
#   severity  attention | notice | unknown | info | pass
#   category  security | network | bloat | maintenance
#   scan      which script recorded it (sentry, redflag, network, audit, updates)
#   check     stable id for WHAT was checked (filevault, listeners, ...) — the
#             same id whether the check passed or failed, which is what lets a
#             report say "FileVault: checked, on" rather than just staying quiet
#   title     one complete sentence; '|' is escaped to '/' at write time, so
#             a title can never add a field
#
# The 4-field form from Neptune 0.x (no check id) is still accepted, so an old
# findings file can be replayed.

# nep_score_records <findings> <allowfile> <quirks> <scored-out> <stats-out>
#
# Validates each record, derives its acknowledge key, marks it acknowledged or
# not, attaches a vendor label, and drops exact duplicates. Writes:
#
#     severity|category|scan|check|title|key|acked|vendor
#
# and "<lines> <valid> <malformed> <duplicates> <written>" to <stats-out>.
#
# The stats line is written in END, so if awk dies part-way through there is
# no stats line at all — which the caller treats as a pipeline failure, never as
# "no findings".
nep_score_records() {
  local IN=$1 ALLOWF=$2 QF=$3 OUT=$4 STATS=$5
  : > "$STATS"
  awk -v allowfile="$ALLOWF" -v quirks="$QF" -v statsfile="$STATS" '
    BEGIN {
      FS = "|"
      while ((getline l < allowfile) > 0) if (l != "" && l !~ /^#/) allow[l] = 1
      close(allowfile)
      nq = 0
      while ((getline line < quirks) > 0) {
        if (line ~ /^#/ || line ~ /^[ \t]*$/) continue
        split(line, f, "\t")
        if (f[1] == "" || f[2] == "") continue
        nq++; pat[nq] = f[1]; ven[nq] = f[2]
      }
      close(quirks)
      ok["attention"] = 1; ok["notice"] = 1; ok["unknown"] = 1
      ok["info"] = 1;      ok["pass"] = 1
    }
    {
      if (NF == 5)      { sev = $1; cat = $2; scan = $3; chk = $4; title = $5 }
      else if (NF == 4) { sev = $1; cat = $2; scan = $3; chk = "";  title = $4 }
      else              { bad++; next }
      if (!(sev in ok) || cat == "" || title == "") { bad++; next }
      gsub(/\t/, " ", title)     # the listing is TSV; a tab must not add a column
      valid++

      # Acknowledge key: lowercased, digits collapsed so it survives PIDs,
      # ports and versions, whitespace normalised, and capped at 90 bytes by
      # adding WHOLE WORDS — never by slicing, which can split a multibyte
      # character (DEVLOG Bugs 10 and 12).
      key = tolower(title)
      gsub(/[0-9]+/, "#", key); gsub(/[ \t]+/, " ", key)
      sub(/^ /, "", key); sub(/ $/, "", key)
      if (length(key) > 90) {
        nw = split(key, w, " ")
        key = w[1]
        for (i = 2; i <= nw; i++) {
          cand = key " " w[i]
          if (length(cand) > 90) break
          key = cand
        }
      }

      # Vendor label: a name and a sentence, never a suppression.
      label = ""
      lt = tolower(title)
      for (i = 1; i <= nq; i++) if (index(lt, pat[i]) > 0) { label = ven[i]; break }

      d = sev "|" cat "|" title
      if (d in seen) { dups++; next }
      seen[d] = 1

      # Only problems can be acknowledged. A pass or a note about the run has
      # nothing to silence.
      acked = (sev != "pass" && sev != "info" && (key in allow)) ? 1 : 0
      printf "%s|%s|%s|%s|%s|%s|%d|%s\n", sev, cat, scan, chk, title, key, acked, label
      written++
    }
    END { printf "%d %d %d %d %d\n", NR, valid, bad, dups, written > statsfile }
  ' "$IN" > "$OUT"
}

# nep_compute_scores <scored> <scores-out>
#
# Each category starts at 100. The first problem of a given severity in a
# category costs full weight; repeats cost about a third, because nine unsigned
# launch items are usually one vendor habit, not nine independent problems — and
# a flat per-finding deduction floors the score at 0, which stops distinguishing
# "several vendor quirks" from "actually compromised". Passes and notes about
# the run cost nothing. Acknowledged findings stay counted and stop deducting.
nep_compute_scores() {
  awk -F'|' '
    BEGIN { n = split("security network bloat maintenance", C, " ")
            for (i = 1; i <= n; i++) score[C[i]] = 100 }
    {
      sev = $1; cat = $2; acked = $7
      if (!(cat in score)) { score[cat] = 100; C[++n] = cat }
      if (sev == "pass") { counts["pass"]++; passes[cat]++; next }
      if (acked == 1)    { acks[cat]++; total_ack++; next }
      counts[sev]++
      if (sev == "info") next
      seen[cat "|" sev]++
      if (seen[cat "|" sev] == 1)
        w = (sev == "attention") ? 12 : (sev == "unknown") ? 8 : 4
      else
        w = (sev == "attention") ?  4 : (sev == "unknown") ? 3 : 1
      score[cat] -= w
    }
    END {
      for (i = 1; i <= n; i++) {
        c = C[i]; if (score[c] < 0) score[c] = 0
        printf "score|%s|%d|%d|%d\n", c, score[c], acks[c] + 0, passes[c] + 0
      }
      printf "count|attention|%d\n",    counts["attention"] + 0
      printf "count|notice|%d\n",       counts["notice"] + 0
      printf "count|unknown|%d\n",      counts["unknown"] + 0
      printf "count|info|%d\n",         counts["info"] + 0
      printf "count|pass|%d\n",         counts["pass"] + 0
      printf "count|acknowledged|%d\n", total_ack + 0
    }
  ' "$1" > "$2"
}

nep_count() { awk -F'|' -v k="$2" '$1=="count" && $2==k {print $3}' "$1"; }

# nep_verdict <scores> <integrity 0|1>
#
# Sets VERDICT, VKEY, VCOL and the N_* counts. Ordered worst-first, and a check
# that could not run outranks a minor finding, because an unknown is not a pass.
# A pipeline integrity failure can never read as healthy: at best it reads as
# incomplete.
nep_verdict() {
  local SC=$1 INTEGRITY=$2
  N_ATTENTION=$(nep_count "$SC" attention); N_NOTICE=$(nep_count "$SC" notice)
  N_UNKNOWN=$(nep_count "$SC" unknown);     N_ACK=$(nep_count "$SC" acknowledged)
  N_INFO=$(nep_count "$SC" info);           N_PASS=$(nep_count "$SC" pass)
  if   [ "${N_ATTENTION:-0}" -gt 0 ]; then VERDICT="NEEDS ATTENTION"; VKEY=needs_attention; VCOL="$RED"
  elif [ "$INTEGRITY" != "1" ];       then VERDICT="INCOMPLETE — results were lost; this is NOT a clean bill of health"; VKEY=incomplete; VCOL="$YEL"
  elif [ "${N_UNKNOWN:-0}"   -gt 0 ]; then VERDICT="HEALTHY — but some checks could not run"; VKEY=incomplete; VCOL="$YEL"
  elif [ "${N_NOTICE:-0}"    -gt 0 ]; then VERDICT="HEALTHY — minor items"; VKEY=healthy_minor; VCOL="$GRN"
  else                                     VERDICT="HEALTHY"; VKEY=healthy; VCOL="$GRN"
  fi
}

# nep_exit_status — the exit-code contract, ordered like the verdict: 1 when
# anything needs attention, 2 when the report is incomplete, 0 only when every
# check ran and passed. Acknowledged findings do not enter it: a machine that
# exits 0 because its owner silenced everything would make the exit code a
# worse signal than no exit code at all. Call after nep_verdict.
nep_exit_status() {
  if   [ "${N_ATTENTION:-0}" -gt 0 ]; then echo 1
  elif [ "${INTEGRITY:-0}" != "1" ] || [ "${N_UNKNOWN:-0}" -gt 0 ]; then echo 2
  else echo 0
  fi
}

# nep_listing <scored> <listing-out> <run-label>
#
# The numbered, actionable list — attention, then could-not-check, then minor —
# as n, severity, category, key, title, check (the check id is last so older
# readers of the first five columns keep working; fix.sh keys on it) —
# exactly as the terminal, the HTML report and --acknowledge number it. Saved
# after every run so that `--acknowledge 5` means item 5 of the list you READ,
# not item 5 of a fresh scan whose numbering may have shifted (DEVLOG Bug 14).
nep_listing() {
  local SCR=$1 OUT=$2 LABEL=$3
  {
    printf '# %s\n' "$LABEL"
    printf '# n\tseverity\tcategory\tkey\ttitle\tcheck\n'
    awk -F'|' '
      $7 == 0 && $1 == "attention" { a[++na] = $0 }
      $7 == 0 && $1 == "unknown"   { u[++nu] = $0 }
      $7 == 0 && $1 == "notice"    { m[++nm] = $0 }
      function emit(rec,   f) { split(rec, f, "|"); printf "%d\t%s\t%s\t%s\t%s\t%s\n", ++n, f[1], f[2], f[6], f[5], f[4] }
      END { for (i = 1; i <= na; i++) emit(a[i])
            for (i = 1; i <= nu; i++) emit(u[i])
            for (i = 1; i <= nm; i++) emit(m[i]) }
    ' "$SCR"
  } > "$OUT"
}

# render_verdict <scored> <scores> <listing> <integrity 0|1> <stats-message>
render_verdict() {
  local SCR=$1 SC=$2 LST=$3 INTEGRITY=$4 WHY=$5
  echo "================================================================"
  echo "  $VERDICT"
  echo "================================================================"
  if [ "$INTEGRITY" != "1" ]; then
    echo
    echo "  !! REPORT INTEGRITY FAILURE: $WHY"
    echo "  !! Some results are missing. Nothing below proves the machine is clean."
  fi
  echo
  awk -F'|' '$1=="score" {
    bar = ""
    filled = int($3 / 10)
    for (i = 0; i < 10; i++) bar = bar (i < filled ? "#" : ".")
    printf "  %-12s %3d/100  [%s]%s\n", $2, $3, bar,
           ($4 > 0 ? "  (" $4 " acknowledged)" : "")
  }' "$SC"
  echo
  printf '  %s checks passed · %s attention · %s minor · %s could not run · %s acknowledged' \
    "${N_PASS:-0}" "${N_ATTENTION:-0}" "${N_NOTICE:-0}" "${N_UNKNOWN:-0}" "${N_ACK:-0}"
  [ "${N_INFO:-0}" -gt 0 ] && printf ' · %s informational' "$N_INFO"
  echo

  # ONE number sequence across the three sections, read from the saved listing
  # so what is printed and what --acknowledge resolves are the same file.
  local LAST="" N SEV CAT KEY TITLE VEN
  while IFS="$(printf '\t')" read -r N SEV CAT KEY TITLE _CHK; do
    case "$N" in ''|'#'*) continue ;; esac
    if [ "$SEV" != "$LAST" ]; then
      echo
      case "$SEV" in
        attention) echo "  NEEDS ATTENTION" ;;
        unknown)   echo "  COULD NOT BE CHECKED  (treat as unknown, not clean)" ;;
        notice)    echo "  MINOR" ;;
      esac
      LAST=$SEV
    fi
    printf '   %2d. [%s] %s\n' "$N" "$CAT" "$TITLE"
    # Through the environment, not -v: awk rewrites backslash escapes in -v
    # values, and lsof prints a space in a command name as \x20.
    VEN=$(K="$KEY" T="$TITLE" awk -F'|' '$6==ENVIRON["K"] && $5==ENVIRON["T"] {print $8; exit}' "$SCR")
    [ -n "$VEN" ] && printf '       known %s pattern — see the HTML report for what it is\n' "$VEN"
  done < "$LST"

  # Unnumbered on purpose: the numbers are the argument to --acknowledge, and
  # there is nothing to acknowledge here. These are notes about the run.
  if [ "${N_INFO:-0}" -gt 0 ]; then
    echo; echo "  FOR INFORMATION — about this run, not about your machine (no score impact)"
    awk -F'|' '$1=="info" {printf "    · [%s] %s\n", $2, $5}' "$SCR"
  fi

  if [ "${N_ACK:-0}" -gt 0 ]; then
    echo; echo "  ACKNOWLEDGED — known-good on this machine, still counted"
    awk -F'|' '$7==1 {printf "   · [%s] %s\n", $2, $5}' "$SCR" | head -8
    [ "${N_ACK:-0}" -gt 8 ] && echo "   · ... and $(( N_ACK - 8 )) more"
  fi

  if [ "${N_ATTENTION:-0}" -gt 0 ] || [ "${N_NOTICE:-0}" -gt 0 ]; then
    echo
    echo "  Fix them one at a time, each shown and confirmed:  ./neptune.sh --fix"
    echo "  Recurring vendor quirk rather than a problem? Acknowledge it:"
    echo "      ./neptune.sh --acknowledge <n>      (number from the list above)"
  fi
  echo "================================================================"
}

# nep_update_seen <scored> <seen-file> <date>
#
# First seen, last seen and run count per PROBLEM (passes are not tracked), so
# a report can say "seen in each of the last six runs" instead of "flagged". A
# finding that stops appearing keeps its row with the date it was last seen —
# the record of something being fixed.
nep_update_seen() {
  local SCR=$1 SEENF=$2 DAY=$3 KEYS
  KEYS=$(mktemp "${TMPDIR:-/tmp}/neptune-keys.XXXXXX")
  # -s, not -f: an empty file would make the first awk pass read the KEYS file
  # as the history and write rows with blank dates.
  [ -s "$SEENF" ] || printf '# key\tfirst_seen\tlast_seen\truns\n' > "$SEENF"
  awk -F'|' '$1 != "pass" && $1 != "info" && $6 != "" {print $6}' "$SCR" | sort -u > "$KEYS"
  awk -F'\t' -v today="$DAY" '
    FNR == NR {
      if ($0 ~ /^#/ || $1 == "") next
      first[$1] = $2; last[$1] = $3; runs[$1] = $4
      if (!($1 in known)) { known[$1] = 1; order[++n] = $1 }
      next
    }
    {
      k = $0
      if (k in known) { last[k] = today; runs[k] = runs[k] + 1 }
      else { known[k] = 1; order[++n] = k; first[k] = today; last[k] = today; runs[k] = 1 }
    }
    END {
      printf "# key\tfirst_seen\tlast_seen\truns\n"
      for (i = 1; i <= n; i++) {
        k = order[i]
        printf "%s\t%s\t%s\t%d\n", k, first[k], last[k], runs[k]
      }
    }
  ' "$SEENF" "$KEYS" > "$SEENF.new" && mv "$SEENF.new" "$SEENF"
  rm -f "$KEYS"
}

# nep_append_history <history-file> <scores> <date> <verdict-key>
nep_append_history() {
  local H=$1 SC=$2 WHEN=$3 VK=$4
  [ -f "$H" ] || printf '# date\tverdict\tsecurity\tnetwork\tbloat\tmaintenance\tattention\tnotice\tunknown\tacknowledged\n' > "$H"
  awk -F'|' -v when="$WHEN" -v vk="$VK" '
    $1 == "score" { s[$2] = $3 }
    $1 == "count" { c[$2] = $3 }
    END { printf "%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n", when, vk,
            s["security"], s["network"], s["bloat"], s["maintenance"],
            c["attention"], c["notice"], c["unknown"], c["acknowledged"] }
  ' "$SC" >> "$H"
}

# python_ok — is there a python3 we can run WITHOUT side effects?
#
# On a Mac without the Xcode Command Line Tools, /usr/bin/python3 is a stub
# that pops a GUI "install developer tools" dialog. The old code assumed "python3
# ships with macOS" (it does not), so --json, --html and the browser-extension
# check could all throw a system dialog in the middle of a scan. The core scan
# and verdict never need python; only the optional outputs do.
python_ok() {
  local P
  P=$(command -v python3 2>/dev/null) || return 1
  if [ "$(uname -s)" = "Darwin" ] && [ "$P" = "/usr/bin/python3" ]; then
    xcode-select -p >/dev/null 2>&1 || return 1
  fi
  "$P" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 6) else 1)' >/dev/null 2>&1
}

# nep_run_pipeline <findings> <allowfile> <workdir> <run-label>
#
# Runs the whole analysis and sets SCORED, SCORES, LISTING, INTEGRITY, WHY and
# the verdict variables. Fails closed: anything that loses records turns
# INTEGRITY off, and the verdict can then never read HEALTHY.
nep_run_pipeline() {
  local FIN=$1 ALLOWF=$2 WORK=$3 LABEL=$4 STATSF ERRF LINES VALID BAD DUPS WROTE
  SCORED="$WORK/scored.txt"; SCORES="$WORK/scores.txt"; LISTING="$WORK/listing.tsv"
  STATSF="$WORK/stats.txt";  ERRF="$WORK/score.err"
  INTEGRITY=1; WHY=""

  if ! nep_score_records "$FIN" "$ALLOWF" "$QUIRKS" "$SCORED" "$STATSF" 2>"$ERRF"; then
    INTEGRITY=0; WHY="the scoring step failed ($(head -1 "$ERRF" 2>/dev/null))"
  fi
  if [ ! -s "$STATSF" ]; then
    INTEGRITY=0; WHY="${WHY:-the scoring step stopped before finishing}"
  else
    read -r LINES VALID BAD DUPS WROTE < "$STATSF"
    if [ "$WROTE" -ne $((VALID - DUPS)) ]; then
      INTEGRITY=0; WHY="$((VALID - DUPS)) records went in and only $WROTE came out"
    elif [ "$LINES" -eq 0 ]; then
      INTEGRITY=0; WHY="no scan recorded any result at all"
    fi
    if [ "$BAD" -gt 0 ]; then
      # Malformed records are not dropped silently: they become a finding.
      printf 'unknown|security|neptune|record-format|%s result line(s) from the scans could not be read, so those checks are missing from this report|unreadable scan records|0|\n' \
        "$BAD" >> "$SCORED"
    fi
  fi

  nep_compute_scores "$SCORED" "$SCORES"
  nep_verdict "$SCORES" "$INTEGRITY"
  nep_listing "$SCORED" "$LISTING" "$LABEL"
}

############################################################################
[ "${NEPTUNE_LIB:-}" = "1" ] && return 0
############################################################################

usage() {
  cat <<'USAGE'
neptune.sh — run the Neptune scans, then report a verdict and scores.

  ./neptune.sh                    run the suite (read-only; nothing is deleted)
  ./neptune.sh --html             also write a readable HTML report: every
                                  finding with what it means, what to do, and
                                  the command to do it — plus every check that
                                  PASSED, so the report proves what it covered.
                                  No JavaScript, no external anything.
  ./neptune.sh --json             also write structured findings as JSON
  ./neptune.sh --sanitize         with --html/--json: replace host, user, home
                                  paths, IPs and MACs, for sharing
  ./neptune.sh --out DIR          write reports to DIR (default ~/Desktop)
  ./neptune.sh --acknowledge N    mark finding N from your LAST run as a
                                  known-good vendor quirk (no re-scan)
  ./neptune.sh --acknowledge 2,5  several at once
  ./neptune.sh --fix              walk your LAST run's findings one at a time:
                                  the fix, its exact command, then a y/N for
                                  each; re-scan at the end to see before/after
  ./neptune.sh --replay FILE      re-render a saved --json file (or a findings
                                  file) without scanning: no sudo, no state
                                  written — for demos, CI and second opinions
  ./neptune.sh --version

Acknowledged findings stay listed and stay counted — they only stop deducting
from the score. Nothing is ever silently hidden. Edit ~/.neptune/allow to undo.

Every run keeps its scores in ~/.neptune/history.tsv and per-finding first/last
seen dates in ~/.neptune/seen.tsv, so the next report can show what moved.
Local plain text; delete either to forget. Nothing ever leaves the machine.

Exit codes, so this is scriptable across machines:
   0  healthy — every check ran and nothing needs attention
   1  one or more findings need attention
   2  incomplete — no attention items, but some check could not run, or the
      report lost results (an unknown is never a pass)
  64  usage error (bad flag, missing file, python3 needed for --html/--json)
  77  could not obtain administrator privileges, so nothing was scanned
Acknowledged findings do not affect the exit code: acknowledging is a statement
about a known vendor quirk, not about severity.

--html and --json need python3 (Xcode Command Line Tools: xcode-select
--install). The scan and verdict themselves need nothing beyond macOS.
See SECURITY.md for the full footprint and how to verify all of this.
USAGE
}

JSON_OUT=false; HTML_OUT=false; SANITIZE_OUT=false
ACK_ARG=""; REPLAY=""; OUT_DIR=""
while [ $# -gt 0 ]; do
  case "$1" in
    --json)        JSON_OUT=true ;;
    --html)        HTML_OUT=true ;;
    --sanitize)    SANITIZE_OUT=true ;;
    --acknowledge) shift; ACK_ARG="${1:-}"; [ -n "$ACK_ARG" ] || { echo "--acknowledge needs a number" >&2; exit 64; } ;;
    --replay)      shift; REPLAY="${1:-}";  [ -n "$REPLAY" ]  || { echo "--replay needs a file" >&2; exit 64; } ;;
    --out)         shift; OUT_DIR="${1:-}"; [ -n "$OUT_DIR" ] || { echo "--out needs a directory" >&2; exit 64; } ;;
    --fix)         exec "$DIR/fix.sh" ;;
    --version)     echo "neptune $NEPTUNE_VERSION"; exit 0 ;;
    -h|--help)     usage; exit 0 ;;
    *)             echo "Unknown option: $1  (try --help)" >&2; exit 64 ;;
  esac
  shift
done
case "$ACK_ARG" in
  ''|*[!0-9,]*) [ -z "$ACK_ARG" ] || { echo "--acknowledge takes finding numbers, e.g. 5 or 5,6,7" >&2; exit 64; } ;;
esac
if $SANITIZE_OUT && ! $JSON_OUT && ! $HTML_OUT; then
  echo "--sanitize only applies with --json or --html" >&2; exit 64
fi
# Refuse BEFORE a five-minute scan, not after it.
if { $JSON_OUT || $HTML_OUT || [ -n "$REPLAY" ]; } && ! python_ok; then
  echo "--html, --json and --replay need python3, which is not usable here." >&2
  echo "Install the Xcode Command Line Tools:  xcode-select --install" >&2
  echo "(The plain scan and verdict need nothing: run ./neptune.sh without them.)" >&2
  exit 64
fi

NEPTUNE_HOME="$HOME/.neptune"
ALLOW="$NEPTUNE_HOME/allow"
HISTORY="$NEPTUNE_HOME/history.tsv"
SEEN="$NEPTUNE_HOME/seen.tsv"
LAST_LISTING="$NEPTUNE_HOME/last-listing.tsv"
STAMP=$(date '+%Y-%m-%d_%H%M')
RUN_LABEL="run $(date '+%Y-%m-%d %H:%M')"

BUILD=$(git -C "$DIR" describe --always --dirty 2>/dev/null || true)
VERSION_STRING="$NEPTUNE_VERSION${BUILD:+ ($BUILD)}"

############################################################################
# --acknowledge: resolve against the list you actually read. No scan, no sudo.
############################################################################
if [ -n "$ACK_ARG" ]; then
  if [ ! -s "$LAST_LISTING" ]; then
    echo "No saved listing yet. Run ./neptune.sh first; the numbers come from its output." >&2
    exit 64
  fi
  RUN_OF=$(head -1 "$LAST_LISTING" | sed 's/^# //')
  AVAIL=$(grep -vc '^#' "$LAST_LISTING" || true)
  PICKED=""; BAD=""
  for N in $(printf '%s' "$ACK_ARG" | tr ',' ' '); do
    LINE=$(awk -F'\t' -v n="$N" '$1 == n' "$LAST_LISTING")
    if [ -n "$LINE" ]; then PICKED="$PICKED$LINE
"; else BAD="$BAD $N"; fi
  done
  if [ -n "$BAD" ]; then
    echo "No finding numbered:$BAD in your last listing (1-${AVAIL} available, from the $RUN_OF)." >&2
    exit 64
  fi
  echo "From the $RUN_OF:"
  printf '%s' "$PICKED" | awk -F'\t' '{printf "   %2d. [%s] %s\n", $1, $3, $5}'
  echo
  read -r -p "Acknowledge these as known-good on this machine? [y/N] " REPLY
  case "$REPLY" in [yY]|[yY][eE][sS]) ;; *) echo "Nothing changed."; exit 0 ;; esac
  mkdir -p "$NEPTUNE_HOME"
  printf '%s' "$PICKED" | awk -F'\t' 'NF >= 4 {print $4}' >> "$ALLOW"
  echo
  echo "Recorded in $ALLOW. These stay listed and counted on every run — they"
  echo "just stop deducting from the score. Delete a line to un-acknowledge."
  exit 0
fi

TMP=$(mktemp -d "${TMPDIR:-/tmp}/neptune.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
FINDINGS="$TMP/findings.txt"
: > "$FINDINGS"

# render <json|html> <outfile> — the one renderer behind both formats.
render() {
  local FMT=$1 OUTF=$2 SAN
  SAN=$($SANITIZE_OUT && echo --sanitize || true)
  PYTHONUTF8=1 python3 "$RENDERER" --format "$FMT" $SAN \
    --scored "$SCORED" --scores "$SCORES" --listing "$LISTING" \
    --verdict-key "$VKEY" --verdict "$VERDICT" \
    --integrity "$INTEGRITY" --integrity-why "$WHY" \
    --quirks "$QUIRKS" --version "$VERSION_STRING" \
    ${RENDER_HISTORY:+--history "$RENDER_HISTORY"} \
    ${RENDER_SEEN:+--seen "$RENDER_SEEN"} \
    ${RENDER_REPLAY:+--replay-source "$RENDER_REPLAY"} > "$OUTF"
}

############################################################################
# --replay: re-render saved results. Reads nothing from the machine, writes no
# state, needs no privileges — safe to run anywhere, including CI and a laptop
# you are showing someone.
############################################################################
if [ -n "$REPLAY" ]; then
  [ -r "$REPLAY" ] || { echo "Cannot read $REPLAY" >&2; exit 64; }
  OUT_DIR="${OUT_DIR:-.}"
  mkdir -p "$OUT_DIR" || exit 64
  RALLOW="$TMP/allow"; : > "$RALLOW"
  case "$REPLAY" in
    *.json) PYTHONUTF8=1 python3 "$RENDERER" --json-to-records "$REPLAY" \
              --records-out "$FINDINGS" --allow-out "$RALLOW" || exit 64 ;;
    *)      cp "$REPLAY" "$FINDINGS" ;;
  esac
  nep_run_pipeline "$FINDINGS" "$RALLOW" "$TMP" "replay of $(basename "$REPLAY")"
  RENDER_REPLAY="$(basename "$REPLAY")"
  echo
  echo "${BOLD}${VCOL}${VERDICT}${RST}   (replayed from $(basename "$REPLAY") — nothing was scanned)"
  render_verdict "$SCORED" "$SCORES" "$LISTING" "$INTEGRITY" "$WHY" | tail -n +4
  if $HTML_OUT; then render html "$OUT_DIR/neptune_report_replay.html" && echo "HTML report: $OUT_DIR/neptune_report_replay.html"; fi
  if $JSON_OUT; then render json "$OUT_DIR/neptune_findings_replay.json" && echo "JSON: $OUT_DIR/neptune_findings_replay.json"; fi
  exit "$(nep_exit_status)"
fi

############################################################################
# Full run
############################################################################
if [ "$(id -u)" -eq 0 ]; then
  echo "Run as your normal user, not with sudo — Neptune asks for it once itself." >&2
  exit 64
fi

OUT_DIR="${OUT_DIR:-$HOME/Desktop}"
mkdir -p "$OUT_DIR" "$NEPTUNE_HOME" || exit 64
[ -f "$ALLOW" ] || : > "$ALLOW"
REPORT="$OUT_DIR/neptune_full_report_${STAMP}.txt"
JSON_PATH="$OUT_DIR/neptune_findings_${STAMP}.json"
HTML_PATH="$OUT_DIR/neptune_report_${STAMP}.html"

echo "${BOLD}Neptune $VERSION_STRING — $(hostname) — $(date '+%Y-%m-%d %H:%M')${RST}"
echo "Combined report will be saved to:"
echo "  $REPORT"
echo

# One sudo prompt up front; the scans reuse the cached timestamp. If it is
# refused, nothing was scanned — say so with its own exit code rather than 1,
# which means "findings need attention".
if ! sudo -v; then
  echo "Could not obtain administrator privileges; nothing was scanned." >&2
  exit 77
fi
# Keep-alive for the cached sudo credential. Its output is detached: the loop's
# `sleep` outlives a kill of the loop by up to 50 s, and while it holds this
# script's stdout, `neptune.sh`'s `| tee` waits for it (found in review).
( while true; do sudo -n true 2>/dev/null; sleep 50; done ) >/dev/null 2>&1 </dev/null & KA=$!
trap 'kill $KA 2>/dev/null; rm -rf "$TMP"' EXIT

# Scans append records here. NEPTUNE_SUITE tells them they are running together,
# so a check two scans both know how to do (double NAT, the persistence listing)
# is done once, by the scan that owns it — one problem, one finding.
export NEPTUNE_FINDINGS="$FINDINGS"
export NEPTUNE_SUITE=1
# Scans that save their own report (redflag) put it beside this one, so --out
# means every file lands in one place rather than half of them on the Desktop.
export NEPTUNE_REPORT_DIR="$OUT_DIR"

strip_ansi() { sed -E $'s/\x1b\\[[0-9;]*[a-zA-Z]//g; s/\x1b\\(B//g'; }

: > "$REPORT"
{
  echo "NEPTUNE FULL REPORT"
  echo "Host:    $(hostname)"
  echo "macOS:   $(sw_vers -productVersion 2>/dev/null) ($(sw_vers -buildVersion 2>/dev/null))"
  echo "Date:    $(date '+%Y-%m-%d %H:%M')"
  echo "Neptune: $VERSION_STRING"
} >> "$REPORT"
HEADER_LINES=5

# run_script <file> <scan-id> <category> <label>
#
# Fails closed at the orchestration level too. A scan that is missing, exits
# non-zero, or finishes having recorded nothing at all becomes an `unknown`
# finding — its checks are not in the report, and the verdict must not read as
# if they had passed. The old runner printed "(skipping ...)" and carried on,
# and a crashed scan simply contributed nothing, which scored as clean.
run_script() {
  local NAME=$1 ID=$2 CAT=$3 LABEL=$4 RC BEFORE AFTER
  if [ ! -x "$DIR/$NAME" ]; then
    echo "  ${YEL}(not run: $NAME is missing or not executable)${RST}"
    printf 'unknown|%s|neptune|scan-missing|%s did not run (missing or not executable), so none of its checks are in this report\n' \
      "$CAT" "$NAME" >> "$FINDINGS"
    return
  fi
  echo "${BOLD}${CYN}>>> Running $LABEL...${RST}"
  BEFORE=$(awk -F'|' -v s="$ID" '$3==s' "$FINDINGS" | wc -l | tr -d ' ')
  "$DIR/$NAME" 2>&1 | tee "$TMP/$NAME.raw"
  RC=${PIPESTATUS[0]}
  AFTER=$(awk -F'|' -v s="$ID" '$3==s' "$FINDINGS" | wc -l | tr -d ' ')
  if [ "$RC" -ne 0 ]; then
    printf 'unknown|%s|neptune|scan-failed|%s stopped with exit status %s before finishing, so some of its checks are missing from this report\n' \
      "$CAT" "$NAME" "$RC" >> "$FINDINGS"
  elif [ "$AFTER" -eq "$BEFORE" ]; then
    printf 'unknown|%s|neptune|scan-silent|%s finished but recorded no results at all, so its checks cannot be counted as passed\n' \
      "$CAT" "$NAME" >> "$FINDINGS"
  fi
  strip_ansi < "$TMP/$NAME.raw" > "$TMP/$NAME.txt"
  {
    echo
    echo "################################################################"
    echo "##  $LABEL — $(date '+%H:%M')"
    echo "################################################################"
    cat "$TMP/$NAME.txt"
  } >> "$REPORT"
  echo
}

run_script sentry.sh        sentry  security    "SENTRY (change detection, process->network, staleness)"
run_script redflag_scan.sh  redflag security    "RED-FLAG SCAN (posture, persistence, processes, listeners, interception)"
run_script network_check.sh network network     "NETWORK CHECK (NAT, DNS, latency, connections)"
run_script audit_system.sh  audit   bloat       "SYSTEM AUDIT (resources, extensions, disk and bloat)"
run_script check_updates.sh updates maintenance "UPDATE SCAN (macOS, brew, App Store, self-updaters)"

nep_run_pipeline "$FINDINGS" "$ALLOW" "$TMP" "$RUN_LABEL"

# Text report: header, verdict, then every scan's full output.
{
  head -"$HEADER_LINES" "$REPORT"
  echo
  render_verdict "$SCORED" "$SCORES" "$LISTING" "$INTEGRITY" "$WHY"
  tail -n +"$((HEADER_LINES + 1))" "$REPORT"
} > "$TMP/final.txt" && mv "$TMP/final.txt" "$REPORT"

# State, then the optional outputs. seen.tsv is updated first so the report
# can say how many runs INCLUDING this one have seen a finding; history.tsv is
# appended last so the renderer's "previous run" really is the previous one.
cp "$LISTING" "$LAST_LISTING"
nep_update_seen "$SCORED" "$SEEN" "$(date '+%Y-%m-%d')"
RENDER_SEEN="$SEEN"; RENDER_HISTORY="$HISTORY"
if $JSON_OUT; then render json "$JSON_PATH"; fi
if $HTML_OUT; then render html "$HTML_PATH"; fi
nep_append_history "$HISTORY" "$SCORES" "$(date '+%Y-%m-%d %H:%M')" "$VKEY"

echo
echo "${BOLD}${VCOL}${VERDICT}${RST}"
render_verdict "$SCORED" "$SCORES" "$LISTING" "$INTEGRITY" "$WHY" | tail -n +4
echo
echo "${BOLD}Full report:${RST} $REPORT"
$HTML_OUT && echo "${BOLD}HTML report:${RST} $HTML_PATH$($SANITIZE_OUT && echo '   (sanitized)')"
$JSON_OUT && echo "${BOLD}JSON findings:${RST} $JSON_PATH$($SANITIZE_OUT && echo '   (sanitized)')"
if ! $HTML_OUT; then
  echo
  echo "For a readable report with what each finding means and what to do:"
  echo "  ./neptune.sh --html"
fi

exit "$(nep_exit_status)"
