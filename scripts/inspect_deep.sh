# inspect_deep.sh — optional deep inspection of the files Neptune already flagged.
#
# Sourced by redflag_scan.sh (and by tests via NEPTUNE_LIB=1); defines functions
# only and runs nothing at source time.
#
# The premise (see claude/PR-6-optional-enrichment.md): when `yara` or `clamscan`
# is installed, scan ONLY the handful of files already flagged this run — never a
# whole-disk sweep — and let a signature *hit* become a real, scored finding. A
# clean result and an absent tool are reported as information: honest, and costing
# no points. The base scan stays zero-dependency and network-silent; the one
# network touch (updating rules and signatures) lives in deep_update_rules, runs
# only when the user types --update-rules, and is grepped for by a test so nothing
# else can reach the network.
#
# Everything above the NEPTUNE_LIB guard is a pure function (it may run an external
# tool, but has no effect on Neptune's state), so the unit tests source this file
# and call the helpers against stubs pointed to by DEEP_YARA / DEEP_CLAMSCAN.

export LC_ALL=C

# deep_rules_dir — where YARA rules live. One `rm -rf` removes everything Neptune
# ever fetched. Honours NEPTUNE_HOME so tests can point it at a sandbox.
deep_rules_dir() { echo "${NEPTUNE_HOME:-$HOME/.neptune}/yara"; }

# deep_yara_rules — the first YARA rules file under the rules dir, or "" if none.
# YARA with no rules does nothing, so "yara is installed" is not the same as
# "yara can tell us anything": the rules have to be there too.
deep_yara_rules() {
  local d f
  d=$(deep_rules_dir)
  [ -d "$d" ] || return 0
  for f in "$d"/neptune.yar "$d"/neptune.yara "$d"/*.yar "$d"/*.yara; do
    [ -f "$f" ] && { echo "$f"; return 0; }
  done
  return 0
}

# deep_tool <name> — the path to a tool that actually RUNS, or "" (same spirit as
# find_python.sh: present on PATH is not the same as runnable). Honours an
# override so a test can point at a stub: DEEP_<NAME>, e.g. DEEP_YARA, DEEP_CLAMSCAN.
deep_tool() {
  local up ovr p
  up=$(printf '%s' "$1" | tr 'a-z' 'A-Z')
  eval "ovr=\${DEEP_$up:-}"
  if [ -n "$ovr" ]; then
    [ -x "$ovr" ] && echo "$ovr"
    return 0
  fi
  p=$(command -v "$1" 2>/dev/null) || return 0
  "$p" --version >/dev/null 2>&1 && echo "$p"
  return 0
}

# deep_label <name> — the human name for a tool.
deep_label() {
  case "$1" in
    yara)     echo "YARA" ;;
    clamscan) echo "ClamAV" ;;
    *)        echo "$1" ;;
  esac
}

# deep_enrichers — the enrichers usable on this machine right now, one per line.
# yara counts only when it runs AND has rules; clamscan ships its own signatures.
deep_enrichers() {
  local p
  p=$(deep_tool yara)
  [ -n "$p" ] && [ -n "$(deep_yara_rules)" ] && echo yara
  p=$(deep_tool clamscan)
  [ -n "$p" ] && echo clamscan
}

# deep_tools_present — the enricher tools that are INSTALLED, ignoring whether
# they have rules yet, one per line. Used only to word the "go deeper" hint, so
# an installed-but-ruleless yara prints "run --update-rules" rather than vanishing.
deep_tools_present() {
  [ -n "$(deep_tool yara)" ]     && echo yara
  [ -n "$(deep_tool clamscan)" ] && echo clamscan
}

# deep_classify_yara <exit> <output> — yara exits 0 whether or not it matched;
# a match prints "RULE /path" lines, a clean file prints nothing. A non-zero exit
# is a real error (bad rules, unreadable file). Prints: hit:<RULE> | clean | err
deep_classify_yara() {
  if [ "$1" -ne 0 ]; then echo err; return; fi
  if [ -n "$2" ]; then
    echo "hit:$(printf '%s\n' "$2" | awk 'NR==1{print $1; exit}')"
  else
    echo clean
  fi
}

# deep_classify_clam <exit> <output> — clamscan: 0 clean, 1 infected, else error.
# An infected line ends with " FOUND" and names the signature before it. Prints:
# hit:<SIGNATURE> | clean | err
deep_classify_clam() {
  case "$1" in
    0) echo clean ;;
    1) echo "hit:$(printf '%s\n' "$2" | awk '/ FOUND$/{sub(/ FOUND$/,""); n=split($0,a,": "); print a[n]; exit}')" ;;
    *) echo err ;;
  esac
}

# deep_scan_file <name> <toolpath> <file> [rules] — run one enricher against one
# file and print its verdict: hit:<name> | clean | err | absent. No side effects,
# no records; the caller decides what a verdict means for the report and score.
deep_scan_file() {
  local name=$1 tool=$2 file=$3 rules=${4:-} out rc
  [ -n "$tool" ] || { echo absent; return; }
  [ -f "$file" ] || { echo absent; return; }
  case "$name" in
    yara)
      [ -n "$rules" ] || { echo absent; return; }
      out=$("$tool" "$rules" "$file" 2>/dev/null); rc=$?
      deep_classify_yara "$rc" "$out"
      ;;
    clamscan)
      out=$("$tool" --no-summary "$file" 2>/dev/null); rc=$?
      deep_classify_clam "$rc" "$out"
      ;;
    *) echo absent ;;
  esac
}

# deep_update_rules — the SINGLE place in Neptune that reaches the network, and
# only when the user types --update-rules. It is loud about it: it names every
# source before touching it. ClamAV's own freshclam updates its signatures (the
# standard, trusted path). For YARA, Neptune does not pick a third-party ruleset
# for you — baking an unverified external source into a security tool is the very
# thing this tool warns about — so it fetches only a source you name in
# NEPTUNE_YARA_URL, verifies it against NEPTUNE_YARA_SHA256 when you set one, and
# otherwise tells you how to point it at a ruleset you trust.
#
# Returns 0 if at least one update path ran, 1 if there was nothing to do.
deep_update_rules() {
  local did=1 dir url sum tmp got
  echo "Updating rules and signatures. This is the only part of Neptune that"
  echo "reaches the network; everything else is local and read-only."
  echo

  # ClamAV signatures via its own updater.
  if [ -n "$(deep_tool clamscan)" ]; then
    if command -v freshclam >/dev/null 2>&1; then
      echo "ClamAV: freshclam (official ClamAV signature servers)"
      freshclam || echo "  freshclam reported a problem; signatures may be unchanged."
      did=0
    else
      echo "ClamAV is installed but freshclam is not on PATH; skipping signature update."
    fi
    echo
  fi

  # YARA rules only from a source you chose.
  dir=$(deep_rules_dir)
  url=${NEPTUNE_YARA_URL:-}
  sum=${NEPTUNE_YARA_SHA256:-}
  if [ -n "$url" ]; then
    mkdir -p "$dir" || return 1
    echo "YARA rules: $url"
    [ -n "$sum" ] && echo "  expecting sha256 $sum"
    tmp="$dir/.neptune.yar.part"
    if curl -fsSL "$url" -o "$tmp"; then
      if [ -n "$sum" ]; then
        got=$(shasum -a 256 "$tmp" 2>/dev/null | awk '{print $1}')
        if [ "$got" != "$sum" ]; then
          echo "  checksum mismatch (got ${got:-none}); not installing." >&2
          rm -f "$tmp"
          return 1
        fi
      fi
      mv "$tmp" "$dir/neptune.yar"
      echo "  saved to $dir/neptune.yar"
      did=0
    else
      echo "  download failed; rules unchanged." >&2
      rm -f "$tmp"
    fi
  else
    echo "YARA rules: no source set. Neptune will not choose a third-party ruleset"
    echo "for you. Point it at one you trust, pinned to a commit, e.g.:"
    echo "  NEPTUNE_YARA_URL=https://.../rules.yar \\"
    echo "  NEPTUNE_YARA_SHA256=<sha256> ./neptune.sh --inspect --update-rules"
    echo "Rules live in $dir; remove them with: rm -rf $dir"
  fi
  return $did
}

[ "${NEPTUNE_LIB:-}" = "1" ] && return 0
