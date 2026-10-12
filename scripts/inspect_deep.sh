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

# deep_clam_ready <toolpath> — true when clamscan has a signature database
# loaded. A fresh `brew install clamav` has none: `clamscan --version` then
# prints just "ClamAV 1.4.1", and every scan exits 2 with "No supported
# database files found". With signatures it prints "ClamAV 1.4.1/27411/<date>".
# Installed-without-signatures is "not ready", never "could not inspect" — the
# file isn't the problem, the tool is.
deep_clam_ready() {
  "$1" --version 2>/dev/null | grep -q '^ClamAV [^/]*/[0-9]'
}

# deep_enrichers — the enrichers usable on this machine right now, one per line.
# yara counts only when it runs AND has rules; clamscan only with signatures.
deep_enrichers() {
  local p
  p=$(deep_tool yara)
  [ -n "$p" ] && [ -n "$(deep_yara_rules)" ] && echo yara
  p=$(deep_tool clamscan)
  [ -n "$p" ] && deep_clam_ready "$p" && echo clamscan
  return 0
}

# deep_tools_present — the enricher tools that are INSTALLED, ignoring whether
# they have rules yet, one per line. Used only to word the "go deeper" hint, so
# an installed-but-ruleless yara prints "run --update-rules" rather than vanishing.
deep_tools_present() {
  [ -n "$(deep_tool yara)" ]     && echo yara
  [ -n "$(deep_tool clamscan)" ] && echo clamscan
  return 0
}

# deep_next_step — what to do when no enricher is ready, as plain lines. One
# wording for the scan, --inspect and the report. Neptune prints the command;
# it never installs or downloads anything on its own.
deep_next_step() {
  local have
  have=$(deep_tools_present)
  if printf '%s\n' "$have" | grep -qx clamscan; then
    echo "ClamAV is installed but has no signatures yet. Download them (this step uses"
    echo "the internet; the check itself doesn't), then the flagged files are checked:"
    echo "  ./neptune.sh --inspect --update-rules"
  elif printf '%s\n' "$have" | grep -qx yara; then
    echo "YARA is installed but has no rules yet. Point it at a ruleset you trust:"
    echo "  NEPTUNE_YARA_URL=<url> ./neptune.sh --inspect --update-rules"
  else
    echo "No malware scanner is installed. To check the flagged files against known-malware"
    echo "signatures (Neptune installs and downloads nothing on its own):"
    echo "  brew install clamav   then  ./neptune.sh --inspect --update-rules"
    echo "  (YARA works too: brew install yara, with rules you choose in NEPTUNE_YARA_URL)"
  fi
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

# deep_clam_batch <toolpath> <file>... — ONE clamscan run over every file, then
# one verdict per file in input order: "<file><TAB>hit:<SIG>|clean|err|absent".
#
# One run, because each run loads the whole signature set (seconds to tens of
# seconds on a Mac); once per file would multiply that. clamscan prints one line
# per file — "<file>: OK", "<file>: <Sig> FOUND", or "<file>: <reason>" (Access
# denied, No such file) — and exits 1 whenever anything matched, even beside
# errors, so the lines decide, not the exit code. A file with no line at all is
# an error, never clean. No signatures loaded ("No supported database files")
# means the tool is not ready: every file is "absent", not charged as an error.
# Paths are matched with index(), not a regex, so spaces and dots are literal;
# the signature is cut after "<file>: ", an ASCII boundary, so substr() can
# never split a multibyte character.
deep_clam_batch() {
  local tool=$1 out list
  shift
  [ $# -gt 0 ] || return 0
  out=$("$tool" --no-summary "$@" 2>&1)
  list=$(printf '%s\n' "$@")
  if printf '%s\n' "$out" | grep -q 'No supported database files'; then
    printf '%s\n' "$list" | awk '{print $0 "\tabsent"}'
    return 0
  fi
  printf '%s\n' "$out" | LIST="$list" awk '
    BEGIN { n = split(ENVIRON["LIST"], f, "\n") }
    {
      bi = 0; bl = 0
      for (i = 1; i <= n; i++) {
        p = f[i] ": "
        if (index($0, p) == 1 && length(p) > bl) { bl = length(p); bi = i }
      }
      if (!bi) next
      rest = substr($0, bl + 1)
      if (rest == "OK") r = "clean"
      else if (rest ~ / FOUND$/) { sub(/ FOUND$/, "", rest); r = "hit:" rest }
      else r = "err"
      if (v[bi] == "" || r ~ /^hit:/) v[bi] = r
    }
    END { for (i = 1; i <= n; i++) print f[i] "\t" (v[i] == "" ? "err" : v[i]) }'
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
      deep_clam_batch "$tool" "$file" | awk -F'\t' 'NR == 1 {print $2}'
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
  local did=1 dir url sum tmp got fc conf yp
  echo "Updating signatures. This step downloads from the internet; the signature"
  echo "check itself downloads nothing, and nothing here installs software."
  echo

  if [ -z "$(deep_tools_present)" ] && [ -z "${NEPTUNE_YARA_URL:-}" ]; then
    deep_next_step
    return 1
  fi

  # ClamAV signatures via its own updater.
  if [ -n "$(deep_tool clamscan)" ]; then
    fc=$(command -v freshclam 2>/dev/null || true)
    # Homebrew's ClamAV ships only freshclam.conf.sample, and freshclam refuses
    # to run without the real file. Writing a third-party tool's config is a
    # change outside ~/.neptune, so Neptune shows the two commands, not runs them.
    conf=""
    [ -n "$fc" ] && conf="$(dirname "$(dirname "$fc")")/etc/clamav/freshclam.conf"
    if [ -n "$conf" ] && [ ! -f "$conf" ] && [ -f "$conf.sample" ]; then
      echo "ClamAV: its updater needs a config file first (Homebrew ships only a"
      echo "sample). Create it, then run this again:"
      echo "  cp \"$conf.sample\" \"$conf\""
      echo "  sed -i '' 's/^Example/#Example/' \"$conf\""
    elif [ -n "$fc" ]; then
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
    # Detection rules decide what gets called malware, so they come over HTTPS
    # only — including every redirect (--proto) — or not at all.
    case "$url" in
      https://*) ;;
      *) echo "YARA rules: $url is not an https:// address; not downloading." >&2
         return 1 ;;
    esac
    mkdir -p "$dir" || return 1
    echo "YARA rules: $url"
    if [ -n "$sum" ]; then
      echo "  expecting sha256 $sum"
    else
      echo "  not pinned: set NEPTUNE_YARA_SHA256 to refuse anything but that exact file"
    fi
    tmp="$dir/.neptune.yar.part"
    if curl --proto '=https' --tlsv1.2 -fsSL "$url" -o "$tmp"; then
      if [ -n "$sum" ]; then
        got=$(shasum -a 256 "$tmp" 2>/dev/null | awk '{print $1}')
        if [ "$got" != "$sum" ]; then
          echo "  checksum mismatch (got ${got:-none}); not installing." >&2
          rm -f "$tmp"
          return 1
        fi
      fi
      # Rules that do not compile would make every check fail; keep the old ones.
      # Probed against a one-byte regular file rather than /dev/null, which a
      # YARA build may refuse to map.
      yp=$(deep_tool yara)
      if [ -n "$yp" ]; then
        printf x > "$dir/.probe"
        if ! "$yp" "$tmp" "$dir/.probe" >/dev/null 2>&1; then
          echo "  these rules do not compile with your YARA; not installing (rules unchanged)." >&2
          rm -f "$tmp" "$dir/.probe"
          return 1
        fi
        rm -f "$dir/.probe"
      fi
      mv "$tmp" "$dir/neptune.yar"
      echo "  saved to $dir/neptune.yar"
      did=0
    else
      echo "  download failed; rules unchanged." >&2
      rm -f "$tmp"
    fi
  elif [ -n "$(deep_tool yara)" ] || [ -z "$(deep_tool clamscan)" ]; then
    # Only when YARA is here to use the rules, or nothing is set up at all; a
    # ClamAV-only Mac does not need a paragraph about YARA on every update.
    echo "YARA rules: no source set. Neptune will not choose a third-party ruleset"
    echo "for you. Point it at one you trust, pinned to a commit, e.g.:"
    echo "  NEPTUNE_YARA_URL=https://.../rules.yar \\"
    echo "  NEPTUNE_YARA_SHA256=<sha256> ./neptune.sh --inspect --update-rules"
    echo "Rules live in $dir; remove them with: rm -rf $dir"
  fi
  return $did
}

[ "${NEPTUNE_LIB:-}" = "1" ] && return 0
