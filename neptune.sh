#!/bin/bash
#
# neptune.sh — the same Neptune, from the top of the repository.
#
# The scripts live in scripts/, and every hint Neptune prints says
# ./neptune.sh. From the top folder that used to fail with "No such file or
# directory" (found on a real run, 2026-10). This hands off to scripts/neptune.sh
# with every argument unchanged, so its exit codes, prompts and refusals (for
# example, it will not run under sudo) are exactly the real script's.
#
# It resolves symlinks first, so a link to this file from anywhere on PATH still
# finds scripts/. It does nothing else.

set -u
export LC_ALL=C

SRC="${BASH_SOURCE[0]:-$0}"
# Follow a symlink chain to the real file (macOS readlink has no -f before 12.3).
while [ -L "$SRC" ]; do
  LINK=$(readlink "$SRC")
  case "$LINK" in
    /*) SRC=$LINK ;;
    *)  SRC="$(dirname "$SRC")/$LINK" ;;
  esac
done
TOP="$(cd "$(dirname "$SRC")" && pwd)"

if [ ! -x "$TOP/scripts/neptune.sh" ]; then
  echo "Can't find Neptune's scripts next to this file ($TOP/scripts/neptune.sh)." >&2
  echo "Run it from the folder you cloned or unpacked, or use scripts/neptune.sh directly." >&2
  exit 64
fi
exec "$TOP/scripts/neptune.sh" "$@"
