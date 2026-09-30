#!/usr/bin/env python3
"""neptune_inspect.py — the few checks that need a real parser, not grep.

Called by the scans only when python3 is usable (see python_ok in neptune.sh;
on a Mac without the Command Line Tools, /usr/bin/python3 is a stub that pops an
install dialog, so the scans never call it blindly). Standard library only.

    neptune_inspect.py extensions <browser-profile-root>...

Prints one tab-separated line per installed extension:

    <browser>\t<name>\t<id>\t<risky permissions, comma-separated or empty>

"Risky" is deliberately narrow: `proxy` (can reroute every request the browser
makes) and `debugger` (can attach DevTools to any tab and read or change
anything in it). Plenty of legitimate extensions ask for <all_urls>; almost
none need either of these. A wide net here would teach people to ignore it.
"""

import json
import os
import sys

RISKY = ("proxy", "debugger")


def _load_json(path):
    try:
        with open(path, encoding="utf-8-sig", errors="replace") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _resolve_name(manifest, ext_dir):
    """Chrome extensions often name themselves "__MSG_appName__" and put the
    real name in _locales. The old scan skipped every such extension, which is
    most of the popular ones."""
    name = manifest.get("name", "") or ""
    if not (name.startswith("__MSG_") and name.endswith("__")):
        return name
    key = name[6:-2]
    locales = []
    if manifest.get("default_locale"):
        locales.append(manifest["default_locale"])
    locales += ["en", "en_US", "en_GB"]
    for loc in locales:
        messages = _load_json(os.path.join(ext_dir, "_locales", loc, "messages.json"))
        if not isinstance(messages, dict):
            continue
        for k, v in messages.items():
            if k.lower() == key.lower() and isinstance(v, dict) and v.get("message"):
                return v["message"]
    return key


def extensions(roots):
    """Walk <root>/<profile>/Extensions/<id>/<version>/manifest.json.

    That is depth 5 below the browser root. The old scan used `find -maxdepth 4`
    and so could never reach a single manifest — its section of every report was
    a heading with nothing under it (DEVLOG Bug 15)."""
    out = []
    seen = set()
    for root in roots:
        browser = os.path.basename(root.rstrip("/")) or root
        if browser == "User Data":           # Arc keeps profiles one level deeper
            browser = os.path.basename(os.path.dirname(root.rstrip("/")))
        try:
            profiles = sorted(os.listdir(root))
        except OSError:
            continue
        for profile in profiles:
            ext_root = os.path.join(root, profile, "Extensions")
            if not os.path.isdir(ext_root):
                continue
            for ext_id in sorted(os.listdir(ext_root)):
                id_dir = os.path.join(ext_root, ext_id)
                if not os.path.isdir(id_dir):
                    continue
                versions = sorted(v for v in os.listdir(id_dir)
                                  if os.path.isfile(os.path.join(id_dir, v, "manifest.json")))
                if not versions:
                    continue
                ver_dir = os.path.join(id_dir, versions[-1])
                manifest = _load_json(os.path.join(ver_dir, "manifest.json"))
                if not isinstance(manifest, dict):
                    continue
                if (browser, ext_id) in seen:
                    continue
                seen.add((browser, ext_id))
                granted = [p for p in manifest.get("permissions", []) if isinstance(p, str)]
                risky = [p for p in RISKY if p in granted]
                name = _resolve_name(manifest, ver_dir).replace("\t", " ").replace("\n", " ")
                out.append("\t".join([browser, name, ext_id, ",".join(risky)]))
    return out


def main(argv):
    if len(argv) >= 2 and argv[1] == "extensions":
        for line in extensions(argv[2:]):
            print(line)
        return 0
    sys.stderr.write(__doc__)
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv))
