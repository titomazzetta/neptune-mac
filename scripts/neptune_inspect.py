#!/usr/bin/env python3
"""neptune_inspect.py — the few checks that need a real parser, not grep.

Called by the scans only when python3 is usable (see python_ok in neptune.sh;
on a Mac without the Command Line Tools, /usr/bin/python3 is a stub that pops an
install dialog, so the scans never call it blindly). Standard library only.

    neptune_inspect.py extensions <browser-profile-root>...
    neptune_inspect.py cask-versions <cask.jws.json> < "App.app<TAB>installed-version" lines

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


def _load_casks(path):
    """Homebrew's local cask catalog (the API cache `brew update` refreshes):
    either a JWS envelope whose payload is a JSON string, or a plain JSON list.
    Reading it costs no network: it is already on disk."""
    data = _load_json(path)
    if isinstance(data, dict) and isinstance(data.get("payload"), str):
        try:
            data = json.loads(data["payload"])
        except ValueError:
            return []
    return data if isinstance(data, list) else []


def _vtuple(v):
    """'3.7.10' -> (3, 7, 10). None when the version has no leading number —
    'latest', build hashes — because then there is nothing honest to compare."""
    v = str(v).split(",")[0].strip()
    parts = []
    for piece in v.replace("-", ".").split("."):
        digits = ""
        for ch in piece:
            if ch.isdigit():
                digits += ch
            else:
                break
        if digits == "":
            break
        parts.append(int(digits))
    return tuple(parts) or None


def cask_versions(catalog, pairs):
    """For each (app bundle name, installed version), find the cask that ships
    that app and compare. Yields app, token, installed, latest, state where
    state is behind | current | unknown."""
    by_app = {}
    for cask in _load_casks(catalog):
        if not isinstance(cask, dict):
            continue
        for art in cask.get("artifacts") or []:
            if isinstance(art, dict) and isinstance(art.get("app"), list):
                for a in art["app"]:
                    if isinstance(a, str) and a.endswith(".app"):
                        by_app.setdefault(a, (cask.get("token", ""), cask.get("version", "")))
    for app, installed in pairs:
        if app not in by_app:
            continue
        token, latest = by_app[app]
        a, b = _vtuple(installed), _vtuple(latest)
        if a is None or b is None:
            state = "unknown"
        else:
            # Compare the parts both have. "7.1.9 (88375)" vs "7.1.9.88375"
            # is the same release written two ways; padding with zeros would
            # call it outdated. A missed update is a smaller error here than a
            # false one, which teaches people to ignore the list.
            n = min(len(a), len(b))
            state = "behind" if a[:n] < b[:n] else "current"
        yield app, token, installed, str(latest).split(",")[0], state


def main(argv):
    if len(argv) >= 2 and argv[1] == "extensions":
        for line in extensions(argv[2:]):
            print(line)
        return 0
    if len(argv) == 3 and argv[1] == "cask-versions":
        pairs = []
        for line in sys.stdin:
            f = line.rstrip("\n").split("\t")
            if len(f) == 2 and f[0]:
                pairs.append((f[0], f[1]))
        for row in cask_versions(argv[2], pairs):
            print("\t".join(row))
        return 0
    sys.stderr.write(__doc__)
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv))
