#!/usr/bin/env python3
"""test_render.py — tests for the renderer, its remediation table, and the
end-to-end --replay path.

Standard library only (unittest), so it runs on the macOS CI runner's python
and on a laptop with nothing installed but the Command Line Tools.

    python3 tests/test_render.py        (or: python3 -m unittest -v tests/test_render.py)

It imports scripts/neptune_render.py directly. The test this replaces used to
extract the remediation table from between two marker comments in a shell
script and exec() it — a test that depended on a comment staying put.
"""

import ast
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(REPO, "scripts")
FIXTURES = os.path.join(REPO, "tests", "fixtures")
sys.path.insert(0, SCRIPTS)

import neptune_render as R  # noqa: E402  (path set up above)

FIXTURE_V2 = os.path.join(FIXTURES, "findings-2026-09-18.txt")
FIXTURE_V1 = os.path.join(FIXTURES, "findings-realworld.txt")


def check_ids_in_scans():
    """Every CHECK=<id> assigned anywhere in the scans, plus the run-level ids
    neptune.sh records itself. Read from the source, so a new check cannot be
    added without this test seeing it."""
    ids = set()
    for path in glob.glob(os.path.join(SCRIPTS, "*.sh")):
        with open(path, encoding="utf-8", errors="replace") as fh:
            src = fh.read()
        ids.update(re.findall(r"\bCHECK=([a-z0-9-]+)", src))
        ids.update(re.findall(r"\|neptune\|([a-z-]+)\|", src))
    return ids


def remediation_ids():
    return {i for entry in R.REMEDIATION for i in entry[0]}


def run(cmd, **kw):
    env = dict(os.environ, LC_ALL="C", PYTHONUTF8="1")
    env.update(kw.pop("env", {}))
    return subprocess.run(cmd, cwd=REPO, env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, universal_newlines=True, **kw)


class RemediationTable(unittest.TestCase):

    def test_every_check_id_has_advice(self):
        missing = sorted(check_ids_in_scans() - remediation_ids())
        self.assertEqual(missing, [], "check ids with no remediation entry")

    def test_no_orphan_advice(self):
        """An entry for an id no scan records is dead text — usually a check that
        was renamed without its advice."""
        base = {i.split(":")[0] for i in remediation_ids()}
        orphans = sorted(base - check_ids_in_scans())
        self.assertEqual(orphans, [])

    def test_the_check_id_scan_sees_something(self):
        # Guards the guard: if the regex above stopped matching, both tests
        # above would pass vacuously.
        self.assertGreater(len(check_ids_in_scans()), 40)

    def test_commands_are_single_commands_with_a_kind(self):
        self.assertEqual(R.remediation_command_problems(), [])

    def test_neptune_commands_name_real_scripts_and_flags(self):
        """A through-line check: every ./script the table tells someone to run
        exists, is executable, and accepts the flags it is given."""
        sample = ("UNSIGNED persistence: com.example.thing runs /Applications/Foo.app/"
                  "Contents/MacOS/foo (/Library/LaunchDaemons/com.example.thing.plist)")
        seen = 0
        for _ids, _pat, _means, _do, cmdf in R.REMEDIATION:
            for command, kind, _effect in cmdf(sample):
                if not command.startswith("./"):
                    continue
                seen += 1
                self.assertEqual(kind, "neptune", command)
                script = command.split()[0][2:]
                path = os.path.join(SCRIPTS, script)
                self.assertTrue(os.access(path, os.X_OK), "%s is not an executable script" % script)
                with open(path, encoding="utf-8") as fh:
                    src = fh.read()
                for flag in re.findall(r"(?<=\s)--[a-z-]+", command):
                    self.assertIn(flag, src, "%s does not know %s" % (script, flag))
        self.assertGreater(seen, 2)

    def test_every_real_finding_gets_advice(self):
        for fixture in (FIXTURE_V2, FIXTURE_V1):
            with open(fixture, encoding="utf-8") as fh:
                for line in fh:
                    f = line.rstrip("\n").split("|")
                    if len(f) == 5:
                        sev, check, title = f[0], f[3], f[4]
                    elif len(f) == 4:
                        sev, check, title = f[0], "", f[3]
                    else:
                        continue
                    if sev in ("pass",):
                        continue
                    advice = R.advise(check, title, sev)
                    self.assertFalse(advice.get("unmapped"), "no advice for: %s" % title)
                    self.assertTrue(advice["means"] and advice["do"], title)

    def test_an_unknown_is_not_advised_as_a_failure(self):
        fail = R.advise("filevault", "FileVault is OFF", "attention")
        unk = R.advise("filevault", "FileVault status could not be read", "unknown")
        self.assertNotEqual(fail["means"], unk["means"])
        self.assertIn("could not", unk["means"])
        # ...except where the check's own entry is about the unknown state.
        own = R.advise("persistence-unresolved", "x could not resolve its target", "unknown")
        self.assertIn("could not read", own["means"])

    def test_severity_specific_advice_wins(self):
        created = R.advise("baseline-diff", "Baseline created: 40 items", "info")
        changed = R.advise("baseline-diff", "NEW since baseline: helper:x", "attention")
        self.assertNotEqual(created["means"], changed["means"])

    def test_unmapped_is_explicit_not_blank(self):
        a = R.advise("", "A finding shape Neptune has never emitted", "attention")
        self.assertTrue(a.get("unmapped"))

    def test_codesign_targets_the_binary_not_the_plist(self):
        t = ("AD-HOC SIGNED persistence: homebrew.mxcl.redis runs /opt/homebrew/opt/redis/bin/"
             "redis-server (/Users/x/Library/LaunchAgents/homebrew.mxcl.redis.plist)")
        cmds = [c["command"] for c in R.advise("persistence-launchd", t, "attention")["commands"]]
        self.assertIn("codesign -dvv /opt/homebrew/opt/redis/bin/redis-server", cmds)

    def test_paths_with_spaces_are_quoted(self):
        t = ("Listener with unverifiable signature: WavesLoca (pid 4500) on 127.0.0.1:6985 "
             "[localhost-only] binary:/Library/Application Support/Waves/WavesLocalServer")
        cmds = [c["command"] for c in R.advise("listeners", t, "attention")["commands"]]
        self.assertIn("codesign -dvv '/Library/Application Support/Waves/WavesLocalServer'", cmds)


class Sanitizer(unittest.TestCase):

    def test_strips_identity(self):
        clean = R.make_sanitizer(True, host="Titos-Mac-Studio.local", user="tito")
        text = ("Titos-Mac-Studio.local /Users/tito/x /Users/other/y 192.168.1.20 "
                "3c:7c:3f:1a:2b:cc 8:0:27:a:b:c Titos-Mac-Studio")
        out = clean(text)
        # The private-range prefix stays (every home network has it); the host part goes.
        for leaked in ("Titos", "tito", "other", "1.20", "3c:7c", "8:0:27"):
            self.assertNotIn(leaked, out)
        self.assertIn("/Users/exampleuser/x", out)

    def test_keeps_what_an_address_means(self):
        clean = R.make_sanitizer(True, "", "")
        self.assertEqual(clean("127.0.0.1:6985 and 0.0.0.0:5000"), "127.0.0.1:6985 and 0.0.0.0:5000")
        self.assertEqual(clean("router 192.168.1.254 then 10.0.0.1 then 8.8.4.4"),
                         "router 192.168.x.x then 10.x.x.x then x.x.x.x")
        self.assertEqual(clean("/Users/Shared/x /Users/tito/y"), "/Users/Shared/x /Users/exampleuser/y")

    def test_disabled_is_identity(self):
        self.assertEqual(R.make_sanitizer(False, "h", "u")("h u 10.0.0.1"), "h u 10.0.0.1")


class PythonFloor(unittest.TestCase):

    def test_parses_as_python_3_6(self):
        """The stated floor is 3.6. subprocess.run(capture_output=...) is 3.7+
        and walrus is 3.8+; parsing with feature_version catches the syntax
        half of that, and the grep catches the library half."""
        if sys.version_info < (3, 8):
            self.skipTest("ast feature_version needs python 3.8+ to check")
        for name in ("neptune_render.py", "neptune_inspect.py"):
            path = os.path.join(SCRIPTS, name)
            with open(path, encoding="utf-8") as fh:
                src = fh.read()
            ast.parse(src, filename=name, feature_version=(3, 6))
            self.assertNotIn("capture_output", src.replace("capture_output:", ""))


class ReplayEndToEnd(unittest.TestCase):
    """Runs the real bash pipeline and the real renderer, via --replay."""

    @classmethod
    def setUpClass(cls):
        if not shutil.which("bash"):
            raise unittest.SkipTest("bash not available")
        cls.tmp = tempfile.mkdtemp(prefix="neptune-test-")
        cls.home = os.path.join(cls.tmp, "home")
        os.makedirs(cls.home)
        cls.out = os.path.join(cls.tmp, "out")
        cls.proc = run(["bash", "scripts/neptune.sh", "--replay", FIXTURE_V2,
                        "--html", "--json", "--out", cls.out], env={"HOME": cls.home})
        with open(os.path.join(cls.out, "neptune_findings_replay.json"), encoding="utf-8") as fh:
            cls.report = json.load(fh)
        with open(os.path.join(cls.out, "neptune_report_replay.html"), encoding="utf-8") as fh:
            cls.html = fh.read()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_exit_code_is_attention(self):
        self.assertEqual(self.proc.returncode, 1, self.proc.stdout)

    def test_counts_match_the_fixture(self):
        c = self.report["counts"]
        self.assertEqual((c["pass"], c["attention"], c["notice"], c["info"]), (15, 11, 4, 2))
        self.assertTrue(self.report["integrity"]["ok"])
        self.assertEqual(self.report["neptune"]["schema"], 3)

    def test_replay_writes_no_state(self):
        self.assertEqual(os.listdir(self.home), [], "--replay must not touch ~/.neptune")

    def test_listing_numbers_are_contiguous_and_match_the_terminal(self):
        ns = sorted(f["n"] for f in self.report["findings"] if "n" in f)
        self.assertEqual(ns, list(range(1, len(ns) + 1)))
        for f in self.report["findings"]:
            if "n" in f:
                self.assertIn("%3d  %s" % (f["n"], f["headline"]), self.proc.stdout)

    def test_every_finding_has_plain_words(self):
        for f in self.report["findings"]:
            self.assertTrue(f["headline"], f["title"])
            if f["severity"] != "info":
                self.assertNotEqual(f["headline"], f["title"],
                                    "no phrasebook row turned this into plain words: " + f["title"])

    def test_render_only_keys_never_reach_the_json(self):
        self.assertFalse([k for k in self.report if k.startswith("_")])
        for f in self.report["findings"]:
            self.assertFalse([k for k in f if k.startswith("_")], f["title"])

    def test_python_scores_match_the_awk_scores(self):
        """simulate_scores re-implements nep_compute_scores so the report can
        say what a fix is worth. This is what keeps the two from drifting."""
        recs = [{"severity": f["severity"], "category": f["category"],
                 "acknowledged": f.get("acknowledged", False)}
                for f in self.report["findings"] + self.report["checks_passed"]]
        self.assertEqual(R.simulate_scores(recs), self.report["scores"])

    def test_html_has_the_reading_levels_and_the_queue(self):
        for needle in ('id="lv1"', 'id="lv2"', 'id="lv3"', "Do these next",
                       "Recommended commands", "Get a second opinion",
                       "./neptune.sh --fix --only ", "neptune_ai_brief_replay.md"):
            self.assertIn(needle, self.html, needle)

    def test_the_queue_is_the_do_these_next_order(self):
        m = re.search(r"Queue them, in this order:.*?--only ([0-9,]+)", self.html, re.S)
        self.assertTrue(m)
        queue = [int(n) for n in m.group(1).split(",")]
        self.assertEqual(len(queue), len(set(queue)), "an item is queued twice")
        numbered = {f["n"] for f in self.report["findings"] if "n" in f}
        self.assertTrue(set(queue) <= numbered)

    def test_brief_is_written_sanitized_with_its_prompt(self):
        with open(os.path.join(self.out, "neptune_ai_brief_replay.md"), encoding="utf-8") as fh:
            brief = fh.read()
        self.assertIn("do not give me shell i can't look up", brief.lower())
        self.assertIn("Sanitized", brief)
        for f in self.report["findings"]:
            if "n" in f:
                self.assertIn("### #%d " % f["n"], brief)

    def test_html_makes_no_network_requests_and_runs_no_script(self):
        low = self.html.lower()
        for bad in ("<script", "<link", "@import", "url(", "<img", "<iframe", "src=",
                    "http://", "https://"):
            self.assertNotIn(bad, low, bad)

    def test_html_is_well_formed(self):
        from html.parser import HTMLParser

        class Balance(HTMLParser):
            VOID = {"meta", "br", "hr", "img", "input", "link", "wbr"}

            def __init__(self):
                super().__init__()
                self.stack, self.bad = [], []

            def handle_starttag(self, tag, attrs):
                if tag not in self.VOID:
                    self.stack.append(tag)

            def handle_endtag(self, tag):
                if self.stack and self.stack[-1] == tag:
                    self.stack.pop()
                else:
                    self.bad.append(tag)

        p = Balance()
        p.feed(self.html)
        self.assertEqual((p.bad, p.stack), ([], []), "unbalanced tags")

    def test_html_escapes_titles(self):
        fixture = os.path.join(self.tmp, "hostile.txt")
        with open(fixture, "w", encoding="utf-8") as fh:
            fh.write('attention|security|redflag|persistence-launchd|'
                     'UNSIGNED persistence: <script>alert(1)</script> runs "/tmp/x" & more\n')
        out = os.path.join(self.tmp, "hostile")
        run(["bash", "scripts/neptune.sh", "--replay", fixture, "--html", "--out", out],
            env={"HOME": self.home})
        with open(os.path.join(out, "neptune_report_replay.html"), encoding="utf-8") as fh:
            page = fh.read()
        self.assertNotIn("<script>", page)
        self.assertIn("&lt;script&gt;", page)

    def test_json_replays_to_the_same_result(self):
        """--json output fed back through --replay must reproduce the verdict,
        scores and counts — the round trip that makes a saved report checkable."""
        src = os.path.join(self.out, "neptune_findings_replay.json")
        out2 = os.path.join(self.tmp, "again")
        p = run(["bash", "scripts/neptune.sh", "--replay", src, "--json", "--out", out2],
                env={"HOME": self.home})
        self.assertEqual(p.returncode, self.proc.returncode)
        with open(os.path.join(out2, "neptune_findings_replay.json"), encoding="utf-8") as fh:
            again = json.load(fh)
        for k in ("verdict", "scores", "counts"):
            self.assertEqual(again[k], self.report[k], k)

    def test_sanitized_replay_leaks_nothing(self):
        fixture = os.path.join(self.tmp, "ident.txt")
        with open(fixture, "w", encoding="utf-8") as fh:
            fh.write("attention|network|sentry|double-nat|SECOND PRIVATE ROUTER in path: "
                     "10.0.0.1 (beyond your gateway 192.168.1.1)\n"
                     "notice|security|redflag|etc-hosts|/Users/somebody/hosts edited\n")
        out = os.path.join(self.tmp, "san")
        run(["bash", "scripts/neptune.sh", "--replay", fixture, "--json", "--html",
             "--sanitize", "--out", out], env={"HOME": self.home})
        for name in ("neptune_findings_replay.json", "neptune_report_replay.html",
                     "neptune_ai_brief_replay.md"):
            with open(os.path.join(out, name), encoding="utf-8") as fh:
                body = fh.read()
            for leaked in ("192.168.1.1", "10.0.0.1", "somebody"):
                self.assertNotIn(leaked, body, name)


def load_phrases():
    rows = []
    with open(os.path.join(SCRIPTS, "phrases.tsv"), encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line or line.startswith("#") or not line.strip():
                continue
            rows.append(line.split("\t"))
    return rows


def phrase_py(rows, check, title):
    """A second reading of phrases.tsv, in Python's regex engine. If a row
    only works because of something BWK awk does differently, the two
    readings disagree and the test below says which title."""
    for c, match, suffix, prefix, head, _ctx in rows:
        if c != check or (match != "-" and not re.search(match, title)):
            continue
        v = title
        if suffix != "-":
            v = re.sub(suffix, "", v, count=1)
        if prefix != "-":
            v = re.sub(prefix, "", v, count=1)
        v = v.replace("\\x20", " ")
        return head.replace("{s}", v)
    return title


class Phrasebook(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.rows = load_phrases()

    def test_rows_have_six_columns_and_compile(self):
        for r in self.rows:
            self.assertEqual(len(r), 6, r)
            for rx in r[1:4]:
                if rx != "-":
                    re.compile(rx)

    def test_every_check_id_has_a_row(self):
        have = {r[0] for r in self.rows}
        missing = sorted(check_ids_in_scans() - have - {"connections-view"})
        self.assertEqual(missing, [], "check ids with no plain-words row")

    def test_no_shouting_in_headlines(self):
        for r in self.rows:
            words = re.sub(r"\{s\}", "", r[4]).split()
            self.assertFalse([w for w in words if len(w) > 3 and w.isupper() and w.isalpha()
                              and w not in ("FileVault", "NAT", "DNS", "WAN", "ISP")], r[4])

    def test_new_since_baseline_reads_by_kind(self):
        """The 1 Oct 2026 run on the development Mac printed
        "New since your last snapshot: listener:Code\\x20H:127.0.0.1:ephemeral"."""
        out = tempfile.mkdtemp()
        try:
            fx = os.path.join(out, "f.txt")
            with open(fx, "w", encoding="utf-8") as fh:
                fh.write("notice|security|sentry|baseline-diff|NEW since baseline: app:Audacity 4.app\n"
                         "notice|security|sentry|baseline-diff|NEW since baseline: listener:Code\\x20H:127.0.0.1:ephemeral\n"
                         "attention|security|sentry|baseline-diff|NEW since baseline: listener:1Password:*:7000\n"
                         "attention|security|sentry|baseline-diff|NEW since baseline: launchd:/Library/LaunchAgents/com.x.agent.plist\n"
                         "notice|maintenance|updates|brew-outdated|Homebrew has updates for 1 formula and 2 casks\n")
            run(["bash", "scripts/neptune.sh", "--replay", fx, "--json", "--out", out], env={"HOME": out})
            with open(os.path.join(out, "neptune_findings_replay.json"), encoding="utf-8") as fh:
                found = json.load(fh)["findings"]
        finally:
            shutil.rmtree(out, ignore_errors=True)
        for want in ("Audacity 4 is new since your last snapshot",
                     "Code H started listening for connections",
                     "1Password started listening for connections",
                     "New login item: com.x.agent.plist",
                     "Homebrew has updates for 1 formula and 2 casks"):
            self.assertIn(want, [f["headline"] for f in found])
        for f in found:
            self.assertEqual(f["headline"], phrase_py(self.rows, f["check"], f["title"]))

    def test_awk_and_python_read_every_fixture_the_same(self):
        for fixture in (FIXTURE_V2,):
            out = tempfile.mkdtemp()
            try:
                run(["bash", "scripts/neptune.sh", "--replay", fixture, "--json", "--out", out],
                    env={"HOME": out})
                with open(os.path.join(out, "neptune_findings_replay.json"), encoding="utf-8") as fh:
                    rep = json.load(fh)
            finally:
                shutil.rmtree(out, ignore_errors=True)
            for f in rep["findings"]:
                self.assertEqual(f["headline"], phrase_py(self.rows, f["check"], f["title"]), f["title"])


class Ladder(unittest.TestCase):
    """The explanation ladder: every rung exists for every check, and every
    command the report can show has every part of it explained."""

    def test_every_check_has_an_in_short(self):
        for c in check_ids_in_scans():
            means = R.advise(c, "x", "attention").get("means", "")
            self.assertTrue(R.short_for(c, "attention", means), c)

    def test_no_orphan_short_or_undo(self):
        ids = check_ids_in_scans()
        self.assertEqual(sorted(set(R.SHORT) - ids), [])
        self.assertEqual(sorted(set(R.UNDO) - ids), [])

    def test_an_unknown_is_never_explained_as_a_failure(self):
        self.assertEqual(R.short_for("firewall", "unknown", ""), R.UNKNOWN_SHORT)

    def test_every_shown_command_is_explained_part_by_part(self):
        sample = ("UNSIGNED persistence: com.example.thing runs /Applications/Some App.app/Contents/"
                  "MacOS/x (/Library/LaunchDaemons/com.example.thing.plist)")
        commands = [c for entry in R.REMEDIATION for c, _k, _e in entry[4](sample)]
        findings = [{"check": c, "severity": "attention", "acknowledged": False, "n": i + 1,
                     "title": sample, "headline": "h"} for i, c in enumerate(sorted(check_ids_in_scans()))]
        commands += [p["command"] for p in R.playbook({"findings": findings})]
        commands += ["./neptune.sh --fix --only 3,1,2", "./neptune.sh --acknowledge 4"]
        self.assertGreater(len(commands), 40)
        for c in commands:
            self.assertTrue(R.explain_command(c), "no part-by-part explanation for: " + c)

    def test_playbook_commands_are_single_commands(self):
        findings = [{"check": c, "severity": "attention", "acknowledged": False, "n": 1,
                     "title": "/Applications/A.app", "headline": "h"} for c in check_ids_in_scans()]
        for p in R.playbook({"findings": findings}):
            for ch in ("|", ";", "&&", ">", chr(96), "$" + "("):
                self.assertNotIn(ch, p["command"])
            self.assertIn(p["kind"], R.KINDS)

    def test_a_vendor_is_one_next_step(self):
        recs, findings = [], []
        for i, (n, ven) in enumerate(((1, "Waves"), (2, "Waves"), (3, None))):
            recs.append({"severity": "attention", "category": "security", "acknowledged": False})
            f = {"n": n, "severity": "attention", "category": "security", "acknowledged": False,
                 "check": "persistence-launchd", "headline": "h%d" % n, "_i": i}
            if ven:
                f["vendor"] = {"name": ven}
            findings.append(f)
        steps = R.next_steps(recs, findings)
        self.assertEqual(sorted(len(s["numbers"]) for s in steps), [1, 2])
        waves = [s for s in steps if len(s["numbers"]) == 2][0]
        # The marginal worth: three items cost 12+4+4; with Waves' two gone the
        # third costs 12, so keeping Waves is worth 8 — not the 16 a sum of
        # "first item" prices would claim.
        self.assertEqual(waves["gains"], [("Security", 8)])


class JsonToRecords(unittest.TestCase):

    def test_round_trip_escapes_separators(self):
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, "r.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"findings": [{"severity": "notice", "category": "network",
                                         "scan": "x", "check": "dns",
                                         "title": "a|b\tc\nd", "acknowledged": True,
                                         "key": "a/b c d"}],
                           "checks_passed": [{"category": "security", "check": "sip",
                                              "title": "SIP on"}]}, fh)
            records, allow = R.json_to_records(path)
        finally:
            shutil.rmtree(tmp)
        self.assertEqual(records[0], "notice|network|x|dns|a/b c d")
        self.assertEqual(records[1], "pass|security|replay|sip|SIP on")
        self.assertEqual(allow, ["a/b c d"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
