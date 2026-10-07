#!/usr/bin/env python3
"""test_repo.py — the repository's own configuration, checked like code.

Settings that live only in a web UI drift silently. These live in files, and
these tests keep the files honest:

  * the branch-protection ruleset requires exactly the CI jobs that exist —
    a renamed job would otherwise leave main requiring a check that never runs
    (every PR blocked) or, worse, dropping one without anyone noticing
  * every workflow action is pinned to a full commit SHA
  * every relative link in the docs points at a file that exists

Standard library only.  python3 tests/test_repo.py
"""
import glob
import json
import os
import re
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(path):
    with open(os.path.join(REPO, path), encoding="utf-8") as fh:
        return fh.read()


def ci_job_names():
    """The `name:` of each job in ci.yml — what GitHub reports as the check."""
    src = read(".github/workflows/ci.yml")
    jobs = src[src.index("\njobs:"):]
    return re.findall(r"^  [a-z][a-z0-9_-]*:\n    name: (.+)$", jobs, re.M)


class Ruleset(unittest.TestCase):

    def setUp(self):
        self.rules = json.loads(read(".github/rulesets/main.json"))

    def test_required_checks_are_the_ci_jobs(self):
        required = next(r for r in self.rules["rules"] if r["type"] == "required_status_checks")
        contexts = sorted(c["context"] for c in required["parameters"]["required_status_checks"])
        self.assertEqual(contexts, sorted(ci_job_names()))
        self.assertGreaterEqual(len(contexts), 3)

    def test_main_cannot_be_rewritten_or_deleted(self):
        types = {r["type"] for r in self.rules["rules"]}
        self.assertTrue({"deletion", "non_fast_forward", "pull_request"} <= types)
        self.assertEqual(self.rules["enforcement"], "active")


class Workflows(unittest.TestCase):

    def test_every_action_is_pinned_to_a_sha(self):
        bad = []
        for wf in glob.glob(os.path.join(REPO, ".github/workflows/*.yml")):
            for n, line in enumerate(open(wf, encoding="utf-8"), 1):
                m = re.match(r"\s*-?\s*uses:\s*([^\s#]+)", line)
                if m and not re.search(r"@[0-9a-f]{40}$", m.group(1)):
                    bad.append("%s:%d %s" % (os.path.basename(wf), n, m.group(1)))
        self.assertEqual(bad, [])

    def test_default_token_is_read_only(self):
        for wf in glob.glob(os.path.join(REPO, ".github/workflows/*.yml")):
            top = open(wf, encoding="utf-8").read().split("\njobs:")[0]
            self.assertRegex(top, r"\npermissions:\s*(read-all|\n\s+contents: read)", os.path.basename(wf))


class DocLinks(unittest.TestCase):

    def test_relative_links_resolve(self):
        broken, checked = [], 0
        docs = glob.glob(os.path.join(REPO, "*.md")) + glob.glob(os.path.join(REPO, "docs", "**", "*.md"), recursive=True)
        for doc in docs:
            text = open(doc, encoding="utf-8").read()
            text = re.sub(r"```.*?```", "", text, flags=re.S)       # ignore code blocks
            for target in re.findall(r"\]\(([^)\s]+)\)", text):
                if re.match(r"[a-z]+:", target) or target.startswith("#"):
                    continue
                checked += 1
                path = target.split("#")[0]
                full = os.path.normpath(os.path.join(os.path.dirname(doc), path))
                if not os.path.exists(full):
                    broken.append("%s -> %s" % (os.path.relpath(doc, REPO), target))
        self.assertEqual(broken, [])
        self.assertGreater(checked, 20, "the link scan found almost nothing to check")


class Community(unittest.TestCase):

    def test_community_files_exist(self):
        for f in ("README.md", "LICENSE", "SECURITY.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md",
                  ".github/pull_request_template.md", ".github/ISSUE_TEMPLATE/bug_report.yml",
                  ".github/ISSUE_TEMPLATE/false_positive.yml", ".github/ISSUE_TEMPLATE/config.yml"):
            self.assertTrue(os.path.exists(os.path.join(REPO, f)), f)


class VersionIsOneNumber(unittest.TestCase):
    """The version lives in neptune.sh; the README, the changelog and the issue
    templates must agree with it, or a release says one thing and the tool
    another (1.2.0 shipped its features while still printing 1.1.0)."""

    def test_everything_names_the_same_version(self):
        with open(os.path.join(REPO, "scripts", "neptune.sh"), encoding="utf-8") as fh:
            code = re.search(r'^NEPTUNE_VERSION="([^"]+)"', fh.read(), re.M).group(1)
        with open(os.path.join(REPO, "README.md"), encoding="utf-8") as fh:
            self.assertIn("Version %s." % code, fh.read())
        with open(os.path.join(REPO, "CHANGELOG.md"), encoding="utf-8") as fh:
            self.assertRegex(fh.read(), r"(?m)^## \[%s\] — \d{4}-\d{2}-\d{2}$" % re.escape(code))
        for name in ("bug_report.yml", "false_positive.yml"):
            with open(os.path.join(REPO, ".github", "ISSUE_TEMPLATE", name), encoding="utf-8") as fh:
                self.assertIn("Neptune %s" % code, fh.read(), name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
