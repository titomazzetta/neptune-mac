#!/usr/bin/env python3
"""e2e_assert.py — check a REAL full run, on real macOS, from its JSON.

The macOS CI job runs ./neptune.sh --html --json on the runner itself and then
this. It does not assert that the runner is healthy — a CI image is whatever it
is — it asserts that the TOOL worked: every scan ran to completion and recorded
results, nothing was lost in the pipeline, the posture panel was filled in, and
the exit code agrees with the verdict. Those are the claims a report makes
about itself, checked on the platform the report is for.

Usage: e2e_assert.py <neptune_findings_*.json> <exit-code> <report.html>
"""
import json
import sys

path, rc, html_path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
report = json.load(open(path, encoding="utf-8"))
problems = []

if not report["integrity"]["ok"]:
    problems.append("integrity failure: %s" % report["integrity"]["problem"])

run_level = [f for f in report["findings"]
             if f.get("check") in ("scan-failed", "scan-missing", "scan-silent", "record-format")]
for f in run_level:
    problems.append("a scan did not complete: %s" % f["title"])

scans = {f["scan"] for f in report["findings"]} | {c["scan"] for c in report["checks_passed"]}
for s in ("sentry", "redflag", "network", "audit", "updates"):
    if s not in scans:
        problems.append("scan %r recorded nothing" % s)

if report["counts"]["pass"] < 20:
    problems.append("only %d checks passed — the suite barely ran" % report["counts"]["pass"])

unchecked = [p["label"] for p in report["posture"] if p["state"] == "not-checked"]
if unchecked:
    problems.append("posture controls never checked: %s" % ", ".join(unchecked))

unmapped = [f["title"] for f in report["findings"] if f["advice"].get("unmapped")]
if unmapped:
    problems.append("findings with no advice: %s" % unmapped)

want = {"needs_attention": 1, "incomplete": 2, "healthy": 0, "healthy_minor": 0}[report["verdict"]]
if rc != want:
    problems.append("exit code %d disagrees with verdict %s (expected %d)" % (rc, report["verdict"], want))

page = open(html_path, encoding="utf-8").read().lower()
for bad in ("<script", "http://", "https://", "<link"):
    if bad in page:
        problems.append("HTML report contains %r" % bad)

print("verdict: %s   exit: %d   passed: %d   attention: %d   minor: %d   unknown: %d"
      % (report["verdict"], rc, report["counts"]["pass"], report["counts"]["attention"],
         report["counts"]["notice"], report["counts"]["unknown"]))
for p in problems:
    print("FAIL  " + p)
sys.exit(1 if problems else 0)
