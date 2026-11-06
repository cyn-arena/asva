"""
agent/code_scan.py -- scan a code fix before its PR opens (ITP2 3.3).

The pipeline's rescan runs after the PR is open, which is too late to do anything but report. With
ASVA_SCAN_BEFORE_PR=1, agent/test_first.py runs the same scanner on a code fix that passed the app's
tests and compares it with today's findings, counted the way the PR's table counts them
(gitops/post_pr_summary.py). A new critical or high goes back to the LLM once, then makes the PR a draft.
New medium and low ones are only shown in the table.

Only what the fix could have caused counts: a route that touches none of the changed files is the
scanner changing its mind between two scans, not this fix. The app needs the scanner installed. If it
can't run, the PR says it was not scanned.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from agent import app_check
from gitops import config
from gitops.post_pr_summary import TOP, distinct

SCAN_TIMEOUT = 600
MAX_ROUTES_SHOWN = 5


def enabled() -> bool:
    return os.environ.get("ASVA_SCAN_BEFORE_PR", "").strip() == "1"


def today(findings_path: str | None) -> dict | None:
    """Today's code findings, or None if they can't be read."""
    try:
        data = json.loads(Path(findings_path).read_text(encoding="utf-8"))
        return distinct(data if isinstance(data, list) else data["findings"], "sast")
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(f"    [scan] today's findings could not be read: {e}")
        return None


def scan(files: dict[str, str], repo_dir: str) -> dict | None:
    """The scanner's code findings for a copy of the app with `files` replaced. None if it could not
    run, which says nothing about the fix."""
    from normaliser.normaliser import process_sarif_file

    temp = Path(tempfile.mkdtemp(prefix="asva-code-scan-"))
    try:
        work = temp / "app"
        shutil.copytree(Path(repo_dir) / config.FIX_PATH_PREFIX, work, ignore=app_check._COPY_IGNORE)
        for relative, content in files.items():
            (work / relative).write_text(content, encoding="utf-8", newline="\n")
        sarif = temp / "sast.sarif.json"
        done = subprocess.run(["snyk", "code", "test", f"--sarif-file-output={sarif}"], cwd=work,
                              capture_output=True, timeout=SCAN_TIMEOUT)
        if done.returncode not in (0, 1) or not sarif.exists():
            print(f"    [scan] the scanner could not run: exit code {done.returncode}")
            return None
        return distinct(process_sarif_file(sarif, strict=True), "sast")
    except (OSError, ValueError, TypeError, subprocess.SubprocessError) as e:
        print(f"    [scan] the scan could not run: {e}")
        return None
    finally:
        shutil.rmtree(temp, ignore_errors=True)


def _files(finding: dict) -> set[str]:
    return {step.get("file") for step in finding.get("code_flow") or []} | {(finding.get("location") or {}).get("file")}


def _route_text(finding: dict) -> str:
    steps = finding.get("code_flow") or [finding.get("location") or {}]
    return " -> ".join(f"{step.get('file')}:{step.get('line')}" for step in steps)


def new_findings(before: dict, after: dict, changed: set[str]) -> list[dict]:
    """The new critical and high findings this fix could have caused, one per rule and file. Which of
    a rule's routes is the new one can't be told, as a fix moves lines, so each lists them all."""
    found: dict[tuple, dict] = {}
    for key, finding in after.items():
        if key in before or finding.get("severity") not in TOP:
            continue
        same = [f for k, f in after.items() if k[:2] == key[:2]]
        if not any(_files(f) & changed for f in same):
            continue
        item = found.setdefault(key[:2], {
            "rule": key[0], "file": key[1], "severity": finding["severity"], "title": finding.get("title") or key[0],
            "before": sum(k[:2] == key[:2] for k in before), "now": len(same),
            "files": sorted({file for f in same for file in _files(f) if file}),
            "routes": [_route_text(f) for f in same][:MAX_ROUTES_SHOWN], "message": finding.get("summary") or ""})
        item["severity"] = TOP[min(TOP.index(item["severity"]), TOP.index(finding["severity"]))]
    return list(found.values())


def extra(new: list[dict]) -> int:
    return sum(item["now"] - item["before"] for item in new)


def suspects(new: list[dict], paths: list[str]) -> list[str]:
    """The changed files on the routes of these findings."""
    named = {file for item in new for file in item["files"]}
    return [path for path in paths if path in named]


def reason(new: list[dict]) -> str:
    """What the LLM is told on its retry."""
    lines = ["the security scanner (not the app's tests) reports new findings after this fix:"]
    for item in new:
        lines.append(f"\n- {item['severity']} {item['rule']} ({item['title']}), starting in {item['file']}: "
                     f"{item['before']} route(s) before the fix, {item['now']} now. {item['message']}".rstrip())
        lines += [f"  route: {route}" for route in item["routes"]]
    lines.append("\nRemove what the fix added that the scanner flags, without bringing back what it fixed.")
    return "\n".join(lines)


def describe(item: dict) -> str:
    """One finding for the PR's text."""
    return f"`{item['file']}`: {item['rule']}, {item['severity']} ({item['before']} before this fix, {item['now']} now)"
