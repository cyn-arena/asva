"""
agent/failure_capture.py -- turn a confirmed-vulnerable misuse-case result into a
JSON-serialisable record for the browser-failure -> fix-agent handoff.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from agent.test_annotations import parse_annotated_files

_PARAM_SUFFIX_RE = re.compile(r"\[.*\]$")


def strip_param_suffix(test_name: str) -> str:
    """"test_foo[chromium]" -> "test_foo", so a parametrized test still matches the
    un-parametrized name its annotation was parsed under."""
    return _PARAM_SUFFIX_RE.sub("", test_name)


def build_capture_record(nodeid: str, files: list[str], detail: str) -> dict:
    """One captured case: which test, which files a fix would touch, and a plain-text
    description of the vulnerable behavior (feeds an LLM prompt, not a stack trace)."""
    file_part, _, test_part = nodeid.partition("::")
    return {
        "test_id": nodeid,
        "test_name": strip_param_suffix(test_part),
        "test_file": file_part,
        "files": files,
        "detail": detail[:2000],
    }


def capture_if_vulnerable(
    nodeid: str,
    vulnerable_behavior_observed: bool,
    detail: str,
    *,
    out_path: str | None = None,
) -> dict | None:
    """Record one confirmed-vulnerable case, if the calling test is "# @a"-annotated.

    No-op (returns None) when: the behavior wasn't observed (nothing to report), no
    output path is configured (via `out_path` or ASVA_CAPTURE_FAILURES_TO -- unset by
    default, so a normal test run is completely unaffected), or the test has no file
    annotations (not a browser-failure-handoff candidate -- e.g. the A1/A10 cases, which go through the
    scanner pipeline instead). Returns the appended record on success.
    """
    if not vulnerable_behavior_observed:
        return None
    out_path = out_path or os.environ.get("ASVA_CAPTURE_FAILURES_TO")
    if not out_path:
        return None

    file_part, _, test_part = nodeid.partition("::")
    try:
        source = Path(file_part).read_text(encoding="utf-8")
    except OSError:
        return None
    files = parse_annotated_files(source).get(strip_param_suffix(test_part))
    if not files:
        return None

    record = build_capture_record(nodeid, files, detail)
    _append_record(Path(out_path), record)
    return record


def _append_record(path: Path, record: dict) -> None:
    existing = json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
    existing.append(record)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(existing, indent=2), encoding="utf-8")
