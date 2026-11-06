"""
agent/browser_failure_batch.py -- turn captured misuse-case failures
(agent/failure_capture.py) into the same batch schema triage.build_batches produces, so
agent_loop.process_batch and gitops.git_gh_ops consume them unchanged.

Each captured test becomes its own batch (one test = one PR, same "1 batch = 1 PR" rule as
the scanner pipeline). A captured test's annotated files are fixed together as one
`logic_change` unit -- see agent_loop.build_fix_prompt's `logic_change` branch, which sends
all of a batch's files to the LLM in a single call instead of the usual one-call-per-file.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

_SAFE_ID_RE = re.compile(r"[^a-zA-Z0-9_]+")


def _safe_batch_suffix(test_name: str) -> str:
    """Turn a test name into something safe to embed in a batch_id / git ref."""
    return _SAFE_ID_RE.sub("_", test_name).strip("_")


def _build_finding(failure: dict, file_path: str, index: int) -> dict:
    """A synthesized finding for one annotated file. No CWE/rule_id/line -- a
    business-logic bug proven by a failing test has none of those, unlike a SAST hit."""
    return {
        "finding_id": f"browser-{_safe_batch_suffix(failure['test_name'])}-{index}",
        "finding_type": "logic",
        "severity": "high",
        "identifiers": {"cve": None, "cwe": None, "rule_id": None},
        "title": "Business-logic vulnerability confirmed by a misuse-case test",
        "summary": failure["detail"],
        "description": failure["detail"],
        "location": {
            "kind": "source_file", "file": file_path, "line": None,
            "package": None, "display": file_path,
        },
        "remediation": {"type": "logic_change", "fixable": True, "upgrade_to": None},
        "priority": index + 1,
        "covered_by": None,
        "is_test_file": False,
        "fix_type": "logic_change",
        "source": "browser_test",
        "test_id": failure["test_id"],
        "test_name": failure["test_name"],
    }


def build_batch(failure: dict, repo_name: str, commit_sha: str) -> dict:
    """One captured failure -> one batch. All its annotated files are grouped into a
    single `logic_change` unit fixed in one LLM call (agent_loop's multi-file path)."""
    short_sha = commit_sha[:8]
    files = failure["files"]
    files_to_fix = [
        {
            "file": file_path,
            "fix_type": "logic_change",
            "finding_type": "logic",
            "findings": [_build_finding(failure, file_path, i)],
            "finding_count": 1,
        }
        for i, file_path in enumerate(files)
    ]
    return {
        "batch_id": f"asva_logic_{short_sha}_{_safe_batch_suffix(failure['test_name'])}",
        "batch_type": "logic",
        "repo_name": repo_name,
        "commit_sha": short_sha,
        "scan_run_id": f"browser-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_files": len(files_to_fix),
        "total_findings": len(files_to_fix),
        "source_test_id": failure["test_id"],
        "files_to_fix": files_to_fix,
    }


def build_batches(
    failures: list[dict], repo_name: str, commit_sha: str
) -> list[tuple[str, dict]]:
    """One batch per captured failure. Returns (batch_id, batch) pairs, the same shape
    triage.build_batches returns, so a caller can write them to fix_batches/ identically."""
    return [
        (batch["batch_id"], batch)
        for batch in (build_batch(f, repo_name, commit_sha) for f in failures)
    ]
