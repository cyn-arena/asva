"""
secrets_scan/gitleaks_gate.py -- ASVA pre-commit secrets gate.

Integrates git-leaks as a safety check that blocks commits/PRs containing leaked
credentials or secrets.

The gate scans the *candidate* fixed file contents directly, BEFORE they are staged,
committed, or pushed. If any secret is found, the caller
(gitops.git_gh_ops.submit_fix_batch) must not create a branch, commit, push, or open a
PR for that batch. A secret the file already had isn't one the fix leaks, so added_leaks
lets the caller tell the two apart by comparing a scan of the original with the fix.

Fail-closed: if gitleaks cannot run at all, scan_files raises GitleaksError and the
caller treats that as "do not push" — a security gate that cannot verify must block.

Config (env):
  GITLEAKS_BINARY      PATH name or absolute path to gitleaks (default: "gitleaks")
  GITLEAKS_SUBCOMMAND  "detect" (universal) or "dir" (newer gitleaks). Default "detect".
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

GITLEAKS_BINARY = os.environ.get("GITLEAKS_BINARY", "gitleaks").strip()
GITLEAKS_SUBCOMMAND = os.environ.get("GITLEAKS_SUBCOMMAND", "detect").strip()

# Exit code gitleaks returns when leaks are found (set explicitly via --exit-code so we
# can distinguish "leaks found" from a real execution error).
_LEAK_EXIT_CODE = 2


class GitleaksError(RuntimeError):
    """Raised when gitleaks cannot be run (missing binary, bad invocation, etc.)."""


@dataclass
class ScanResult:
    """Outcome of a secrets scan. Truthy when it is safe to proceed."""

    clean: bool
    leaks: list[dict] = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.clean


def _safe_rel(path: str) -> str:
    """Reject directory traversal so a candidate file can't escape the scan tree — which
    would otherwise let a secret in a `../`-pathed file bypass the gate entirely."""
    rel = path.replace("\\", "/").lstrip("/")
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    if ".." in parts:
        raise GitleaksError(f"Unsafe path (directory traversal): {path!r}")
    return "/".join(parts)


def _write_candidate_tree(files: list[dict], root: Path) -> None:
    """Materialise the proposed file contents under `root`, preserving relative paths."""
    base = root.resolve()
    for f in files:
        dest = (base / _safe_rel(f["path"])).resolve()
        if dest != base and base not in dest.parents:
            raise GitleaksError(f"Refusing to write outside the scan tree: {f['path']!r}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(f.get("content", ""), encoding="utf-8")


def _build_cmd(src: Path, report: Path) -> list[str]:
    # No --redact: added_leaks needs the values to compare. The report sits beside the scanned
    # files in the same temp folder, is deleted with it, and _parse_report keeps only a hash.
    common = [
        "--report-format", "json",
        "--report-path", str(report),
        "--no-banner",
        "--exit-code", str(_LEAK_EXIT_CODE),
    ]
    if GITLEAKS_SUBCOMMAND == "dir":
        return [GITLEAKS_BINARY, "dir", str(src), *common]
    # "detect --no-git --source <dir>" scans files (no git history) — broadest compatibility.
    return [GITLEAKS_BINARY, "detect", "--no-git", "--source", str(src), *common]


def _parse_report(report: Path, src: Path) -> list[dict]:
    if not report.exists():
        return []
    try:
        data = json.loads(report.read_text(encoding="utf-8") or "[]")
    except json.JSONDecodeError:
        return []
    leaks = []
    for item in data or []:
        raw = item.get("File") or ""
        # gitleaks reports an absolute path under the temp tree — report it relative to
        # the scanned root so it matches the candidate file path (e.g. app/config.js).
        try:
            rel = str(Path(raw).resolve().relative_to(src.resolve())).replace("\\", "/")
        except (ValueError, OSError):
            rel = raw
        secret = item.get("Secret")
        leaks.append({
            "file": rel,
            "rule": item.get("RuleID") or item.get("Rule"),
            "line": item.get("StartLine"),
            "description": item.get("Description"),
            "value_id": hashlib.sha256(secret.encode("utf-8")).hexdigest() if secret else None,
        })
    return leaks


def added_leaks(original: "ScanResult", fixed: "ScanResult") -> list[dict]:
    """The leaks in `fixed` that `original` doesn't account for. Compares values, not line
    numbers, as a fix moves lines. A value found more often than before counts as added, and
    so does a leak with no value to compare, as the gate can't say it was already there."""
    known = Counter(leak["value_id"] for leak in original.leaks if leak.get("value_id"))
    added = []
    for leak in fixed.leaks:
        if known[leak.get("value_id")] > 0:
            known[leak["value_id"]] -= 1
        else:
            added.append(leak)
    return added


def scan_files(files: list[dict]) -> ScanResult:
    """Scan candidate file contents for secrets.

    `files` has the same shape pushed to GitHub: [{"path": ..., "content": ...}, ...].
    Returns ScanResult(clean=..., leaks=[...]). Raises GitleaksError if gitleaks itself
    cannot run (the caller should fail closed).
    """
    if not files:
        return ScanResult(clean=True)

    with tempfile.TemporaryDirectory(prefix="asva-secrets-") as tmp:
        root = Path(tmp)
        src = root / "tree"
        src.mkdir()
        report = root / "report.json"
        _write_candidate_tree(files, src)

        try:
            proc = subprocess.run(_build_cmd(src, report), capture_output=True, text=True)
        except FileNotFoundError as e:
            raise GitleaksError(
                f"git-leaks binary '{GITLEAKS_BINARY}' not found. Install gitleaks "
                "(https://github.com/gitleaks/gitleaks) and put it on PATH, or set "
                "GITLEAKS_BINARY."
            ) from e

        leaks = _parse_report(report, src)

        # 0 = clean, _LEAK_EXIT_CODE = leaks found. Any other code with no parsed leaks
        # means gitleaks failed to run properly — surface it so the caller fails closed.
        if proc.returncode not in (0, _LEAK_EXIT_CODE) and not leaks:
            detail = proc.stderr.strip() or proc.stdout.strip() or "no output"
            raise GitleaksError(f"gitleaks failed (exit {proc.returncode}): {detail}")

    # Derive clean from the authoritative exit code, NOT from the parsed report. If gitleaks
    # found leaks (exit 2) but the report was missing/unparseable, leaks would be empty —
    # trusting it would let the secret through. The exit code can't be downgraded that way.
    return ScanResult(clean=(proc.returncode == 0), leaks=leaks)
