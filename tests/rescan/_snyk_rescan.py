"""Run before/after Snyk scans and compare findings by dedup_key.

Only SAST differences are enforced strictly. SCA and container findings are informational
because their vulnerability data can change between scans.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

from normaliser.normaliser import deduplicate, process_sarif_file

# Load rescan settings here so this test tier works when run by itself.
load_dotenv()

SNYK_BINARY = os.environ.get("SNYK_BINARY", "snyk").strip()
SNYK_ORG = os.environ.get("SNYK_ORG", "").strip()

HIGH_SEVERITIES = {"critical", "high"}


class SnykScanError(RuntimeError):
    """Raised when the snyk CLI cannot be run, or ran but produced no SARIF report."""


def is_authenticated() -> bool:
    """True if the snyk CLI is ready to scan -- via `snyk auth` (stores its own token in
    the CLI's local config, no env var involved) or a SNYK_TOKEN env var (the CI path).
    `snyk whoami` is the CLI's own way to answer this without triggering a real scan."""
    try:
        proc = subprocess.run(
            [SNYK_BINARY, "whoami"], capture_output=True, text=True
        )
    except FileNotFoundError:
        return False
    return proc.returncode == 0


def _run_snyk(args: list[str], cwd: Path, sarif_out: Path) -> None:
    cmd = [SNYK_BINARY, *args, f"--sarif-file-output={sarif_out}"]
    proc = None
    if SNYK_ORG:
        cmd.append(f"--org={SNYK_ORG}")
    try:
        # snyk exits 1 when issues are found -- that is not a failure to run, so the
        # return code is deliberately not checked here. Only "no SARIF written at all"
        # (missing binary, auth failure, etc.) is treated as a real error.
        proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    except FileNotFoundError as e:
        raise SnykScanError(
            f"snyk binary {SNYK_BINARY!r} not found. Install the pinned version via "
            "scripts/install-snyk.sh / install-snyk.ps1 (see scripts/snyk-version.txt), "
            "or set SNYK_BINARY."
        ) from e
    if not sarif_out.exists():
        # Show what snyk itself said (e.g. "Snyk Code is not enabled for this org"), since
        # the cause is otherwise invisible
        said = " ".join(((getattr(proc, "stderr", "") or "") + " " + (getattr(proc, "stdout", "") or "")).split())
        raise SnykScanError(
            f"snyk did not write a SARIF report to {sarif_out} -- check that `snyk auth` "
            "has run (or SNYK_TOKEN is set) and SNYK_ORG is correct."
            + (f" Exit code {getattr(proc, 'returncode', '?')}." if proc is not None else "")
            + (f" snyk said: {said[-1500:]}" if said else "")
        )


def run_sast_scan(target_dir: Path, sarif_out: Path) -> Path:
    """Run `snyk code test` (SAST) against target_dir, writing SARIF to sarif_out."""
    _run_snyk(["code", "test"], target_dir, sarif_out)
    return sarif_out


def run_sca_scan(target_dir: Path, sarif_out: Path) -> Path:
    """Run `snyk test` (SCA/open-source) against target_dir, writing SARIF to sarif_out."""
    _run_snyk(["test"], target_dir, sarif_out)
    return sarif_out


def load_findings(sarif_paths: list[Path]) -> list[dict]:
    """Normalise + dedupe one or more SARIF files into a flat findings list that still
    carries dedup_key (normaliser.build_ranked_unified strips it for the downstream
    pipeline, but matching before/after scans by identity is exactly what it's for)."""
    findings: list[dict] = []
    for path in sarif_paths:
        findings.extend(process_sarif_file(path))
    return deduplicate(findings)


@dataclass
class RescanDiff:
    """Before/after findings split by dedup_key membership, never by count."""

    remediated: list[dict] = field(default_factory=list)  # in before, gone in after
    persisted: list[dict] = field(default_factory=list)   # in before, still in after
    introduced: list[dict] = field(default_factory=list)  # new in after, absent in before

    def introduced_of_type(self, finding_type: str) -> list[dict]:
        return [f for f in self.introduced if f["finding_type"] == finding_type]

    def introduced_high_severity(self) -> list[dict]:
        return [f for f in self.introduced if f["severity"] in HIGH_SEVERITIES]


def diff_findings(before: list[dict], after: list[dict]) -> RescanDiff:
    """Match `before` and `after` findings by dedup_key and split into remediated
    (fixed), persisted (still present), and introduced (new) buckets."""
    before_by_key = {f["dedup_key"]: f for f in before}
    after_by_key = {f["dedup_key"]: f for f in after}

    remediated = [f for key, f in before_by_key.items() if key not in after_by_key]
    persisted = [f for key, f in before_by_key.items() if key in after_by_key]
    introduced = [f for key, f in after_by_key.items() if key not in before_by_key]
    return RescanDiff(remediated=remediated, persisted=persisted, introduced=introduced)


def assert_fully_remediated(
    before: list[dict], diff: RescanDiff, expected_rule_ids: set[str]
) -> None:
    """Raise AssertionError unless every `before` finding whose rule_id is in
    expected_rule_ids has actually been remediated (absent from diff.persisted).

    Also raises if a rule_id in expected_rule_ids never appeared in `before` at all --
    without that guard, a mistyped rule_id (or one the scanner stopped emitting for an
    unrelated reason) would let this pass vacuously without proving anything was fixed.
    """
    before_rule_ids = {f["identifiers"]["rule_id"] for f in before}
    missing_from_before = expected_rule_ids - before_rule_ids
    if missing_from_before:
        raise AssertionError(
            "expected these SAST rule_ids in the 'before' scan (nothing to remediate "
            f"otherwise, check for a rule_id rename/typo): {sorted(missing_from_before)}"
        )

    persisted_rule_ids = {f["identifiers"]["rule_id"] for f in diff.persisted}
    still_present = expected_rule_ids & persisted_rule_ids
    if still_present:
        raise AssertionError(
            f"expected these SAST rule_ids to be fully remediated but they persisted: "
            f"{sorted(still_present)}"
        )
