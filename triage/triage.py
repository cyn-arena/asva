#!/usr/bin/env python3
"""
triage.py -- ASVA Triage Agent (Stage A)
=========================================
Reads ranked_unified_findings.json from the normaliser, filters to
critical and high severity fixable findings, groups them by file,
and splits into batches by finding type.

Batch file naming convention:
  {repo_name}_{scan_type}_{shortSHA}.json
  e.g. asva_sast_239f8ach_1.json

This provides traceability to the repo and codebase that was scanned.

Batch limits:
  - SCA:       1 batch containing the observed source manifests
  - Container: 1 batch (always 1 file — the one given by --container-file)
  - SAST:      max 10 files per batch — splits into multiple batches
               if there are more than 10 SAST files to fix

Each batch file = one PR created by agent_loop.py
Each batch      = one commit with all file fixes

Outputs:
  findings/ranked_findings.json                    -- full classified list
  fix_batches/{repo}_{type}_{sha}.json             -- SCA + container batches
  fix_batches/{repo}_sast_{sha}_1.json             -- SAST batch 1
  fix_batches/{repo}_sast_{sha}_2.json             -- SAST batch 2 (if > 10 files)

Usage:
    python triage.py --input     ../findings/ranked_unified_findings.json
                     --output    ../findings/ranked_findings.json
                     --batch-dir ../fix_batches
                     --repo-name asva
                     --commit-sha 239f8ach
                     --container-file docker-compose.yml   (optional; this is the default)
"""

import json
import sys
import argparse
from pathlib import Path
from datetime import datetime, timezone


# ===========================================================================
# SECTION 1: CONSTANTS
# ===========================================================================

# Only auto-fix critical/high. Medium is dominated by noise (incl. hardcoded-password
# warnings in the DB seed script whose "fix" would break the seeded test logins) -- see
# ALWAYS_FIX_RULES / NEVER_FIX_RULES below for the deliberate exceptions.
ACTIONABLE_SEVERITIES = {"critical", "high"}

# Rule IDs we ALWAYS fix even when the scanner rates them below the severity cut. These are
# high-value, low-noise vulnerabilities the scanner tends to score "medium" but that are
# genuinely exploitable. Keyed on rule_id (not the app) so this generalises to any scanned
# app, not just NodeGoat.
ALWAYS_FIX_RULES = {
    "javascript/OR",  # A10 unvalidated redirect / open redirect (Snyk Code)
}

# Rule IDs we NEVER auto-fix, whatever the severity — the automated fix is more likely to
# break the app than to help. e.g. hardcoded-credential findings which, in this codebase, all
# live in the DB seed script whose accounts every test logs in with; "fixing" them breaks the
# test suite. This denylist wins over both the severity cut and ALWAYS_FIX_RULES.
NEVER_FIX_RULES = {
    "javascript/NoHardcodedPasswords",
}

# Max files per SAST batch — each file = one fix, each batch = one commit + PR
MAX_FILES_PER_SAST_BATCH = 10

# Paths that indicate a test/non-production file
TEST_PATH_MARKERS = (
    "test", "tests", "spec", "specs",
    "example", "examples", "fixture", "fixtures",
    "bench", "benchmark", "demo", "sample",
    "mock", "mocks", "stub", "stubs"
)

# Batch types
BATCH_TYPES = ("sast", "sca", "container")


# ===========================================================================
# SECTION 2: FILTERING
# ===========================================================================

def _is_actionable(finding: dict) -> bool:
    """A finding is actionable when it is fixable, outside node_modules, NOT on the
    never-fix denylist, and EITHER critical/high OR an always-fix allowlisted rule."""
    rule_id = (finding.get("identifiers") or {}).get("rule_id")
    if rule_id in NEVER_FIX_RULES:
        return False
    if finding.get("is_node_modules", False):
        return False
    file = finding.get("location", {}).get("file", "")
    if file.startswith("node_modules/") or file.startswith("node_modules\\"):
        return False
    if not finding.get("remediation", {}).get("fixable", False):
        return False
    return finding.get("severity") in ACTIONABLE_SEVERITIES or rule_id in ALWAYS_FIX_RULES


def filter_actionable(findings: list[dict]) -> list[dict]:
    """Filter to fixable, non-node_modules findings that are critical/high or an
    allowlisted rule (and never a denylisted rule)."""
    actionable = [f for f in findings if _is_actionable(f)]
    print(f"  Filtered: {len(findings)} total -> {len(actionable)} actionable "
          f"(critical/high or allowlisted rule, fixable, non-node_modules)")
    return actionable


# ===========================================================================
# SECTION 3: CLASSIFICATION
# ===========================================================================

def is_test_file(finding: dict) -> bool:
    """Return True if the finding is in a test/non-production file path."""
    file_path = finding.get("location", {}).get("file", "").lower()
    parts = file_path.replace("\\", "/").split("/")
    return any(marker in parts for marker in TEST_PATH_MARKERS)


def get_fix_type(finding: dict) -> str:
    """Determine fix type from remediation.type."""
    remediation_type = finding.get("remediation", {}).get("type", "")
    if remediation_type == "version_upgrade":
        return "version_upgrade"
    if remediation_type == "code_change":
        return "code_change"
    return "config_change"


def editable_target(finding: dict, container_file: str) -> str | None:
    """Route only source observations and configured OS image remediation."""
    location = finding["location"]
    if finding["finding_type"] == "container":
        if location.get("kind") in {"dependency", "container_package"}:
            # Image manifests are not source paths. Keep the finding for review.
            return None
        return container_file
    file = location["file"].replace("\\", "/")
    if file.startswith("/") or ":" in file or ".." in file.split("/") or file == "unknown":
        return None
    return file


def classify(actionable: list[dict], container_file: str = "docker-compose.yml") -> list[dict]:
    """Resolve editable targets before selecting roots by (scan type, target)."""
    groups: dict[tuple, list[dict]] = {}
    for finding in actionable:
        target = editable_target(finding, container_file)
        key = (finding["finding_type"], target)
        groups.setdefault(key, []).append(finding)

    classified = []
    for finding in actionable:
        target = editable_target(finding, container_file)
        siblings = groups[(finding["finding_type"], target)]
        root_id = siblings[0]["finding_id"]
        is_root = finding["finding_id"] == root_id
        location = dict(finding["location"])
        if target:
            location.update(file=target, observed_file=finding["location"]["file"])
        reason = (
            f"Root fix for {target} — agent edits this file once to address all {len(siblings)} finding(s)."
            if is_root else f"Covered by root fix for {target} — will be addressed in the same commit."
        ) if target else "Deferred: no evidence mapping the observation to an editable source target."
        classified.append({
            **finding,
            "location": location,
            "editable_target": target,
            "routing_status": "editable" if target else "deferred",
            "covered_by": None if is_root or not target else root_id,
            "is_test_file": is_test_file(finding),
            "fix_type": get_fix_type(finding),
            "triage_reason": reason,
        })
    return classified


def validate(classified: list[dict], actionable: list[dict],
             container_file: str = "docker-compose.yml") -> list[dict]:
    """Restore missing findings through the same target resolution and grouping."""
    input_ids = {f["finding_id"] for f in actionable}
    output_ids = {f["finding_id"] for f in classified}
    missing = input_ids - output_ids
    if missing:
        print(f"[WARN] {len(missing)} finding(s) missing — restoring", file=sys.stderr)
        classified = classify(actionable, container_file)
    classified.sort(key=lambda f: f.get("priority") or 9999)
    return classified


# ===========================================================================
# SECTION 4: BATCHING
# ===========================================================================

def build_files_to_fix(classified: list[dict], finding_type: str) -> list[dict]:
    """
    Build the files_to_fix list for a given finding_type.
    Each entry = one file the agent fixes and stages.
    Includes all findings (root + covered) for that file.
    """
    groups: dict[str, list[dict]] = {}
    for finding in classified:
        if finding["finding_type"] != finding_type or finding.get("routing_status") == "deferred":
            continue
        groups.setdefault(finding["location"]["file"], []).append(finding)
    files_to_fix = []
    for file, all_for_file in groups.items():
        root = all_for_file[0]
        files_to_fix.append({
            "file": file,
            "fix_type": root.get("fix_type"),
            "finding_type": finding_type,
            "findings": all_for_file,
            "finding_count": len(all_for_file),
        })

    return files_to_fix


def make_batch(
    batch_id:     str,
    batch_type:   str,
    repo_name:    str,
    short_sha:    str,
    scan_run_id:  str,
    files_to_fix: list[dict]
) -> dict:
    """Build a single batch object."""
    return {
        "batch_id":       batch_id,
        "batch_type":     batch_type,
        "repo_name":      repo_name,
        "commit_sha":     short_sha,
        "scan_run_id":    scan_run_id,
        "generated_at":   datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_files":    len(files_to_fix),
        "total_findings": sum(f["finding_count"] for f in files_to_fix),
        "files_to_fix":   files_to_fix,
    }


def build_batches(
    classified:  list[dict],
    repo_name:   str,
    short_sha:   str,
    scan_run_id: str,
) -> list[tuple[str, dict]]:
    """
    Build all batch files.

    Naming convention: {repo_name}_{scan_type}_{shortSHA}
    e.g. asva_sast_239f8ach_1.json

    SCA + container: 1 batch each
    SAST: split into chunks of MAX_FILES_PER_SAST_BATCH
    """
    batches: list[tuple[str, dict]] = []

    for batch_type in BATCH_TYPES:
        files_to_fix = build_files_to_fix(classified, batch_type)
        if not files_to_fix:
            continue

        if batch_type == "sast" and len(files_to_fix) > MAX_FILES_PER_SAST_BATCH:
            # split SAST into chunks of MAX_FILES_PER_SAST_BATCH
            chunks = [
                files_to_fix[i:i + MAX_FILES_PER_SAST_BATCH]
                for i in range(0, len(files_to_fix), MAX_FILES_PER_SAST_BATCH)
            ]
            for idx, chunk in enumerate(chunks, start=1):
                batch_id = f"{repo_name}_sast_{short_sha}_{idx}"
                batches.append((
                    batch_id,
                    make_batch(batch_id, "sast", repo_name, short_sha, scan_run_id, chunk)
                ))
        else:
            if batch_type == "sast":
                batch_id = f"{repo_name}_sast_{short_sha}_1"
            else:
                batch_id = f"{repo_name}_{batch_type}_{short_sha}"
            batches.append((
                batch_id,
                make_batch(batch_id, batch_type, repo_name, short_sha, scan_run_id, files_to_fix)
            ))

    return batches


# ===========================================================================
# SECTION 5: MAIN
# ===========================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="ASVA Triage Agent — classify by file, split into batches."
    )
    parser.add_argument(
        "--input",
        default="../findings/ranked_unified_findings.json",
        metavar="FILE",
        help="Path to ranked_unified_findings.json."
    )
    parser.add_argument(
        "--output",
        default="../findings/ranked_findings.json",
        metavar="FILE",
        help="Path to write ranked_findings.json."
    )
    parser.add_argument(
        "--batch-dir",
        default="../fix_batches",
        metavar="DIR",
        help="Directory to write batch files. Default: ../fix_batches"
    )
    parser.add_argument(
        "--repo-name",
        default="repo",
        metavar="NAME",
        help="GitHub repo name for batch file naming. e.g. asva"
    )
    parser.add_argument(
        "--commit-sha",
        default="00000000",
        metavar="SHA",
        help="Git commit SHA (full or short). First 8 chars used. e.g. 239f8ach"
    )

    parser.add_argument(
        "--container-file",
        default="docker-compose.yml",
        help="App-relative file for container remediation batches. Default preserves NodeGoat behavior.",
    )
    args        = parser.parse_args()
    input_path  = Path(args.input)
    output_path = Path(args.output)
    batch_dir   = Path(args.batch_dir)
    repo_name   = args.repo_name.replace("/", "-")  # sanitise e.g. org/repo -> org-repo
    short_sha   = args.commit_sha[:8]               # first 8 chars only

    if not input_path.exists():
        print(f"[ERROR] Input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    print("=" * 60)
    print("ASVA Triage Agent (Stage A) — Group by File + Batch")
    print("=" * 60)
    print(f"  repo:       {repo_name}")
    print(f"  commit SHA: {short_sha}")

    print("\n[1/5] Loading ranked unified findings...")
    with input_path.open("r", encoding="utf-8") as f:
        findings = json.load(f)
    scan_run_id = findings[0].get("scan_run_id", "unknown") if findings else "unknown"
    print(f"  Loaded {len(findings)} findings (scan_run_id: {scan_run_id})")

    print("\n[2/5] Filtering to actionable findings...")
    actionable = filter_actionable(findings)

    if not actionable:
        print("\n[INFO] No actionable findings.")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as f:
            json.dump([], f, indent=2)
        return

    print("\n[3/5] Classifying by file...")
    classified = classify(actionable, container_file=args.container_file)
    classified = validate(classified, actionable, args.container_file)
    print(f"  Classified {len(classified)} findings")

    print("\n[4/5] Writing ranked_findings.json...")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(classified, f, indent=2, ensure_ascii=False)
    print(f"  Wrote: {output_path}")

    print("\n[5/5] Building and writing batch files...")
    batches = build_batches(classified, repo_name, short_sha, scan_run_id)
    batch_dir.mkdir(parents=True, exist_ok=True)

    for batch_id, batch in batches:
        batch_path = batch_dir / f"{batch_id}.json"
        with batch_path.open("w", encoding="utf-8") as f:
            json.dump(batch, f, indent=2, ensure_ascii=False)
        print(f"  Wrote: {batch_path}  "
              f"({batch['total_files']} file(s), "
              f"{batch['total_findings']} finding(s))")

    # Summary
    root_fixes = [f for f in classified if not f.get("covered_by") and f.get("routing_status") != "deferred"]
    covered    = [f for f in classified if f.get("covered_by")]
    test_files = [f for f in classified if f.get("is_test_file")]

    print()
    print("=" * 60)
    print("TRIAGE SUMMARY")
    print("=" * 60)
    print(f"  repo name           : {repo_name}")
    print(f"  commit SHA          : {short_sha}")
    print(f"  scan_run_id         : {scan_run_id}")
    print(f"  total actionable    : {len(classified)}")
    print(f"  files to fix        : {len(root_fixes)}  (one commit per batch)")
    print(f"  covered findings    : {len(covered)}")
    print(f"  deferred findings   : {sum(f.get('routing_status') == 'deferred' for f in classified)}")
    print(f"  test files          : {len(test_files)}")
    print(f"  max SAST batch size : {MAX_FILES_PER_SAST_BATCH} files")
    print()
    print(f"  Batches → PRs:")
    for batch_id, batch in batches:
        print(f"    {batch_id}.json "
              f"— {batch['total_files']} file(s), "
              f"{batch['total_findings']} finding(s)")
    print()
    print("  Files the agent will fix:")
    for f in root_fixes:
        count = sum(
            1 for x in classified
            if x["location"]["file"] == f["location"]["file"] and x["finding_type"] == f["finding_type"]
        )
        print(f"    [{f['severity'].upper():8s}] "
              f"{f['finding_type']:10s} | "
              f"{f['location']['file']} "
              f"— {count} finding(s) | {f.get('fix_type')}")
    print()
    print(f"  Agent will make {len(batches)} PR(s) total\n")
    print("Done.\n")


if __name__ == "__main__":
    main()
