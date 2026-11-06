"""Package a completed scan/triage run for the dashboard's existing v0.1 contract."""

import argparse
import datetime
import json
import os
from pathlib import Path
import re
import shutil

from jsonschema import Draft202012Validator


SCHEMA = Path(__file__).resolve().parents[1] / "schemas/dashboard-contract-v0.1.json"


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def package_run(input_dir, output_dir, *, app, run_id, sha, branch, repository,
                created_at, workflow, run_attempt="1"):
    for segment in (app, run_id):
        if not re.fullmatch(r"[A-Za-z0-9_-]+", segment):
            raise ValueError("Application and run ID must be plain path segments")
    if not re.fullmatch(r"[0-9a-fA-F]{40}", sha):
        raise ValueError("Record the full scanned commit SHA")
    datetime.datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    source = Path(input_dir)
    target = Path(output_dir) / app / run_id
    if target.exists():
        raise ValueError(f"Output already exists: {target}")

    status = read_json(source / "scan/scan-status.json")
    if (status.get("app"), status.get("run_id"), status.get("commit_sha")) != (app, run_id, sha):
        raise ValueError("Scan evidence does not match this application, run and commit")
    scan_paths = {}
    for kind in ("sast", "sca", "container"):
        rel = f"scan/{kind}.sarif.json"
        data = read_json(source / rel)
        if status.get("scans", {}).get(kind, {}).get("status") != "completed":
            raise ValueError(f"{kind} scan did not complete")
        if data.get("version") != "2.1.0" or not data.get("runs"):
            raise ValueError(f"{kind} report is not complete SARIF 2.1.0")
        scan_paths[kind] = rel

    findings_path = "findings/ranked_unified_findings.json"
    triage_path = "findings/ranked_findings.json"
    findings = read_json(source / findings_path)
    triage = read_json(source / triage_path)
    batch_paths = sorted((source / "remediation/fix_batches").glob("*.json"))
    batches = [read_json(path) for path in batch_paths]
    for finding in findings + triage:
        if finding.get("scan_run_id") != run_id:
            raise ValueError("A finding belongs to a different scan run")
    finding_ids = {f["finding_id"] for f in findings}
    triage_ids = {f["finding_id"] for f in triage}
    if not triage_ids.issubset(finding_ids):
        raise ValueError("Triage contains findings missing from the original scan")
    for batch in batches:
        if batch.get("scan_run_id") != run_id or batch.get("commit_sha") != sha[:8]:
            raise ValueError("A fix batch belongs to a different run or commit")
        for file in batch["files_to_fix"]:
            if not {f["finding_id"] for f in file["findings"]}.issubset(triage_ids):
                raise ValueError("A fix batch contains findings absent from triage")

    manifest = {
        "schema_version": "0.1", "app": app, "run_id": run_id,
        "commit_sha": sha, "branch": branch, "workflow": workflow,
        "created_at": created_at,
        "workflow_url": f"https://github.com/{repository}/actions/runs/{run_id}",
        "stages": {"scan": "completed", "normalise": "completed", "triage": "completed",
                   "fix": "not_available", "validate": "not_available"},
        "artifacts": {
            "scan": scan_paths, "findings": findings_path, "triage": triage_path,
            "fix_batches": [p.relative_to(source).as_posix() for p in batch_paths],
        },
        "run_attempt": run_attempt,
        "packaged_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    payload = {"manifest": manifest, "findings": findings, "triage": triage, "batches": batches}
    Draft202012Validator(read_json(SCHEMA)).validate(payload)

    # Only write a dashboard bundle after all evidence and schema checks pass.
    for rel in [*scan_paths.values(), "scan/scan-status.json", findings_path, triage_path,
                *manifest["artifacts"]["fix_batches"]]:
        dest = target / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / rel, dest)
    (target / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Dashboard bundle: {target} ({len(findings)} findings, {len(triage)} actionable)")
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", required=True)
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--created-at", required=True)
    parser.add_argument("--run-id", default=os.getenv("GITHUB_RUN_ID"))
    parser.add_argument("--sha", default=os.getenv("GITHUB_SHA"))
    parser.add_argument("--branch", default=os.getenv("GITHUB_REF_NAME"))
    parser.add_argument("--repository", default=os.getenv("GITHUB_REPOSITORY"))
    parser.add_argument("--workflow", default=os.getenv("GITHUB_WORKFLOW"))
    parser.add_argument("--run-attempt", default=os.getenv("GITHUB_RUN_ATTEMPT", "1"))
    args = parser.parse_args()
    if not all((args.run_id, args.sha, args.branch, args.repository, args.workflow)):
        parser.error("Provide run metadata explicitly or through GitHub Actions environment variables")
    package_run(args.input_dir, args.output_dir, app=args.app, run_id=args.run_id,
                sha=args.sha, branch=args.branch, repository=args.repository,
                created_at=args.created_at, workflow=args.workflow, run_attempt=args.run_attempt)


if __name__ == "__main__":
    main()
