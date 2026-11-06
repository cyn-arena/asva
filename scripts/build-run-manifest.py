"""Build truthful initial/candidate manifests from available evidence and job outcomes."""
import argparse
import datetime
import json
import os
from pathlib import Path
import shutil
from jsonschema import Draft202012Validator


SCHEMAS = Path(__file__).resolve().parents[1] / "schemas"


def read(path, default=None):
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else default


def make_manifest(root, app, run_id, sha, outcomes, *, scan_kind="initial", after_fix_of=None, created_at=None):
    root.mkdir(parents=True, exist_ok=True)
    convert = {"success": "completed", "failure": "failed", "cancelled": "cancelled", "skipped": "skipped"}
    statuses = {key: convert.get(value, value) for key, value in outcomes.items()}
    stage_file = read(root / "stage-status.json", {})
    statuses.update({key: convert.get(value, value) for key, value in stage_file.items()})
    batches = sorted((root / "remediation/fix_batches").glob("*.json"))
    if statuses.get("fix") == "failed" and not (root / "remediation/fixes.json").exists():
        (root / "remediation").mkdir(exist_ok=True)
        (root / "remediation/fixes.json").write_text(json.dumps([
            {"batch_id": read(path)["batch_id"], "batch_type": read(path).get("batch_type", "unknown"), "status": "not_available", "stage_status": "failed",
             "message": "Fix stage failed before recording this batch's outcome", "scanned_sha": sha}
            for path in batches], indent=2), encoding="utf-8")
    artifacts = {}
    scans = {kind: f"scan/{kind}.sarif.json" for kind in ("sast", "sca", "container")
             if (root / f"scan/{kind}.sarif.json").is_file()}
    if scans:
        artifacts["scan"] = scans
    for key, rel in (("findings", "findings/ranked_unified_findings.json"),
                     ("triage", "findings/ranked_findings.json"),
                     ("fixes", "remediation/fixes.json"), ("remediation", "remediation/prs.json"),
                     ("normalisation_audit", "findings/normalisation-audit.json"),
                     ("scan_status", "scan/scan-status.json")):
        if (root / rel).is_file():
            artifacts[key] = rel
    artifacts["fix_batches"] = [p.relative_to(root).as_posix() for p in sorted((root / "remediation/fix_batches").glob("*.json"))]
    validation = [p.relative_to(root).as_posix() for p in sorted((root / "validation").glob("*.json"))]
    artifacts["validation"] = validation
    if "validation/baseline.json" in validation:
        artifacts["baseline_validation"] = "validation/baseline.json"
        baseline = read(root / "validation/baseline.json")
        baseline.update(phase="baseline", tested_sha=baseline.get("commit_sha", sha))
        (root / "validation/baseline.json").write_text(json.dumps(baseline, indent=2), encoding="utf-8")
    fixes = read(root / "remediation/fixes.json")
    if fixes is not None:
        for fix in fixes:
            result = read(root / "validation" / (fix["batch_id"] + ".json"))
            if result:
                if result.get("tested_sha") != fix.get("candidate_sha"):
                    raise ValueError("Validation does not match the fix candidate commit")
                fix["validation_result"] = result["result"]
                fix["validation_path"] = f"validation/{fix['batch_id']}.json"
        (root / "remediation/fixes.json").write_text(json.dumps(fixes, indent=2), encoding="utf-8")
    findings = read(root / "findings/ranked_unified_findings.json")
    contract = read(SCHEMAS / "dashboard-contract-v0.1.json")
    triage = read(root / "findings/ranked_findings.json", [])
    batch_data = [read(path) for path in batches]
    for key, data in (("findings", findings), ("triage", triage), ("batches", batch_data)):
        if data is not None:
            Draft202012Validator(contract["properties"][key]).validate(data)
    if findings is not None:
        if any(f.get("scan_run_id") != run_id for f in findings + triage):
            raise ValueError("Findings are not associated with this run")
        ids = {f["finding_id"] for f in findings}
        triage_ids = {f["finding_id"] for f in triage}
        if not triage_ids.issubset(ids):
            raise ValueError("Triage references findings absent from the scan")
        for batch in batch_data:
            if batch.get("scan_run_id") != run_id or batch.get("commit_sha") != sha[:8]:
                raise ValueError("Batch does not match the scanned run and commit")
            if any(f["finding_id"] not in triage_ids for entry in batch["files_to_fix"] for f in entry["findings"]):
                raise ValueError("Batch references findings absent from triage")
    scan_status = read(root / "scan/scan-status.json")
    if scan_status and (scan_status.get("run_id") != run_id or scan_status.get("commit_sha") != sha):
        raise ValueError("Scan evidence does not match this run and commit")
    manifest = {"schema_version": "0.1", "app": app, "run_id": run_id, "commit_sha": sha,
                "branch": os.environ.get("GITHUB_REF_NAME", "local"),
                "workflow": os.environ.get("GITHUB_WORKFLOW", "local"),
                "created_at": created_at or (os.environ.get("RUN_CREATED_AT") if scan_kind == "initial" else None) or datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "workflow_url": f"https://github.com/{os.environ.get('GITHUB_REPOSITORY', 'local/local')}/actions/runs/{os.environ.get('GITHUB_RUN_ID', run_id)}",
                "stages": {key: statuses.get(key, "not_available") for key in ("scan", "normalise", "triage", "fix", "validate")},
                "baseline_status": statuses.get("baseline", "not_available"),
                "scan_kind": scan_kind, "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "1"),
                "artifacts": artifacts}
    if after_fix_of:
        manifest["after_fix_of"] = after_fix_of
    Draft202012Validator(read(SCHEMAS / "dashboard-run-manifest.json")).validate(manifest)
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", required=True)
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--outcomes", required=True)
    args = parser.parse_args()
    outcomes = json.loads(args.outcomes)
    root = args.output_dir / args.app / os.environ["GITHUB_RUN_ID"]
    root.mkdir(parents=True, exist_ok=True)
    for source in args.input_dir.iterdir():
        if source.name == "candidates":
            continue
        if source.is_dir():
            shutil.copytree(source, root / source.name, dirs_exist_ok=True)
        else:
            shutil.copyfile(source, root / source.name)
    # Candidate scan records are published independently, not mixed into the initial scan.
    candidates = args.input_dir / "candidates"
    if candidates.exists():
        for candidate in candidates.iterdir():
            metadata = read(candidate / "candidate.json")
            if not metadata:
                continue
            child_id = f"{os.environ['GITHUB_RUN_ID']}-after-fix-{candidate.name}"
            child = args.output_dir / args.app / child_id
            shutil.copytree(candidate, child, dirs_exist_ok=True)
            make_manifest(child, args.app, child_id, metadata["commit_sha"], metadata["outcomes"],
                          scan_kind="after_fix", after_fix_of=os.environ["GITHUB_RUN_ID"], created_at=metadata.get("scan_started_at"))
    make_manifest(root, args.app, os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_SHA"], outcomes)
