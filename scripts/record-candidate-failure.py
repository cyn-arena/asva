"""Retain a failed candidate record when setup or validation could not finish."""
import argparse
import datetime
import json
from pathlib import Path


def record(app, batch_id, sha, root=Path("asva-results")):
    folder = root / "candidates" / batch_id
    if (folder / "candidate.json").exists():
        return
    path = root / "validation" / (batch_id + ".json")
    report = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {
        "app": app, "batch_id": batch_id, "commit_sha": sha, "tested_sha": sha,
        "app_started": False, "checks": [],
        "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "misuse_tests": "not_available",
    }
    report["result"] = "failed"
    report["phase"] = "post_fix"
    report["checks"].append({"name": "candidate workflow completed", "kind": "pipeline",
                             "status": "failed", "detail": "Setup or candidate checking did not produce a complete result; inspect the Actions log."})
    path.parent.mkdir(parents=True, exist_ok=True)
    folder.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    (folder / "validation").mkdir(exist_ok=True)
    (folder / "validation" / path.name).write_text(json.dumps(report, indent=2), encoding="utf-8")
    (folder / "candidate.json").write_text(json.dumps({"commit_sha": sha, "outcomes": {
        "scan": "failure", "normalise": "skipped", "validate": "failure"}}, indent=2), encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", required=True)
    parser.add_argument("--batch-id", required=True)
    parser.add_argument("--sha", required=True)
    args = parser.parse_args()
    record(args.app, args.batch_id, args.sha)
