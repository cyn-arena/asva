"""Convert existing NodeGoat JUnit evidence to structured validation JSON."""
import argparse
import datetime
import json
from pathlib import Path
import xml.etree.ElementTree as ET


def convert(paths, app, sha, batch_id=None, app_started=False):
    checks = [{"name": "app starts up", "kind": "app_start", "status": "passed" if app_started else "failed",
               "detail": None if app_started else "App did not become ready"}]
    for kind, path in paths:
        if not path.is_file():
            continue
        for case in ET.parse(path).getroot().iter("testcase"):
            failure = case.find("failure")
            if failure is None:
                failure = case.find("error")
            skipped = case.find("skipped")
            checks.append({"name": case.get("name"), "kind": kind,
                           "status": "failed" if failure is not None else "skipped" if skipped is not None else "passed",
                           "detail": failure.get("message", "") if failure is not None else skipped.get("message") if skipped is not None else None})
    return {"app": app, "commit_sha": sha, "tested_sha": sha, "batch_id": batch_id,
            "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "app_started": app_started,
            "result": "passed" if app_started and len(checks) > 1 and all(c["status"] == "passed" for c in checks) else "failed",
            "misuse_tests": "completed" if any(c["kind"] == "misuse" for c in checks) else "not_available",
            "checks": checks}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--batch-id")
    parser.add_argument("--app-started", choices=("true", "false"), default="false")
    parser.add_argument("--smoke", type=Path, default=Path("smoke.xml"))
    parser.add_argument("--misuse", type=Path, default=Path("misuse.xml"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = convert([("smoke", args.smoke), ("misuse", args.misuse)], args.app, args.sha, args.batch_id, args.app_started == "true")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
