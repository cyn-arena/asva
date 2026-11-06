"""Bound an explicit AI run and retain every batch's outcome, including early failures."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


def gh(*args):
    return json.loads(subprocess.check_output(["gh", *args], text=True, encoding="utf-8"))


def select_batches(batches, limit):
    """Try one batch of each available type before additional batches of that type."""
    first, remaining, seen = [], [], set()
    for path in batches:
        kind = json.loads(path.read_text(encoding="utf-8")).get("batch_type", "unknown")
        if kind in seen:
            remaining.append(path)
        else:
            seen.add(kind)
            first.append(path)
    return (first + remaining)[:limit]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", required=True)
    parser.add_argument("--batch-dir", type=Path, required=True)
    parser.add_argument("--max-batches", type=int, default=1)
    args = parser.parse_args()
    if not 1 <= args.max_batches <= 10:
        parser.error("max-batches must be between 1 and 10")
    order = {"sast": 0, "sca": 1, "container": 2}
    batches = sorted(args.batch_dir.glob("*.json"), key=lambda path: (
        order.get(json.loads(path.read_text(encoding="utf-8")).get("batch_type"), 3), path.name))
    selected = select_batches(batches, args.max_batches)
    destination = Path("asva-results/remediation")
    destination.mkdir(parents=True, exist_ok=True)
    raw = destination / "agent-results.json"
    code = 0
    if selected:
        code = subprocess.run([sys.executable, "agent/agent_loop.py", "--batch-dir", str(args.batch_dir),
                               *[arg for path in selected for arg in ("--batch", str(path))], "--base-branch", os.environ["GITHUB_REF_NAME"],
                               "--repo-dir", ".", "--output-json", str(raw),
                               "--import-map-dir", str(destination / "import_maps")]).returncode
    outcomes = json.loads(raw.read_text(encoding="utf-8")) if raw.exists() else []
    by_id = {row["batch_id"]: row for row in outcomes}
    rows, prs, matrix = [], [], []
    for path in batches:
        batch = json.loads(path.read_text(encoding="utf-8"))
        row = by_id.get(batch["batch_id"], {
            "batch_id": batch["batch_id"], "status": "failed" if path in selected else "not_attempted",
            "message": f"Agent exited {code} before producing this result" if path in selected else "Outside this run's batch limit",
        })
        row.update(batch_type=batch.get("batch_type", "unknown"), app=args.app, scan_run_id=os.environ["GITHUB_RUN_ID"], scanned_sha=os.environ["GITHUB_SHA"])
        if row.get("pr_url"):
            try:
                pr = gh("pr", "view", row["pr_url"], "--json", "number,title,url,state,isDraft,headRefName,headRefOid,body")
                repo = os.environ["GITHUB_REPOSITORY"]
                files = gh("api", f"repos/{repo}/pulls/{pr['number']}/files?per_page=100")
                comments = gh("api", f"repos/{repo}/issues/{pr['number']}/comments?per_page=100")
                prefix = f"target-apps/{'PyGoat' if args.app == 'pygoat' else 'NodeGoat'}/"
                detail = {"number": pr["number"], "title": pr["title"], "html_url": pr["url"],
                          "state": pr["state"], "draft": pr["isDraft"], "head_branch": pr["headRefName"],
                          "body": pr["body"], "batch_type": batch["batch_type"], "source_note": "Fix for this exact scanned revision",
                          "files": [{"filename": f["filename"], "path": f["filename"].removeprefix(prefix),
                                     "additions": f["additions"], "deletions": f["deletions"], "patch": f.get("patch")} for f in files],
                          "comments": [{"author": c["user"]["login"], "created_at": c["created_at"], "body": c["body"]} for c in comments]}
                row.update(candidate_sha=pr["headRefOid"], **detail)
                prs.append(detail)
                matrix.append({"batch_id": batch["batch_id"], "branch": pr["headRefName"],
                               "sha": pr["headRefOid"], "pr_url": pr["url"]})
            except subprocess.CalledProcessError:
                row["evidence_error"] = "Could not fetch PR details; preserve the agent result and inspect GitHub"
                code = code or 1
        rows.append(row)
        if row["status"] in ("failed", "blocked", "no_commits", "error") or row.get("failed") or row.get("blocked"):
            code = code or 1
    (destination / "fixes.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    (destination / "prs.json").write_text(json.dumps(prs, indent=2), encoding="utf-8")
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
            output.write("prs=" + json.dumps(matrix, separators=(",", ":")) + "\n")
    return code


if __name__ == "__main__":
    sys.exit(main())
