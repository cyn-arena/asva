"""Combine the parallel fix jobs' outputs into the one fix output the later jobs read.

Each fix job (one per fix batch, see nodegoat-fix.yml and pygoat-fix.yml) saves its own prs.json,
fixes.json, stage-status.json, batch files and import maps. This rebuilds the single
<app>-fix-output that pr-check, the rescan, the PR summary and the dashboard package read, as if
one job had fixed every batch.

  python scripts/combine_fix_parts.py --prep DIR --parts DIR --output DIR

--prep is the triage output (findings/ and fix_batches/), --parts holds one folder per fix job.
Writes the combined files to --output and, in CI, the PR matrix (`prs`) and the counts
(`planned`, `opened`) to $GITHUB_OUTPUT.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
from pathlib import Path


def _read(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _copy_all(source: Path, pattern: str, target: Path) -> None:
    for path in sorted(source.glob(pattern)):
        shutil.copy2(path, target / path.name)


def combine(prep: Path, parts: Path, output: Path) -> tuple[list[dict], int]:
    """Write the combined output. Returns (PR matrix, number of batches triage planned)."""
    for name in ("findings", "fix_batches", "import_maps"):
        (output / name).mkdir(parents=True, exist_ok=True)
    _copy_all(prep / "findings", "*.json", output / "findings")
    planned = {}
    for path in sorted((prep / "fix_batches").glob("*.json")):
        batch = _read(path, {})
        planned[batch.get("batch_id", path.stem)] = batch.get("batch_type")
    _copy_all(prep / "fix_batches", "*.json", output / "fix_batches")

    prs, fixes, errors, ran = [], [], [], False
    for part in sorted(p for p in parts.iterdir() if p.is_dir()) if parts.is_dir() else []:
        ran = True
        prs += _read(part / "prs.json", [])
        fixes += _read(part / "fixes.json", [])
        errors += _read(part / "stage-status.json", {}).get("evidence_errors") or []
        # After triage's copies: the agent adds to a batch file (what the scan before the PR found)
        # and writes new ones (the major-version dependency batch).
        _copy_all(part / "fix_batches", "*.json", output / "fix_batches")
        _copy_all(part / "import_maps", "*.html", output / "import_maps")

    # A fix job that crashed before saving anything still shows, as dashboard_evidence does.
    done = {row.get("batch_id") for row in fixes}
    for batch_id, batch_type in planned.items():
        if batch_id not in done:
            fixes.append({"batch_id": batch_id, "batch_type": batch_type, "status": "error",
                          "message": "The fix job for this batch produced no result",
                          "branch": None, "pr_url": None, "pr_number": None, "title": "", "body": "",
                          "files": []})
            errors.append(batch_id)

    matrix = [{"batch_id": row["batch_id"], "branch": row["branch"], "sha": row["candidate_sha"],
               "pr_url": row["pr_url"], "status": "pr_opened"}
              for row in fixes
              if row.get("status") == "pr_opened" and row.get("pr_url") and row.get("candidate_sha")]
    status = "success" if matrix else "failure" if ran or planned else "skipped"
    (output / "prs.json").write_text(json.dumps(prs, indent=2), encoding="utf-8")
    (output / "fixes.json").write_text(json.dumps(fixes, indent=2), encoding="utf-8")
    (output / "stage-status.json").write_text(json.dumps({
        "normalise": os.environ.get("NORMALISE_RESULT", "skipped"),
        "triage": os.environ.get("TRIAGE_RESULT", "skipped"),
        "fix": status, "evidence_errors": errors}, indent=2), encoding="utf-8")
    return matrix, len(planned)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prep", type=Path, required=True)
    parser.add_argument("--parts", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    matrix, planned = combine(args.prep, args.parts, args.output)
    print(f"{planned} batch(es), {len(matrix)} fix candidate(s): " + ", ".join(p["batch_id"] for p in matrix))
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as out:
            out.write("prs=" + json.dumps(matrix, separators=(",", ":")) + "\n")
            out.write(f"planned={planned}\nopened={len(matrix)}\n")


if __name__ == "__main__":
    main()
