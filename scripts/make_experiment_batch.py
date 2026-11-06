#!/usr/bin/env python3
"""Build a SAST batch for the 3.6 attention-dilution experiment.

Task 6 compares remediation as more vulnerable code goes into one prompt. Triage only keeps
critical/high findings, which for NodeGoat leaves 4 files, so this script builds the batch
straight from the SAST scan instead:

  1. normalise the SARIF scan with the shipped normaliser,
  2. keep app-code findings of every severity (no libraries such as node_modules/ or
     site-packages/, no test files, and not the rules triage never auto-fixes),
  3. group them by file, most findings first, up to --max-files files.

Works for any target app: the app is ASVA_FIX_PATH_PREFIX (or --path-prefix), and the scan
defaults to samples/scans/<app>-sast.sarif.json, e.g. samples/scans/nodegoat-sast.sarif.json or
samples/scans/pygoat-sast.sarif.json (download PyGoat's from the "PyGoat - Scan" workflow artifact).

Only files that have findings go into the batch. --max-files is a cap, not a target: if the
app has fewer vulnerable files, the batch is smaller (NodeGoat has about 9). Run the SAME
batch at different --files-per-prompt values so the vulnerable files are identical in every
condition and only the amount of code per prompt changes.

  python scripts/make_experiment_batch.py --max-files 20 --out-dir eval_results/nodegoat/batches/task6
  python scripts/make_experiment_batch.py --path-prefix target-apps/PyGoat --max-files 20
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from gitops import config  # noqa: E402  (loads .env, for ASVA_FIX_PATH_PREFIX)
from agent.repo_context import _is_library  # noqa: E402
from normaliser.normaliser import deduplicate, process_sarif_file  # noqa: E402
from triage.triage import NEVER_FIX_RULES, get_fix_type, is_test_file  # noqa: E402


def default_scan(path_prefix: str) -> str:
    """samples/scans/<app>-sast.sarif.json for the app folder the prefix names."""
    app = Path(path_prefix.strip().strip("/")).name.lower() or "nodegoat"
    return f"samples/scans/{app}-sast.sarif.json"


def strip_app_prefix(path: str, prefix: str) -> str:
    """Scanners run from the repo root report target-apps/<App>/x; batches use app paths."""
    path = path.replace("\\", "/")
    prefix = prefix.strip().strip("/")
    return path[len(prefix) + 1:] if prefix and path.startswith(prefix + "/") else path


def vulnerable_files(scan: Path, prefix: str = "") -> list[tuple[str, list[dict]]]:
    """Usable app-code SAST findings grouped by file, most findings first."""
    findings = deduplicate(process_sarif_file(scan))
    by_file: dict[str, list[dict]] = {}
    for f in findings:
        path = strip_app_prefix((f.get("location") or {}).get("file") or "", prefix)
        if f.get("location"):
            f["location"]["file"] = path
        for step in f.get("code_flow") or []:
            if step.get("file"):
                step["file"] = strip_app_prefix(step["file"], prefix)
        rule = (f.get("identifiers") or {}).get("rule_id")
        if (f.get("finding_type") != "sast" or f.get("is_node_modules")
                or _is_library(path) or is_test_file(f)
                or rule in NEVER_FIX_RULES):
            continue
        f["fix_type"] = get_fix_type(f)
        by_file.setdefault(path, []).append(f)
    return sorted(by_file.items(), key=lambda kv: (-len(kv[1]), kv[0]))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--max-files", type=int, default=20,
                        help="Upper limit on files in the batch (default 20)")
    parser.add_argument("--scan", default=None,
                        help="SAST SARIF file. Default: samples/scans/<app>-sast.sarif.json")
    parser.add_argument("--repo-dir", default=str(REPO_ROOT))
    parser.add_argument("--path-prefix", default=config.FIX_PATH_PREFIX,
                        help="Default: ASVA_FIX_PATH_PREFIX from the environment / .env")
    parser.add_argument("--out-dir", default=str(REPO_ROOT / "eval_results" / "batches"))
    args = parser.parse_args()

    prefix = args.path_prefix.strip().strip("/")
    app_root = Path(args.repo_dir) / prefix if prefix else Path(args.repo_dir)
    scan_arg = args.scan or default_scan(prefix)
    scan = Path(scan_arg) if Path(scan_arg).is_absolute() else Path(args.repo_dir) / scan_arg
    if not scan.exists():
        sys.exit(f"[ERROR] SAST scan not found: {scan}. Pass --scan, or save the app's Snyk Code "
                 f"SARIF there (for PyGoat: the sast.sarif.json in the 'PyGoat - Scan' artifact).")

    chosen = [(p, fs) for p, fs in vulnerable_files(scan, prefix) if (app_root / p).exists()]
    chosen = chosen[: args.max_files]
    if not chosen:
        sys.exit("[ERROR] no app-code SAST findings found for files on disk")

    files_to_fix = [{
        "file": path, "fix_type": "code_change", "finding_type": "sast",
        "findings": findings, "finding_count": len(findings),
    } for path, findings in chosen]

    batch_id = "asva_exp_sast"
    now = datetime.now(timezone.utc)
    batch = {
        "batch_id": batch_id,
        "batch_type": "sast",
        "repo_name": "asva",
        "commit_sha": "offline0",
        "scan_run_id": f"experiment-{now.strftime('%Y%m%d%H%M%S')}",
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_files": len(files_to_fix),
        "total_findings": sum(f["finding_count"] for f in files_to_fix),
        "experiment": {"max_files": args.max_files, "scan": str(scan_arg), "app": prefix},
        "files_to_fix": files_to_fix,
    }

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{batch_id}.json"
    out_path.write_text(json.dumps(batch, indent=2), encoding="utf-8")
    print(f"wrote {out_path}")
    print(f"  {len(files_to_fix)} file(s), {batch['total_findings']} finding(s)")
    if len(files_to_fix) < args.max_files:
        print(f"  [NOTE] only {len(files_to_fix)} files have findings, below the limit of "
              f"{args.max_files}. Any --files-per-prompt of {len(files_to_fix)} or more sends "
              f"all of them in one prompt, so those settings give identical runs.")
    for f in files_to_fix:
        print(f"    {f['finding_count']:>2}  {f['file']}")


if __name__ == "__main__":
    main()
