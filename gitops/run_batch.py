"""
gitops/run_batch.py -- drive one scan cycle through the secrets gate + git/gh GitOps.

A "scan cycle" is every batch triage.py produced for one scan (same repo + commit_sha).
This entry point loads them and submits ONE pull request PER BATCH, one commit per fixed
file:

    1 batch  ->  1 fix branch (fix/<batch_id>)  ->  1 commit per file  ->  1 PR
    1 scan cycle (N batches)  ->  N PRs

The real agent loop calls gitops.git_gh_ops.submit_scan_cycle directly, passing
LLM-produced file contents plus its own test_fn and refix_fn for the
fix -> test -> retry loop. This runner does not test; it exists to exercise the GitOps +
secrets-gate path on its own.

Usage:
  python -m gitops.run_batch --batch-dir fix_batches                    # safe dry run
  python -m gitops.run_batch --batch-dir fix_batches --fixed-dir <dir>  # with fixed contents
  python -m gitops.run_batch --batch-dir fix_batches --fixed-dir <dir> --execute
"""

import argparse
import json
import sys
from pathlib import Path

from . import config
from .git_gh_ops import (
    batch_branch_name,
    batch_pr_body,
    batch_pr_title,
    file_commit_message,
    gate_file,
    iter_file_fixes,
    repo_path,
    submit_scan_cycle,
)


def _load_files(batch: dict, fixed_dir: str | None, repo_dir: str) -> list[dict]:
    """Build [{path, content}] for a batch. With --fixed-dir read the proposed (LLM-fixed)
    content; otherwise fall back to the file's current content (exercises wiring only)."""
    files = []
    for entry in batch.get("files_to_fix", []):
        path = entry["file"]
        src = Path(fixed_dir) / path if fixed_dir else Path(repo_dir) / repo_path(path)
        content = src.read_text(encoding="utf-8") if src.exists() else ""
        files.append({"path": path, "content": content})
    return files


def _select_batches(batch_dir: str, batch_files: list[str], sha: str | None) -> list[dict]:
    paths = [Path(p) for p in batch_files] if batch_files else sorted(Path(batch_dir).glob("*.json"))
    batches = [json.loads(p.read_text(encoding="utf-8")) for p in paths]
    if sha:
        batches = [b for b in batches if str(b.get("commit_sha", ""))[:8] == sha[:8]]
    if not batches:
        sys.exit("No batch files found for the given selection.")
    shas = {str(b.get("commit_sha", ""))[:8] for b in batches}
    if len(shas) > 1:
        sys.exit(f"Multiple scan cycles found ({sorted(shas)}); pass --sha to choose one.")
    return batches


def main() -> None:
    parser = argparse.ArgumentParser(description="Run one ASVA scan cycle (gate + git/gh, 1 PR).")
    parser.add_argument("--batch-dir", default="fix_batches", help="Directory of batch JSON files.")
    parser.add_argument("--batch", action="append", default=[], help="Explicit batch file(s); repeatable.")
    parser.add_argument("--sha", default=None, help="Filter to one scan cycle by short commit SHA.")
    parser.add_argument("--fixed-dir", default=None, help="Directory of fixed file contents.")
    parser.add_argument("--base", default=None, help=f"Base branch (default: {config.GITHUB_BASE_BRANCH}).")
    parser.add_argument("--repo-dir", default=".", help="Path to the repo working tree.")
    parser.add_argument("--execute", action="store_true", help="Actually branch/commit/push/PR.")
    args = parser.parse_args()

    batches = _select_batches(args.batch_dir, args.batch, args.sha)
    base = args.base or config.GITHUB_BASE_BRANCH
    cycle = [{"batch": b, "files": _load_files(b, args.fixed_dir, args.repo_dir)} for b in batches]
    sha = str(batches[0].get("commit_sha", ""))[:8]

    print("=" * 70)
    print(f"ASVA scan cycle @ {sha}  ->  base {base}  ->  1 PR per batch")
    print(f"  batches ({len(batches)}): {[b['batch_id'] for b in batches]}")
    print("=" * 70)

    if args.execute:
        result = submit_scan_cycle(cycle, base_branch=base, repo_dir=args.repo_dir)
        print(f"\nstatus : {result['status']}")
        print(f"message: {result['message']}")
        for r in result.get("prs", []):
            line = f"  [{r['batch_id']}] {r['status']}"
            if r.get("pr_url"):
                line += f" -> {r['pr_url']}"
            print(line)
            for b in r.get("blocked", []):
                print(f"      blocked: {b['path']}: {b['reason']}")
        sys.exit(0 if result["status"] == "prs_opened" else 1)

    # --- Dry run: per batch, gate each file and print the PR plan (one commit per file) ---
    any_pr = False
    for c in cycle:
        batch = c["batch"]
        print(f"\n[dry run] batch {batch['batch_id']}  ->  1 fix branch: "
              f"{batch_branch_name(batch)} (this runner does not test)")
        committed, blocked = [], []
        already_there: dict[str, str] = {}
        for ff in iter_file_fixes([c]):
            clean, reason = gate_file(ff["path"], ff["content"], args.repo_dir, already_there)
            if clean:
                committed.append(ff)
                print(f"  [GATE] {ff['path']}: clean  ->  commit: {file_commit_message(ff)}")
            else:
                blocked.append({"path": ff["path"], "reason": reason})
                print(f"  [GATE] {ff['path']}: withheld ({reason})")

        if not committed:
            print("  [dry run] no file passed the gate → this batch would open no PR.")
            continue

        any_pr = True
        print(f"  [dry run] would make {len(committed)} commit(s) and open ONE PR:")
        print(f"    title: {batch_pr_title(batch, committed)}")
        print("    body:")
        for bodyline in batch_pr_body(batch, committed, blocked, [], already_there).splitlines():
            print(f"      {bodyline}")

    if not any_pr:
        print("\n[dry run] no batch passed the gate → no PRs would be created.")
        sys.exit(1)
    print("\n[dry run] no changes made. Re-run with --fixed-dir <dir> --execute to submit.")


if __name__ == "__main__":
    main()
