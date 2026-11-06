"""
gitops/post_fix_failure_issue.py -- when every file in a batch fails before commit
(status == "no_commits"), there's no PR to attach a warning to, so file a GitHub issue
instead.

Usage:
  python agent/agent_loop.py --batch-dir fix_batches --output-json prs.json
  python -m gitops.post_fix_failure_issue \\
      --prs-json prs.json --batch-dir fix_batches [--repo-dir .]   # dry run, prints each issue
      [--execute]                                                  # actually opens via gh

Only entries with status == "no_commits" are handled here. status == "error" (push
rejected, a transient gh failure) is a separate, infrastructure-level failure -- the CI
step is already red for those, so they're skipped rather than getting a duplicate issue.

A container batch held back with nothing safe to change gets no issue of its own: it is in the
app's container report, which is updated every run (gitops/post_container_report.py).

Dedup: searches for an existing open issue titled with this batch_id before creating one,
so a repeated run doesn't spam duplicates. batch_id is keyed to the scan commit, so the
same underlying vulnerability rescanned at a new commit still gets a new issue -- dedup by
rule_ids/files across scans would be a finer follow-up if that becomes noisy.
"""

import argparse
import json
import sys
from pathlib import Path

from .git_gh_ops import GitOpError, find_open_issue, open_issue


def _finding_rows(files_to_fix: list[dict]) -> list[str]:
    rows = []
    for ff in files_to_fix:
        for f in ff.get("findings", []):
            ident = f.get("identifiers") or {}
            ref = ident.get("cve") or ident.get("cwe") or ident.get("rule_id") or "-"
            rows.append(f"| `{ff['file']}` | {f.get('title', '-')} ({ref}) | {f.get('severity', '-')} |")
    return rows


def format_issue_title(batch_id: str, entry: dict | None = None) -> str:
    if ((entry or {}).get("generation") or {}).get("method") == "rag":  # agent/safe_upgrades.py
        return f"ASVA: vulnerability confirmed, no safe fix, needs a person -- batch {batch_id}"
    return f"ASVA: vulnerability confirmed, automated fix failed -- batch {batch_id}"


def format_issue_body(batch: dict, entry: dict) -> str:
    batch_id = batch.get("batch_id", entry.get("batch_id", "-"))
    generation = entry.get("generation") or {}
    held_back = generation.get("method") == "rag"  # agent/safe_upgrades.py: nothing safe to change
    lines = [
        "## ASVA automated security remediation -- "
        + ("held back, needs a person" if held_back else "fix failed before commit"),
        "",
        ("The scanner confirmed the vulnerabilities below. No fix was attempted: nothing safe can "
         "be changed without a major version change, which can break the app. No PR was opened. "
         "The vulnerabilities are still present and need a person to decide."
         if held_back else
         "The scanner confirmed the vulnerabilities below. The automated fix was attempted "
         "and rejected before commit -- no PR was opened. The vulnerabilities are still "
         "present and need a manual fix."),
        "",
        f"- **Repo / scan commit:** `{batch.get('repo_name', 'repo')}` @ "
        f"`{str(batch.get('commit_sha', '-'))[:8]}`",
        f"- **Batch:** `{batch_id}` ({batch.get('batch_type', 'security')})",
        "",
        "### Findings",
        "| File | Finding | Severity |",
        "|---|---|---|",
        *_finding_rows(batch.get("files_to_fix", [])),
    ]

    if entry.get("blocked"):
        lines += [
            "",
            "### :no_entry: Withheld by the secrets gate",
            *[f"- `{b['path']}`: {b['reason']}" for b in entry["blocked"]],
        ]
    if entry.get("failed"):
        lines += [
            "",
            "### :pause_button: Held back" if held_back else "### :x: Rejected before commit",
            *[f"- `{f['path']}`: {f['reason']}" for f in entry["failed"]],
        ]
    if generation.get("rag_text"):
        lines += ["", "### From the RAG (security context service)", "", generation["rag_text"]]

    lines += [
        "",
        "_Pipeline: Build -> Scan -> Triage -> Fix ("
        + ("held back here" if held_back else "failed here, before commit")
        + ") -> a human writes the real fix. ASVA never auto-merges; this issue exists because "
        "there wasn't even a PR to attach a warning to._",
    ]
    return "\n".join(lines) + "\n"


def _load_batch(batch_dir: str, batch_id: str) -> dict:
    path = Path(batch_dir) / f"{batch_id}.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"batch_id": batch_id}


def process_no_commits_entries(
    entries: list[dict], batch_dir: str, *, repo_dir: str = ".", execute: bool = False
) -> int:
    """Filed-issue pass over one agent_loop --output-json list. Returns a process exit code
    (nonzero only if an issue that should have been opened failed to open -- an existing
    open issue for the same batch, or a dry run, are both a normal, successful no-op)."""
    no_commits = [e for e in entries if e.get("status") == "no_commits"]

    if not no_commits:
        print("No no_commits batches in this run -- nothing to do.")
        return 0

    exit_code = 0
    for entry in no_commits:
        batch_id = entry.get("batch_id")
        batch = _load_batch(batch_dir, batch_id)

        if batch.get("batch_type") == "container" and ((entry.get("generation") or {}).get("method") == "rag"
                                                       or batch.get("remediation_method") == "base_image"):
            print(f"Batch {batch_id} was held back: see the container report (its issue, or this run's log on a test branch).")
            continue

        title = format_issue_title(batch_id, entry)
        body = format_issue_body(batch, entry)

        print(f"=== {title} ===")
        print(body)

        if not execute:
            print("[DRY RUN] Not created. Re-run with --execute to open the issue.")
            continue

        existing = find_open_issue(f"{batch_id} in:title", repo_dir=repo_dir)
        if existing:
            print(f"[SKIP] Issue #{existing} is already open for batch {batch_id}.")
            continue

        try:
            url = open_issue(title, body, repo_dir=repo_dir)
            print(f"Opened: {url}")
        except GitOpError as e:
            print(f"[ERROR] Could not open issue for batch {batch_id}: {e}")
            exit_code = 1

    return exit_code


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Open a GitHub issue for each no_commits batch via gh."
    )
    parser.add_argument("--prs-json", required=True, metavar="FILE",
                         help="Output of agent/agent_loop.py --output-json.")
    parser.add_argument("--batch-dir", required=True, metavar="DIR",
                         help="Directory of fix_batches/<batch_id>.json files.")
    parser.add_argument("--repo-dir", default=".", metavar="DIR")
    parser.add_argument("--execute", action="store_true",
                         help="Actually open issues via gh. Without this, prints a dry run.")
    args = parser.parse_args()

    prs_path = Path(args.prs_json)
    if not prs_path.exists():
        # The agent can abort before writing prs.json at all (e.g. an LLM outage exits
        # before any fix is attempted). No batch got far enough to fail before commit,
        # so there is genuinely nothing to report -- distinct from a prs.json full of
        # no_commits entries, which is exactly what this tool is for.
        print(f"{prs_path} does not exist -- the agent never attempted any fixes, "
              "so there are no per-batch failures to report.")
        return

    entries = json.loads(prs_path.read_text(encoding="utf-8"))
    exit_code = process_no_commits_entries(
        entries, args.batch_dir, repo_dir=args.repo_dir, execute=args.execute
    )
    if exit_code:
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
