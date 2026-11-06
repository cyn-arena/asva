#!/usr/bin/env python3
"""Build a logic_change fix batch without running the app (ITP2 3.6 evaluation).

The fix_batches/ folder only ever holds scanner batches; logic batches normally come from a
misuse-case test failing against a running NodeGoat. This script produces the same batch
offline by feeding a capture record straight into the shipped
agent.browser_failure_batch.build_batch, so 3.6 can be exercised and compared in dry runs.

Two modes:

  From an annotated misuse-case test (files from its "# @a" lines, detail from the test):
    python scripts/make_logic_batch.py --test test_idor_allocations

  Synthetic batch of any files (for the batch-size sweep):
    python scripts/make_logic_batch.py --name sweep_5 --detail "..." \\
        --files app/routes/allocations.js app/data/allocations-dao.js ...

Writes fix_batches/<batch_id>.json (override with --out-dir) and prints the path.
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from agent.browser_failure_batch import build_batch  # noqa: E402
from agent.failure_capture import build_capture_record  # noqa: E402
from agent.test_annotations import parse_annotated_files  # noqa: E402

DEFAULT_TEST_FILE = "tests/e2e/api/test_misuse_cases.py"


def detail_from_test(source: str, test_name: str) -> str:
    """The `detail = "..."` string the test passes to capture_if_vulnerable, so the batch
    matches what a real capture would produce. Falls back to the test's docstring."""
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == test_name:
            for sub in ast.walk(node):
                if (isinstance(sub, ast.Assign)
                        and any(isinstance(t, ast.Name) and t.id == "detail" for t in sub.targets)
                        and isinstance(sub.value, ast.Constant) and isinstance(sub.value.value, str)):
                    return sub.value.value
            return ast.get_docstring(node) or ""
    return ""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--test", help="Annotated misuse-case test name, e.g. test_idor_allocations")
    parser.add_argument("--test-file", default=DEFAULT_TEST_FILE, help=f"Default: {DEFAULT_TEST_FILE}")
    parser.add_argument("--files", nargs="+", help="Synthetic mode: app-relative files to include")
    parser.add_argument("--name", help="Synthetic mode: batch name suffix (e.g. sweep_5)")
    parser.add_argument("--detail", help="Vulnerability description (overrides the test's)")
    parser.add_argument("--repo-name", default="asva")
    parser.add_argument("--commit-sha", default="offline0")
    parser.add_argument("--out-dir", default=str(REPO_ROOT / "fix_batches"))
    args = parser.parse_args()

    if args.test:
        test_file = REPO_ROOT / args.test_file
        source = test_file.read_text(encoding="utf-8")
        files = parse_annotated_files(source).get(args.test)
        if not files:
            sys.exit(f"[ERROR] {args.test} has no '# @a' annotations in {args.test_file}")
        detail = args.detail or detail_from_test(source, args.test)
        nodeid = f"{args.test_file}::{args.test}"
    elif args.files and args.name:
        files = args.files
        if not args.detail:
            sys.exit("[ERROR] synthetic mode needs --detail")
        detail = args.detail
        nodeid = f"offline::{args.name}"
    else:
        sys.exit("[ERROR] give --test, or --files with --name and --detail")

    record = build_capture_record(nodeid, files, detail)
    batch = build_batch(record, args.repo_name, args.commit_sha)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{batch['batch_id']}.json"
    out_path.write_text(json.dumps(batch, indent=2), encoding="utf-8")
    print(f"wrote {out_path}  ({len(files)} file(s): {', '.join(files)})")


if __name__ == "__main__":
    main()
