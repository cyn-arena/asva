#!/usr/bin/env python3
"""Print the exact fix prompt(s) the agent would send for a batch -- no LLM call, no tokens.

Makes 3.1 and 3.6 inspectable: read the real prompt instead of a description of it.

  # 3.1: what repo-aware context adds to one file's prompt (diff without -> with)
  python scripts/preview_fix_prompt.py --batch-file fix_batches/asva_sast_bf49b76a_1.json \\
      --file app/routes/profile.js --diff

  # 3.6: the local (pass 1) and integration (pass 2) prompts, 10 files per prompt
  python scripts/preview_fix_prompt.py --batch-file eval_results/batches/task6/asva_exp_sast.json \\
      --passes 2 --files-per-prompt 10 --summary

With --passes 2 no pass-1 result exists yet, so the pass-2 prompt is shown with each file's
ORIGINAL content standing in for its pass-1 result. It shows the prompt's shape and size,
not a real integration input.
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# agent_loop imports the LLM client, which reads these at import time. Nothing is sent.
os.environ.setdefault("OLLAMA_HOST", "http://localhost:11434")
os.environ.setdefault("OLLAMA_API_KEY", "preview-only")
os.environ.setdefault("OLLAMA_MODEL", "preview-only")

from agent import agent_loop  # noqa: E402
from gitops import config  # noqa: E402
from gitops.git_gh_ops import repo_path  # noqa: E402


def _rule(title: str) -> str:
    return f"\n{'=' * 20} {title} {'=' * max(0, 58 - len(title))}\n"


def _diff(a: str, b: str, from_label: str, to_label: str) -> None:
    print(f"prompt chars: {len(a)} -> {len(b)} ({len(b) - len(a):+d})")
    sys.stdout.writelines(difflib.unified_diff(
        a.splitlines(keepends=True), b.splitlines(keepends=True),
        fromfile=from_label, tofile=to_label,
    ))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--batch-file", required=True)
    parser.add_argument("--file", help="Only this app-relative file (default: every file)")
    parser.add_argument("--repo-dir", default=str(REPO_ROOT))
    parser.add_argument("--path-prefix", default=None,
                        help="Override ASVA_FIX_PATH_PREFIX, e.g. target-apps/NodeGoat")
    parser.add_argument("--no-repo-context", action="store_true")
    parser.add_argument("--passes", type=int, choices=(1, 2), default=1)
    parser.add_argument("--files-per-prompt", type=int, default=1)
    parser.add_argument("--diff", action="store_true",
                        help="--passes 1: without -> with context. --passes 2: pass 1 -> pass 2.")
    parser.add_argument("--summary", action="store_true", help="Only print prompt sizes")
    args = parser.parse_args()

    if args.path_prefix is not None:
        config.FIX_PATH_PREFIX = args.path_prefix.strip().strip("/")

    batch = json.loads(Path(args.batch_file).read_text(encoding="utf-8"))
    batch_type = batch.get("batch_type", "unknown")
    use_ctx = agent_loop.repo_context_enabled(not args.no_repo_context)
    index = agent_loop.load_repo_index(args.repo_dir) if use_ctx else None

    entries = []
    for fe in batch.get("files_to_fix", []):
        if args.file and fe["file"] != args.file:
            continue
        disk = Path(args.repo_dir) / repo_path(fe["file"])
        if not disk.exists():
            print(f"[WARN] {disk} not found — skipping {fe['file']}")
            continue
        entries.append({
            "path": fe["file"], "content": disk.read_text(encoding="utf-8"),
            "findings": fe.get("findings", []),
            "fix_type": "logic_change" if batch_type == "logic" else fe["fix_type"],
        })
    if not entries:
        sys.exit(f"[ERROR] no matching file on disk for {args.batch_file}")

    contexts = {e["path"]: agent_loop.file_fix_context(e["path"], e["fix_type"], index, e["findings"])
                for e in entries}
    groups = agent_loop.make_prompt_groups(entries, batch_type, args.files_per_prompt)

    for n, group in enumerate(groups, start=1):
        label = f"prompt {n}/{len(groups)}: {len(group)} file(s)" + (
            f" ({group[0]['path']})" if len(group) == 1 else "")
        no_ctx = agent_loop.build_pass_prompt(group, None, second_pass=False)
        if args.passes == 1:
            with_ctx = agent_loop.build_pass_prompt(group, contexts, second_pass=False)
            shown = with_ctx if use_ctx else no_ctx
            print(_rule(label))
            if args.summary:
                print(f"chars: {len(shown)} (without context: {len(no_ctx)})")
            elif args.diff:
                _diff(no_ctx, with_ctx, "without repo context", "with repo context")
            else:
                print(shown)
            continue

        group_ctx = {e["path"]: contexts.get(e["path"]) for e in group}
        has_ctx = any(group_ctx.values())
        second = agent_loop.build_pass_prompt(group, group_ctx, second_pass=True) if has_ctx else None
        print(_rule(label))
        if args.summary:
            print(f"pass 1 (local) chars: {len(no_ctx)}")
            print(f"pass 2 (integration) chars: {len(second)}" if second else
                  "pass 2 (integration): skipped, no additional context for these file(s)")
        elif args.diff and second:
            _diff(no_ctx, second, "pass 1 (local)", "pass 2 (integration)")
        else:
            print("--- pass 1 (local, no additional context) ---")
            print(no_ctx)
            print("--- pass 2 (integration; original content stands in for the pass-1 result) ---")
            print(second or "(skipped: no additional context for these file(s))")


if __name__ == "__main__":
    main()
