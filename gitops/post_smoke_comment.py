"""
gitops/post_smoke_comment.py -- attach a smoke-suite run's result to a fix PR.

Closes the gap the plan's Enforcement model calls out: the smoke suite can pass locally and
still never reach the human reviewer unless something puts the result on the PR itself.

Usage:
  pytest -m smoke --junit-xml=smoke.xml                                          # produce the report
  python -m gitops.post_smoke_comment --junit-xml smoke.xml --pr <url_or_number>            # dry run, prints the comment
  python -m gitops.post_smoke_comment --junit-xml smoke.xml --pr <url_or_number> --execute  # actually posts via gh
"""

import argparse
import sys

from .git_gh_ops import comment_on_pr
from .smoke_report import format_pr_comment, parse_junit_xml


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Attach a pytest --junit-xml smoke result to a PR via gh."
    )
    parser.add_argument("--junit-xml", required=True, metavar="FILE",
                         help="Path to the smoke suite's --junit-xml report.")
    parser.add_argument("--pr", required=True, metavar="PR",
                         help="PR number or URL to comment on.")
    parser.add_argument("--base-url", default="", metavar="URL",
                         help="Target the smoke suite ran against, for the comment header.")
    parser.add_argument("--repo-dir", default=".", metavar="DIR")
    parser.add_argument("--execute", action="store_true",
                         help="Actually post the comment via gh. Without this, prints a dry run.")
    args = parser.parse_args()

    result = parse_junit_xml(args.junit_xml)
    comment = format_pr_comment(result, base_url=args.base_url)

    print(comment)
    print()

    if not args.execute:
        print("[DRY RUN] Not posted. Re-run with --execute to comment on the PR.")
        return

    url = comment_on_pr(args.pr, comment, repo_dir=args.repo_dir)
    print(f"Posted: {url}")

    if result.failed:
        sys.exit(1)  # non-zero so a CI step surfaces the failure even though the comment posted


if __name__ == "__main__":
    main()
