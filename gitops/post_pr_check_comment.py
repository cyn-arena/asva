"""
gitops/post_pr_check_comment.py -- attach pr-check's pre-merge result (smoke suite, plus
the matched misuse-case check, if any) to a fix PR.

Unlike gitops/post_smoke_comment.py (which reports a post-deploy smoke run against the
shared green environment), this reports a pre-merge run against a throwaway instance built
from the fix PR's own branch -- see nodegoat-orchestrator.yml's pr-check job.

Usage:
  BASE_URL=http://localhost:4000 pytest -m smoke --junit-xml=smoke.xml
  python -m agent.pr_test_selector --batch-file fix_batches/<batch_id>.json --output matched.json
  # only if matched.json has at least one matched test:
  BASE_URL=http://localhost:4000 TARGET=candidate pytest -m api -k "<matched names>" --junit-xml=misuse.xml

  python -m gitops.post_pr_check_comment \\
      --smoke-xml smoke.xml --matched-json matched.json [--misuse-xml misuse.xml] \\
      --app-started true --pr <url_or_number> --sha <short-sha>            # dry run, prints the comment
      [--rescan-json asva-results/validation/<batch_id>.json]              # add the Snyk rescan row
      [--batch-file asva-results/fix/fix_batches/<batch_id>.json]          # add new findings the scan before the PR left
      [--execute]                                                          # actually posts via gh
      [--no-draft]                                                         # on failure, comment only -- don't convert the PR to draft

On a failing result with --execute, the PR is converted to draft before the comment is
posted, so the comment can truthfully say it happened. A rescan that still finds the
targeted issues, or that could not be completed, is a failing result too. A misuse-case
check the PR did not attempt is listed but is not a failing result, as in the dashboard.
"""

import argparse
import json
import os
import sys
from pathlib import Path

from .git_gh_ops import GitOpError, comment_on_pr, convert_pr_to_draft
from .smoke_report import (RescanResult, format_pr_check_comment, misuse_fails_pr, parse_junit_xml,
                           reviewer_skipped_lines)


def tested_sha(report):
    """Final validation records tested_sha; the pre-rescan record (dashboard_evidence.py) only commit_sha."""
    return report.get("tested_sha") or report.get("commit_sha")


def format_validation_comment(report, marked_draft=False, new_findings=None, reviewer_skipped=None):
    """Render exactly the checks retained in the dashboard's validation JSON, plus what the scan
    before the PR left (agent/test_first.py) and the findings a reviewer skipped, which the
    validation does not know about."""
    checks = report["checks"]
    counts = {status: sum(c["status"] == status for c in checks)
              for status in ("passed", "failed", "skipped", "not_available")}
    heading = ("## :white_check_mark: Ready to merge, pending review"
               if report["result"] == "passed" and not new_findings else "## :x: Not ready to merge")
    lines = [heading, "",
             f"**Result: {report['result']}** — {len(checks)} checks: {counts['passed']} passed, "
             f"{counts['failed']} failed, {counts['skipped']} skipped, {counts['not_available']} not available.", "",
             *([f"**The scan before this PR also found new critical or high findings:** "
                f"{'; '.join(new_findings)}. It should not be merged until someone has checked them.", ""]
               if new_findings else []),
             *reviewer_skipped_lines(reviewer_skipped),
             f"Tested commit: `{tested_sha(report)}`", "",
             "| Check | Kind | Result | Detail |", "|---|---|---|---|"]
    def cell(value):
        return str(value or "").replace("|", "\\|").replace("\n", " ").replace("\r", " ")
    lines.extend("| " + " | ".join(cell(c.get(key)) for key in ("name", "kind", "status", "detail")) + " |" for c in checks)
    if new_findings:
        lines.append(f"| New findings (scan before this PR) | security_scan | found | {cell('; '.join(new_findings))} |")
    out_of_scope = report.get("out_of_scope_checks") or []
    if out_of_scope:
        lines.extend(["", "Security checks this batch did not target (shown, not counted in the result):", "",
                      "| Check | Result | Detail |", "|---|---|---|"])
        lines.extend("| " + " | ".join(cell(c.get(key)) for key in ("name", "status", "detail")) + " |" for c in out_of_scope)
    if marked_draft:
        lines.extend(["", "This PR has been converted to a draft so it can't be merged by accident. "
                      "Mark it \"Ready for review\" only after a person has resolved the problem above."])
    lines.extend(["", "This is the same check list published in the validation JSON. Human review is still required; this run does not merge the PR."])
    return "\n".join(lines) + "\n"


# The checks the candidate rescan adds to the validation JSON alongside the JUnit-derived
# ones -- see scripts/check-fix-candidate.py and scripts/record-candidate-failure.py.
_RESCAN_KINDS = ("security_scan", "scan_preparation", "pipeline")
_TARGETED_CHECK = "targeted scanner findings absent from candidate"


def rescan_outcome(path: str | Path) -> RescanResult:
    """Reduce the validation JSON's rescan checks to one outcome for the comment.

    Fails closed: anything short of a finished rescan with every rescan check passed --
    a missing or unreadable file, no security_scan check at all, or a failed dependency
    install, scan or workflow step -- is "incomplete", which counts as a failure.
    """
    try:
        report = json.loads(Path(path).read_text(encoding="utf-8"))
        checks = [c for c in report["checks"] if c.get("kind") in _RESCAN_KINDS]
    except FileNotFoundError:
        return RescanResult("incomplete", reason="No rescan result was saved for this PR.")
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return RescanResult("incomplete", reason="The rescan result could not be read.")

    if not any(c.get("kind") == "security_scan" for c in checks):
        return RescanResult("incomplete", reason="No rescan result was recorded for this PR.")
    if all(c.get("status") == "passed" for c in checks):
        return RescanResult("passed")

    targeted = next((c for c in checks if c.get("kind") == "security_scan"
                     and c.get("name") == _TARGETED_CHECK), None)
    if targeted is not None and targeted.get("status") == "failed":
        # detail is a JSON list of [rule_id, file_or_package] pairs still reported.
        try:
            findings = [(str(rule), str(where))
                        for rule, where in json.loads(targeted.get("detail") or "[]")]
        except (ValueError, TypeError):
            findings = []
        return RescanResult("still_present", findings=findings)

    first_problem = next(c for c in checks if c.get("status") != "passed")
    # The targeted check's detail is a findings list, not a reason anyone could read.
    reason = "" if first_problem is targeted else str(first_problem.get("detail") or "")
    return RescanResult("incomplete", reason=reason)


def _from_batch(path: str | None, key: str) -> list[str]:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8")).get(key) or [] if path else []
    except (OSError, ValueError, AttributeError):
        return []


def new_before_pr(path: str | None) -> list[str]:
    """New findings the scan before the PR left in this batch (agent/test_first.py)."""
    return _from_batch(path, "new_before_pr")


def reviewer_skipped(path: str | None) -> list[dict]:
    """The findings a reviewer's decision kept out of this PR (agent/agent_loop.py)."""
    return _from_batch(path, "reviewer_skipped")


def with_dropped_fixes(matched_tests: list[dict], path: str | None) -> list[dict]:
    """Mark the holes whose misuse fix was tried and dropped (agent/test_first.py), so the comment
    doesn't say nothing tried to fix them. They still don't count against this PR."""
    dropped = set(_from_batch(path, "misuse_dropped"))
    return [dict(m, fix_dropped=True) if m["test_name"] in dropped else m for m in matched_tests]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Attach pr-check's smoke + misuse-case result to a PR via gh."
    )
    parser.add_argument("--validation-json", metavar="FILE", help="Final candidate validation; use its exact check list instead of recomputing JUnit summaries.")
    parser.add_argument("--smoke-xml", metavar="FILE",
                         help="Path to the smoke suite's --junit-xml report.")
    parser.add_argument("--matched-json", metavar="FILE",
                         help="Output of `python -m agent.pr_test_selector` for this PR's batch.")
    parser.add_argument("--misuse-xml", default=None, metavar="FILE",
                         help="Path to the misuse-case suite's --junit-xml report. Omit if "
                              "--matched-json had no matched tests, so nothing ran.")
    parser.add_argument("--rescan-json", default=None, metavar="FILE",
                         help="Final candidate validation JSON; its Snyk rescan checks become "
                              "one more row in the readable comment. A missing or unreadable "
                              "file counts as a failed rescan. Unlike --validation-json, this "
                              "keeps the readable comment format.")
    parser.add_argument("--batch-file", default=None, metavar="FILE",
                         help="This PR's fix batch; new findings the scan before the PR left "
                              "(agent/test_first.py) become one more failed row, and a dropped "
                              "misuse fix is reported as tried. Missing or "
                              "unreadable adds nothing, as the PR's own text has them too.")
    parser.add_argument("--pr", required=True, metavar="PR",
                         help="PR number or URL to comment on.")
    parser.add_argument("--sha", metavar="SHA",
                         help="Short SHA the ephemeral instance was built from.")
    parser.add_argument("--app-started", choices=["true", "false"],
                         help="Whether the app's readiness probe succeeded. When false, "
                              "the smoke/misuse results are ignored -- pytest still runs "
                              "and produces a report even when nothing is listening, but "
                              "every case in it is just a connection failure, not a real "
                              "check of the app's behaviour.")
    parser.add_argument("--repo-dir", default=".", metavar="DIR")
    parser.add_argument("--execute", action="store_true",
                         help="Actually post the comment via gh. Without this, prints a dry run.")
    parser.add_argument("--no-draft", action="store_true",
                         help="On a failing result, only post the comment -- don't also "
                              "convert the PR to draft.")
    args = parser.parse_args()

    if args.validation_json:
        report = json.loads(Path(args.validation_json).read_text(encoding="utf-8"))
        if args.sha and tested_sha(report) != args.sha:
            parser.error("Validation does not match the PR candidate SHA")
        failing = report["result"] != "passed"
        new_findings = new_before_pr(args.batch_file)
        # Same order as the JUnit path: draft first, so the comment can say it happened.
        marked_draft = False
        if args.execute and (failing or new_findings) and not args.no_draft:
            try:
                convert_pr_to_draft(args.pr, repo_dir=args.repo_dir)
                marked_draft = True
            except GitOpError as e:
                print(f"[WARN] Could not convert PR to draft: {e}")
        comment = format_validation_comment(report, marked_draft=marked_draft, new_findings=new_findings,
                                            reviewer_skipped=reviewer_skipped(args.batch_file))
        print(comment)
        if not args.execute:
            print("[DRY RUN] Not posted. Re-run with --execute to comment on the PR.")
            return
        print(f"Posted: {comment_on_pr(args.pr, comment, repo_dir=args.repo_dir)}")
        if output := os.environ.get("GITHUB_OUTPUT"):
            with open(output, "a", encoding="utf-8") as stream:
                stream.write("comment_result=success\n")
        if failing:
            sys.exit(1)
        return
    if not all((args.smoke_xml, args.matched_json, args.sha, args.app_started)):
        parser.error("Provide --validation-json or all legacy JUnit report arguments")
    smoke = parse_junit_xml(args.smoke_xml)
    match_report = json.loads(Path(args.matched_json).read_text(encoding="utf-8"))
    misuse = parse_junit_xml(args.misuse_xml) if args.misuse_xml else None
    rescan = rescan_outcome(args.rescan_json) if args.rescan_json is not None else None
    new_findings = new_before_pr(args.batch_file)
    matched_tests = with_dropped_fixes(match_report.get("matched_tests", []), args.batch_file)

    app_started = args.app_started == "true"
    failing = (not app_started or not smoke.all_passed
               or misuse_fails_pr(misuse, matched_tests)
               or (rescan is not None and not rescan.passed))

    # If drafting fails, still post the comment -- it matters more than the draft flip.
    marked_draft = False
    if args.execute and (failing or new_findings) and not args.no_draft:
        try:
            convert_pr_to_draft(args.pr, repo_dir=args.repo_dir)
            marked_draft = True
        except GitOpError as e:
            print(f"[WARN] Could not convert PR to draft: {e}")

    comment = format_pr_check_comment(
        smoke,
        short_sha=args.sha,
        changed_files=match_report.get("changed_files", []),
        matched_tests=matched_tests,
        misuse=misuse,
        app_started=app_started,
        marked_draft=marked_draft,
        rescan=rescan,
        new_findings=new_findings,
        reviewer_skipped=reviewer_skipped(args.batch_file),
    )

    print(comment)
    print()

    if not args.execute:
        print("[DRY RUN] Not posted. Re-run with --execute to comment on the PR.")
        return

    url = comment_on_pr(args.pr, comment, repo_dir=args.repo_dir)
    print(f"Posted: {url}")
    if output := os.environ.get("GITHUB_OUTPUT"):
        with open(output, "a", encoding="utf-8") as stream:
            stream.write("comment_result=success\n")

    # Not for new findings: the tests passed and one can be a false alarm, so a person checks the
    # draft, but nothing in the pipeline broke.
    if failing:
        sys.exit(1)  # non-zero so the CI step surfaces the failure even though the comment posted


if __name__ == "__main__":
    main()
