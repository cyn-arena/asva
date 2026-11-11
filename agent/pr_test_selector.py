"""
agent/pr_test_selector.py -- match a fix batch's changed files against the misuse-case
suite's "# @a" annotations (pre-merge PR check).

A PR's own batch file (fix_batches/<batch_id>.json) lists exactly which files that PR
changed. Cross-referencing those against tests/e2e/api/test_misuse_cases.py's "# @a"
comments (the same convention the browser-failure -> fix-agent handoff uses to route a
failing misuse-case test to the fix agent, parsed via
agent/test_annotations.py::parse_annotated_files) is a coarse
file-level proxy for "which vulnerability does this PR claim to fix" -- a file shared by
more than one case can cause more than one match, so callers of this module (pr-check /
gitops/post_pr_check_comment.py) must surface that in the PR comment rather than silently
trust a single match.

Usage (as run by nodegoat-orchestrator.yml's pr-check job):
    python -m agent.pr_test_selector --batch-file fix_batches/<batch_id>.json --output matched.json
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path

from agent.test_annotations import parse_annotated_files

DEFAULT_MISUSE_TEST_FILE = "tests/e2e/api/test_misuse_cases.py"


@dataclass(frozen=True)
class CaseLabel:
    """Everything the PR comment needs to describe one misuse-case check in plain
    language, without the reader having to know the test name or tests/expectations.py's
    case_id. `when_vulnerable` is the core finding only -- pr-check appends a note about
    whether a fix was attempted at all, so this shouldn't repeat that.

    `rule_ids`: scanner rule IDs that count as a fix attempt at this case. Empty when the
    scanner can't detect the case at all; `why_no_attempt` is the reviewer-facing reason."""
    case_id: str
    label: str
    when_fixed: str
    when_vulnerable: str
    rule_ids: tuple[str, ...] = ()
    why_no_attempt: str = ""


# Misuse-case test name -> its plain-language description for the PR comment. Test names
# and this wording are unrelated to each other, so nothing but this table connects e.g.
# "test_ssji_eval_contributions" back to something a reviewer can read without opening
# tests/expectations.py or the test file itself.
TEST_CASE_LABELS: dict[str, CaseLabel] = {
    "test_idor_allocations": CaseLabel(
        case_id="a4_idor",
        label="Data-exposure check (/allocations)",
        when_fixed="A logged-in user can no longer view another user's private data by "
                    "changing the ID in the URL.",
        when_vulnerable="A logged-in user can still view another user's private data by "
                         "changing the ID in the URL.",
        rule_ids=(),
        why_no_attempt="The scanner could not detect this bug (a missing permission check).",
    ),
    "test_missing_access_control_benefits": CaseLabel(
        case_id="a2_missing_access_control",
        label="Access-control check (/benefits)",
        when_fixed="A regular (non-admin) user can no longer submit this admin-only form.",
        when_vulnerable="A regular (non-admin) user can still submit this admin-only form.",
        rule_ids=(),
        why_no_attempt="The scanner could not detect this bug (a missing permission check).",
    ),
    "test_unvalidated_redirect_learn": CaseLabel(
        case_id="a10_unvalidated_redirect",
        label="Open-redirect fix (/learn page)",
        when_fixed="Untrusted redirect targets are now blocked.",
        when_vulnerable="This page still redirects to any external URL without checking "
                         "it first, which can be used for phishing.",
        rule_ids=("javascript/OR",),
    ),
    "test_ssji_eval_contributions": CaseLabel(
        case_id="a1_ssji_eval",
        label="Code-injection fix (contributions form)",
        when_fixed="The unsafe input is now rejected instead of being executed.",
        when_vulnerable="This form still runs unsafe input as code instead of rejecting it.",
        rule_ids=("javascript/CodeInjection",),
    ),
    "test_redos_regex_bankrouting_still_validates": CaseLabel(
        case_id="a1_redos_bankrouting",
        label="ReDoS fix (profile form)",
        when_fixed="",
        when_vulnerable="This form's validation can still be tricked with a malicious "
                         "pattern that could slow down or crash the server.",
        rule_ids=("javascript/reDOSPolynomial",),
    ),
    "test_ssrf_research_symbol_lookup": CaseLabel(
        case_id="a10_ssrf",
        label="SSRF check (research page)",
        when_fixed="The research lookup no longer fetches and reflects an arbitrary "
                    "attacker-supplied URL.",
        when_vulnerable="The research lookup still fetches and reflects back whatever "
                         "URL it's given, which can be used to reach internal services.",
        rule_ids=("javascript/Ssrf",),
    ),
    "test_development_zap_key_uses_environment_and_rescans_clean": CaseLabel(
        case_id="config_hardcoded_zap_key",
        label="Hardcoded ZAP API key fix",
        when_fixed="The development configuration now reads the ZAP API key from the "
                   "environment, and the post-fix Snyk rescan no longer reports CWE-547.",
        when_vulnerable="The development configuration still contains a hardcoded ZAP "
                        "API key or Snyk still reports CWE-547.",
        rule_ids=("javascript/HardcodedNonCryptoSecret",),
    ),
}


def batch_changed_files(batch: dict) -> list[str]:
    """The app-relative file paths one triage batch touches (fix_batches/<batch_id>.json's
    files_to_fix) -- the same shape agent_loop.py already reads."""
    return [entry["file"] for entry in batch.get("files_to_fix", [])]


def matching_tests(changed_files: list[str], test_source: str) -> dict[str, list[str]]:
    """test_name -> overlapping annotated files, for every "# @a"-annotated test in
    `test_source` that shares at least one file with `changed_files`."""
    annotated = parse_annotated_files(test_source)
    changed = set(changed_files)
    return {name: files for name, files in annotated.items() if changed & set(files)}


def _skip_key(rule_id, file, line) -> tuple[str, str, str]:
    return str(rule_id), str(file), str(line)


def batch_rule_ids(batch: dict) -> set[str]:
    """Every scanner rule_id in this batch's findings, except the findings a reviewer's decision
    kept out of the PR (`reviewer_skipped`, written by agent/agent_loop.py's save_for_pr_check)."""
    skipped = {_skip_key(s.get("rule_id"), s.get("file"), s.get("line"))
               for s in batch.get("reviewer_skipped") or []}
    return {
        rule_id
        for entry in batch.get("files_to_fix", [])
        for f in entry.get("findings", [])
        if (rule_id := (f.get("identifiers") or {}).get("rule_id"))
        and _skip_key(rule_id, (f.get("location") or {}).get("file") or entry.get("file"),
                      (f.get("location") or {}).get("line")) not in skipped
    }


def build_match_report(
    changed_files: list[str], test_source: str, rule_ids: set[str] | None = None,
    reviewer_skipped: list[dict] | None = None,
) -> dict:
    """The JSON shape pr-check hands to gitops/post_pr_check_comment.py: which tests
    matched, their plain-language description, and the files that drove each match.

    With `rule_ids` (from batch_rule_ids), each match also gets `attempted` -- whether
    this PR contains a fix aimed at that case or only touches the same file, None for a
    test TEST_CASE_LABELS doesn't know, so it stays in scope -- and `why_no_attempt`.
    A case not attempted because a reviewer skipped its findings also gets `reviewer_decision`
    (the decision and its note), and is shown as skipped rather than still vulnerable."""
    matches = matching_tests(changed_files, test_source)
    fallback = CaseLabel(case_id="", label="", when_fixed="", when_vulnerable="")
    matched_tests = []
    for name, files in matches.items():
        label = TEST_CASE_LABELS.get(name, fallback)
        entry = {
            "test_name": name,
            "files": files,
            "case_id": label.case_id or None,
            "label": label.label or name,
            "when_fixed": label.when_fixed,
            "when_vulnerable": label.when_vulnerable,
        }
        if rule_ids is not None:
            entry["attempted"] = bool(set(label.rule_ids) & rule_ids) if name in TEST_CASE_LABELS else None
            entry["why_no_attempt"] = label.why_no_attempt
            decided = next((s for s in reviewer_skipped or [] if s.get("rule_id") in label.rule_ids), None)
            if entry["attempted"] is False and decided:
                entry["reviewer_decision"] = {"decision": decided.get("decision"), "note": decided.get("note") or ""}
        matched_tests.append(entry)
    return {"changed_files": changed_files, "matched_tests": matched_tests}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Match a fix batch's changed files against the misuse-case suite's "
                     "'# @a' annotations, for pr-check's pre-merge vulnerability-specific check."
    )
    parser.add_argument("--batch-file", required=True, metavar="PATH",
                         help="fix_batches/<batch_id>.json for this PR.")
    parser.add_argument("--test-file", default=DEFAULT_MISUSE_TEST_FILE, metavar="PATH",
                         help=f"Misuse-case test file to scan for annotations. Default: {DEFAULT_MISUSE_TEST_FILE}")
    parser.add_argument("--output", default=None, metavar="PATH",
                         help="Write the match report as JSON here. Default: stdout.")
    args = parser.parse_args()

    batch = json.loads(Path(args.batch_file).read_text(encoding="utf-8"))
    test_source = Path(args.test_file).read_text(encoding="utf-8")
    report = build_match_report(
        batch_changed_files(batch), test_source, rule_ids=batch_rule_ids(batch),
        reviewer_skipped=batch.get("reviewer_skipped"),
    )

    out = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
    else:
        print(out)


if __name__ == "__main__":
    main()
