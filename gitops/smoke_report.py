"""
gitops/smoke_report.py -- turn a pytest --junit-xml smoke report into a PR-comment-ready
summary (surfaces the pre-merge smoke result on the PR).

The smoke suite (tests/e2e/browser/test_smoke.py) proves green's core flows still work
before a fix PR merges, but a human reviewer never sees a local pytest run -- the result
has to be attached to the PR itself or it doesn't do its job (see the plan's Enforcement
model: the human reviewer is the real enforcement point, so they must actually see this).

`format_pr_comment` covers the existing post-deploy smoke-comment path
(gitops/post_smoke_comment.py) against the shared green environment.
`format_pr_check_comment` covers a *different* comment: pr-check's pre-merge
smoke + misuse-case result against a PR's own ephemeral candidate instance
(gitops/post_pr_check_comment.py), before that PR ever merges.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class SmokeFailure:
    name: str
    message: str


@dataclass(frozen=True)
class CaseResult:
    """One test case's outcome, kept for ALL cases (not just failures) so the pr-check
    comment can render a full per-check results table."""
    name: str
    status: str  # "passed" | "failed" | "skipped"
    message: str = ""


@dataclass(frozen=True)
class SmokeResult:
    total: int
    passed: int
    failed: int
    skipped: int
    failures: list[SmokeFailure] = field(default_factory=list)
    cases: list[CaseResult] = field(default_factory=list)

    @property
    def all_passed(self) -> bool:
        return self.failed == 0 and self.total > 0


@dataclass(frozen=True)
class RescanResult:
    """The candidate's Snyk rescan reduced to one outcome for the pr-check comment (see
    `rescan_outcome` in gitops/post_pr_check_comment.py, which builds it)."""
    status: str  # "passed" | "still_present" | "incomplete"
    # (rule_id, file or package) for each targeted finding the rescan still reports.
    findings: list[tuple[str, str]] = field(default_factory=list)
    reason: str = ""  # why an incomplete rescan could not finish, when known

    @property
    def passed(self) -> bool:
        return self.status == "passed"


def parse_junit_xml(path: str | Path) -> SmokeResult:
    """Parse a pytest `--junit-xml` report into a SmokeResult.

    Handles both a bare <testsuite> root and the <testsuites> wrapper pytest emits when a
    run spans more than one suite.
    """
    root = ET.parse(Path(path)).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite"))

    total = passed = failed = skipped = 0
    failures: list[SmokeFailure] = []
    cases: list[CaseResult] = []
    for suite in suites:
        for case in suite.findall("testcase"):
            total += 1
            name = case.get("name", "<unknown>")
            failure = case.find("failure")
            error = case.find("error")
            skip = case.find("skipped")
            if failure is not None or error is not None:
                failed += 1
                node = failure if failure is not None else error
                message = (node.get("message") or "").strip() or "(no message)"
                failures.append(SmokeFailure(name=name, message=message))
                cases.append(CaseResult(name=name, status="failed", message=message))
            elif skip is not None:
                skipped += 1
                cases.append(CaseResult(name=name, status="skipped",
                                        message=(skip.get("message") or "").strip()))
            else:
                passed += 1
                cases.append(CaseResult(name=name, status="passed"))
    return SmokeResult(total=total, passed=passed, failed=failed, skipped=skipped,
                       failures=failures, cases=cases)


def format_pr_comment(result: SmokeResult, base_url: str = "") -> str:
    """Build the markdown comment body attached to the fix PR."""
    status = (
        ":white_check_mark: **All smoke checks passed**" if result.all_passed
        else ":x: **Smoke checks failed**"
    )
    lines = [
        "## ASVA pre-merge smoke check",
        "",
        status,
        "",
        f"- **Target:** `{base_url or 'unknown'}`",
        f"- **Tests:** {result.total} total - {result.passed} passed, "
        f"{result.failed} failed, {result.skipped} skipped",
        "",
    ]
    if result.failures:
        lines.append("### Failed checks")
        for f in result.failures:
            lines.append(f"- `{f.name}`: {f.message}")
        lines.append("")
    lines.append(
        "_Pre-merge behavioural verification (happy-path suite against green). This does "
        "not replace human review -- it's evidence for it._"
    )
    return "\n".join(lines)


_PARAM_SUFFIX_RE = re.compile(r"\[.*\]$")

# The smoke suite's four "does the site still work" checks read as one row -- a reviewer
# doesn't need a separate line for "login works" vs. "profile loads"; they need to know if
# the core site broke. The off-site redirect check gets its own row because it exists
# specifically to catch an over-aggressive redirect fix, which is common enough (SAST
# 'open redirect' fixes routinely over-block) to call out by name.
_CORE_FLOW_TESTS = (
    "test_login_redirects_to_dashboard",
    "test_dashboard_loads_for_logged_in_user",
    "test_normal_contribution_submits",
    "test_profile_renders",
)
_LEARNING_LINK_TEST = "test_learning_resources_link_reaches_offsite"
_LEARNING_LINK_EXPLANATION = (
    "This link is supposed to send users to an external site (Khan Academy), but it now "
    "sends them back to the homepage instead. The redirect fix appears to block all "
    "outside links, including ones that are supposed to work."
)


def _strip_param_suffix(name: str) -> str:
    return _PARAM_SUFFIX_RE.sub("", name)


def _not_attempted(matched_tests: list[dict]) -> set[str]:
    """Tests this PR only shares a file with: no fix in it aims at them. As in the dashboard's
    validation record (scripts/dashboard_evidence.py), they can't fail the PR. A test without the
    flag stays in scope."""
    return {m["test_name"] for m in matched_tests if m.get("attempted") is False}


def misuse_fails_pr(misuse: SmokeResult | None, matched_tests: list[dict]) -> bool:
    """Whether the misuse-case results count against this PR."""
    if misuse is None:
        return False
    if misuse.total == 0:
        return True
    ignored = _not_attempted(matched_tests)
    return any(c.status == "failed" and _strip_param_suffix(c.name) not in ignored for c in misuse.cases)


_FIX_DROPPED = ("ASVA tried to fix this, but no fix passed the app's tests, so none is in this PR "
                "and it still requires its own fix.")


def _no_fix_reason(m: dict, changed_files: list[str]) -> str:
    """The note after a still-vulnerable result: distinguishes a fix that was attempted
    and doesn't work from one the scanner never generated."""
    attempted = m.get("attempted")
    if attempted is True:
        return "This PR includes a fix aimed at this, but the check shows it doesn't work."
    if m.get("fix_dropped"):
        return _FIX_DROPPED
    if attempted is False:
        why = m.get("why_no_attempt") or "The scanner could not detect this bug."
        overlap = [f for f in m.get("files", []) if f in changed_files]
        files = ", ".join(f"`{f}`" for f in overlap) or "the same file"
        return (f"{why} This was included because this PR edits "
                f"{'the file ' if len(overlap) == 1 else 'the files ' if overlap else ''}"
                f"{files}, and it still requires its own fix.")
    # matched.json predating the attempted field
    return "This PR touches a related file but doesn't fix this specific issue."


_DECISION_WORDS = {"false_positive": "false positive", "accepted_risk": "accepted risk",
                   "needs_manual_fix": "needs a manual fix"}


def _decision_text(decision: dict) -> str:
    words = _DECISION_WORDS.get(decision.get("decision"), decision.get("decision") or "reviewer decision")
    return f"{words}: {decision['note']}" if decision.get("note") else words


def reviewer_skipped_lines(skipped: list[dict] | None) -> list[str]:
    """The findings a reviewer's decision kept out of this PR (agent/agent_loop.py's
    save_for_pr_check): listed so the reader knows they were left alone on purpose. Not counted."""
    if not skipped:
        return []
    return ["**Skipped by reviewer decision** (not fixed by this PR, not counted in the result):", "",
            *[f"- `{s.get('rule_id')}` in `{s.get('file')}:{s.get('line')}` -- {_decision_text(s)}" for s in skipped],
            ""]


def _row(check: str, passed: bool, note: str, *, verb: tuple[str, str] = ("Passed", "Failed")) -> str:
    result = f":white_check_mark: {verb[0]}" if passed else f":x: {verb[1]}"
    return f"| {check} | {result} | {note} |"


_RESCAN_CHECK = "Security rescan (Snyk)"
_RESCAN_LIST_LIMIT = 5


def _cell(text: str) -> str:
    """Make text taken from the scanner safe inside a table cell -- a stray "|" or line
    break would otherwise end the cell or the whole row early."""
    return " ".join(str(text).split()).replace("|", "\\|")


def _rescan_note(rescan: RescanResult) -> str:
    """The "What we found" text for the rescan row."""
    if rescan.passed:
        return "The scanner no longer reports any of the issues this PR targets."
    if rescan.status == "still_present":
        shown = ", ".join(f"`{_cell(rule)}` in `{_cell(where)}`"
                          for rule, where in rescan.findings[:_RESCAN_LIST_LIMIT])
        if not shown:
            return "The scanner still reports some of the issues this PR targets."
        more = len(rescan.findings) - _RESCAN_LIST_LIMIT
        if more > 0:
            shown += f", and {more} more"
        return (f"The scanner still reports {len(rescan.findings)} of the issues this PR "
                f"targets: {shown}.")
    # Anything else is an unfinished rescan, which is never treated as a pass.
    note = "The rescan could not be completed, so it is not confirmed that the issues are gone."
    reason = _cell(rescan.reason)
    if reason:
        note += " " + reason + ("" if reason[-1] in ".!?" else ".")
    if "actions log" not in reason.lower():
        note += " See the Actions log."
    return note


def format_pr_check_comment(
    smoke: SmokeResult,
    *,
    short_sha: str,
    changed_files: list[str],
    matched_tests: list[dict],
    misuse: SmokeResult | None = None,
    app_started: bool = True,
    marked_draft: bool = False,
    rescan: RescanResult | None = None,
    new_findings: list[str] | None = None,
    reviewer_skipped: list[dict] | None = None,
) -> str:
    """Build pr-check's pre-merge PR comment: one results table covering
    whether the app starts, the smoke suite's core-flow + off-site-redirect checks, and
    (when this PR's changed files matched one or more misuse-case tests -- see
    agent/pr_test_selector.py) each matched check's result run with TARGET=candidate
    against this PR's own ephemeral instance, not the shared blue/green environment.

    `app_started` reflects the readiness probe (curl polling the app's own HTTP port), not
    anything in `smoke` -- pytest always collects and runs the same 5 smoke tests whether
    or not the app is actually listening, so a boot failure has to be reported separately
    or every row would misleadingly read as five unrelated connection failures.

    `matched_tests` = [{"test_name", "files", "case_id", "label", "when_fixed",
    "when_vulnerable"}, ...] (possibly empty -- e.g. a version_upgrade/SCA batch touches
    no file any misuse-case test names).

    `marked_draft` only controls the notice text; the caller converts the PR separately
    via `convert_pr_to_draft`.

    `rescan` is the Snyk rescan of this PR's code. When given, it adds one last row that
    counts like any other, so the headline can't say "ready" while the scanner still
    finds the issue. None (no rescan available) leaves the comment exactly as before.

    `reviewer_skipped` = the findings a reviewer's decision kept out of this PR. A matched check
    with `reviewer_decision` is shown as skipped, whatever its result, and not counted.
    """
    rows: list[str] = []
    failed_count = 0
    total_count = 0
    still_open: list[str] = []  # failed, but this PR did not attempt them: shown, not counted
    left_out: list[str] = []  # the same, but a fix was tried and dropped
    decided: list[str] = []  # skipped by a reviewer's decision: shown, not counted

    def add(check: str, passed: bool, note: str, verb=("Passed", "Failed")) -> None:
        nonlocal failed_count, total_count
        total_count += 1
        if not passed:
            failed_count += 1
        rows.append(_row(check, passed, note, verb=verb))

    add("App starts up", app_started, "" if app_started else
        "The app never finished starting after this fix -- nothing answered on its port "
        "within 90 seconds. " + (
            "None of the other checks below could run because of this." if rescan is None else
            "None of the app's tests could run because of this, but the security rescan "
            "below checks the code itself, so it still ran."))

    if app_started:
        core_cases = [c for c in smoke.cases if _strip_param_suffix(c.name) in _CORE_FLOW_TESTS]
        if core_cases:
            core_ok = all(c.status == "passed" for c in core_cases)
            note = "Core site still works normally" if core_ok else "; ".join(
                f"{_strip_param_suffix(c.name)}: {c.message}"
                for c in core_cases if c.status != "passed"
            )
            add("Login, dashboard, contributions, profile", core_ok, note)

        link_case = next(
            (c for c in smoke.cases if _strip_param_suffix(c.name) == _LEARNING_LINK_TEST), None
        )
        if link_case is not None:
            link_ok = link_case.status == "passed"
            add('"Learning Resources" link', link_ok, "" if link_ok else _LEARNING_LINK_EXPLANATION)

        for m in matched_tests:
            if m.get("reviewer_decision"):
                decided.append(m["label"])
                rows.append(f"| {m['label']} | :fast_forward: Skipped, reviewer decision | "
                            f"{_decision_text(m['reviewer_decision'])} |")
                continue
            case_result = None
            if misuse is not None:
                case_result = next(
                    (c for c in misuse.cases if _strip_param_suffix(c.name) == m["test_name"]),
                    None,
                )
            if case_result is None:
                continue
            fixed = case_result.status == "passed"
            note = (m["when_fixed"] if fixed
                    else f"{m['when_vulnerable']} {_no_fix_reason(m, changed_files)}")
            if case_result.status == "failed" and m["test_name"] in _not_attempted([m]):
                (left_out if m.get("fix_dropped") else still_open).append(m["label"])
                state = "fix tried and dropped" if m.get("fix_dropped") else "not attempted"
                rows.append(f"| {m['label']} | :warning: Still vulnerable, {state} | {note.strip()} |")
                continue
            add(m["label"], fixed, note.strip(), verb=("Fixed", "Still vulnerable"))

    # The rescan reads the code rather than the running app, so it has a result even when
    # the app never started -- show it either way.
    if rescan is not None:
        add(_RESCAN_CHECK, rescan.passed, _rescan_note(rescan),
            verb=("Passed", "Still vulnerable" if rescan.status == "still_present" else "Failed"))

    # What the scan before the PR left (agent/test_first.py): the tests can pass and this still stand.
    if new_findings:
        add("New findings (scan before this PR)", False, "; ".join(new_findings), verb=("None", "Found"))

    header = (
        f"## :white_check_mark: Ready to merge, pending review -- all {total_count} checks passed"
        if failed_count == 0 else
        f"## :x: Not ready to merge -- {failed_count} of {total_count} checks failed"
    )

    lines = [
        header,
        "",
        *([f"**Still vulnerable, not attempted by this PR:** {', '.join(still_open)}. This PR did not cause "
           "them or make them worse, but merging it does not fix them.", ""] if still_open else []),
        *([f"**Still vulnerable, fix tried and dropped:** {', '.join(left_out)}. No fix passed the app's tests, so "
           "merging this PR does not fix them.", ""] if left_out else []),
        *reviewer_skipped_lines(reviewer_skipped),
        f"This was tested by building this PR's branch (`{short_sha}`) on its own and "
        "running it in isolation.",
        "",
        "| Check | Result | What we found |",
        "|---|---|---|",
        *rows,
        "",
    ]

    summary = _summary_line(
        app_started=app_started,
        core_ok=all(c.status == "passed" for c in smoke.cases
                    if _strip_param_suffix(c.name) in _CORE_FLOW_TESTS) if app_started else None,
        link_ok=(next((c.status == "passed" for c in smoke.cases
                       if _strip_param_suffix(c.name) == _LEARNING_LINK_TEST), None)
                 if app_started else None),
        matched_tests=matched_tests,
        misuse=misuse,
        changed_files=changed_files,
        rescan=rescan,
    )
    if new_findings:
        summary = ("**Summary:** every test passed, but the scan before this PR found new critical or high findings. "
                   "It should not be merged until someone has checked them." if summary == _ALL_PASSED_SUMMARY else
                   f"{summary} The scan before this PR also found new critical or high findings.")
    if decided:
        summary += (f" {len(decided)} check{'s' if len(decided) > 1 else ''} ({', '.join(decided)}) "
                    "skipped by reviewer decision, not counted.")
    lines.append(summary)

    if marked_draft:
        lines += [
            "",
            "This PR has been converted to a draft so it can't be merged by accident. "
            "Mark it \"Ready for review\" only after a person has resolved the problem above.",
        ]

    lines += [
        "",
        "_Tested on a throwaway copy of this branch, not the environment the team shares. "
        "A person still needs to review and merge this._",
    ]
    return "\n".join(lines) + "\n"


_ALL_PASSED_SUMMARY = "**Summary:** every check passed. This fix looks safe to merge, pending review."


def _summary_line(
    *,
    app_started: bool,
    core_ok: bool | None,
    link_ok: bool | None,
    matched_tests: list[dict],
    misuse: SmokeResult | None,
    changed_files: list[str],
    rescan: RescanResult | None = None,
) -> str:
    """One or two plain sentences, no table, restating the verdict for anyone skimming.
    A rescan that failed or never finished is always stated, and rules out the all-clear."""
    summary = _tests_summary(
        app_started=app_started, core_ok=core_ok, link_ok=link_ok,
        matched_tests=matched_tests, misuse=misuse, changed_files=changed_files,
    )
    if rescan is None or rescan.passed:
        return summary
    if rescan.status == "still_present":
        found = (f"{len(rescan.findings)} of the issues" if rescan.findings else "issues")
        problem = (f"the security rescan still finds {found} this PR targets, so the "
                   "vulnerability is not fixed")
    else:
        problem = ("the security rescan could not be completed, so it is not confirmed "
                   "that the vulnerability is fixed")
    if summary == _ALL_PASSED_SUMMARY:
        return f"**Summary:** every test passed, but {problem}. It should not be merged as-is."
    return f"{summary} {problem[0].upper()}{problem[1:]}."


def _tests_summary(
    *,
    app_started: bool,
    core_ok: bool | None,
    link_ok: bool | None,
    matched_tests: list[dict],
    misuse: SmokeResult | None,
    changed_files: list[str],
) -> str:
    """The summary from the app's own tests alone (no rescan)."""
    if not app_started:
        return (
            "**Summary:** this fix appears to break the app entirely. It should not be "
            "merged until the app can start successfully again. The vulnerability this "
            "PR targets is still present and still needs a fix -- just not this one."
        )

    fixed_labels = []
    vulnerable = []
    for m in matched_tests:
        if misuse is None or m.get("reviewer_decision"):  # skipped by a reviewer: not part of the verdict
            continue
        case_result = next(
            (c for c in misuse.cases if _strip_param_suffix(c.name) == m["test_name"]), None
        )
        if case_result is None:
            continue
        if case_result.status == "passed":
            fixed_labels.append(m["label"])
        else:
            vulnerable.append(m)
    vulnerable_labels = [m["label"] for m in vulnerable]

    broke_something = core_ok is False or link_ok is False

    if not matched_tests:
        if broke_something:
            return (
                "**Summary:** this fix broke something in the app itself. See the table "
                "above for what's affected."
            )
        files_display = ", ".join(f"`{f}`" for f in changed_files) or "the file(s) it changes"
        return (
            f"**Summary:** no security-behavior check applies to {files_display}, and the "
            "rest of the app still works normally."
        )

    if not vulnerable_labels and not broke_something:
        return _ALL_PASSED_SUMMARY

    tried = [m["label"] for m in vulnerable if m.get("attempted") is True]
    dropped = [m["label"] for m in vulnerable if m.get("attempted") is False and m.get("fix_dropped")]
    unasked = [m["label"] for m in vulnerable if m.get("attempted") is False and not m.get("fix_dropped")]
    if vulnerable_labels and len(tried) + len(dropped) + len(unasked) == len(vulnerable_labels):
        sentences = []
        if fixed_labels:
            n = len(fixed_labels)
            sentences.append(
                f"{n} of the security fixes in this PR {'is' if n == 1 else 'are'} good."
            )
        if tried:
            sentences.append(
                f"Its fix for the {tried[0]} issue does not work -- that vulnerability "
                "is still there."
                if len(tried) == 1 else
                f"Its fixes for {len(tried)} issues ({', '.join(tried)}) do not work -- "
                "those vulnerabilities are still there."
            )
        if dropped:
            sentences.append(
                f"ASVA tried to fix the {dropped[0]} issue, but no fix passed the app's tests, so "
                "that one still requires its own fix."
                if len(dropped) == 1 else
                f"ASVA tried to fix {len(dropped)} issues ({', '.join(dropped)}), but no fix passed "
                "the app's tests, so those still require their own fix."
            )
        if unasked:
            sentences.append(
                f"It never attempted to fix the {unasked[0]} issue -- the scanner could "
                "not detect it, so that one still requires its own fix."
                if len(unasked) == 1 else
                f"It never attempted to fix {len(unasked)} issues ({', '.join(unasked)}) "
                "-- the scanner could not detect them, so those still require their own fix."
            )
        if broke_something:
            sentences.append("It also breaks something else in the app. See the table above.")
        return "**Summary:** " + " ".join(sentences)

    # Legacy wording for matched.json predating the attempted field.
    # Each fact below is its own sentence -- chaining them all with "but" reads fine for
    # two facts and turns into a run-on for three, so only the first join gets a "but";
    # anything past that starts a fresh sentence instead.
    sentences = []
    if fixed_labels and vulnerable_labels:
        sentences.append(
            f"{len(fixed_labels)} of the security fixes in this PR are good, but it does "
            "not address "
            + (f"the {vulnerable_labels[0]} issue" if len(vulnerable_labels) == 1
               else f"{len(vulnerable_labels)} issues ({', '.join(vulnerable_labels)})")
            + ", even though it edits a file associated with "
            + ("it" if len(vulnerable_labels) == 1 else "them") + "."
        )
    elif fixed_labels:
        if broke_something:
            sentences.append(
                "This fix does close the vulnerability it targets, but it breaks "
                "something else in the app, so it can't be merged as-is -- which means "
                "the vulnerability remains unfixed in the app until someone writes a "
                "better fix. See the table above for what broke."
            )
        else:
            sentences.append(f"{len(fixed_labels)} of the security fixes in this PR are good.")
    elif vulnerable_labels:
        sentences.append(
            "This PR does not address "
            + (f"the {vulnerable_labels[0]} issue" if len(vulnerable_labels) == 1
               else f"{len(vulnerable_labels)} issues ({', '.join(vulnerable_labels)})")
            + ", even though it edits a file associated with "
            + ("it" if len(vulnerable_labels) == 1 else "them") + "."
        )

    if broke_something and not (fixed_labels and not vulnerable_labels):
        sentences.append("It also breaks something else in the app. See the table above.")

    return "**Summary:** " + " ".join(sentences)
