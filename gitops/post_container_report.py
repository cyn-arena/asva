"""
gitops/post_container_report.py -- one GitHub issue per app saying what the container scan found.

Most container findings never reach the fix stage, so without this they leave nothing on GitHub and
the container looks clean. The report groups every finding by why it has no automatic fix and what a
person can do instead. It is written only from the scanner's data and the RAG's sources, never by an
LLM, and says "unknown" when they don't say.

The issue is updated on every run rather than a new one opened, and is only opened when there is
something to report. A problem here warns and never fails the run.

The issue shows the official result, so only the branches in ASVA_REPORT_BRANCHES post to it
(space-separated patterns, default "main rel/*"). A run on any other branch prints the report in
its log, so test runs don't overwrite what people are reading.

Usage (before the RAG is stopped, so it can be asked):
  python -m gitops.post_container_report \\
      --findings findings/ranked_unified_findings.json --batch-dir fix_batches --prs-json prs.json \\
      --commit-sha <sha> --repo-name <name> [--repo-dir .]   # dry run, prints the report
      [--execute]                                            # actually opens or updates it via gh
"""

import argparse
import fnmatch
import json
import os
from collections import Counter, defaultdict
from pathlib import Path

from agent import rag_client
from security_context.integration import asva_rag_client

from . import config
from .git_gh_ops import GitOpError, find_open_issue_by_title, open_issue, update_issue
from .post_pr_summary import distinct, severity_counts

LABEL = "asva-container-report"
SEVERITIES = ("critical", "high", "medium", "low")
TOP_SEVERITIES = ("critical", "high")
MAX_LOOKUPS = 30   # the RAG checks at most this many CVEs against the OS's fix data per request
MAX_ROWS = 50      # a longer table is not read, and an issue body has a size limit
MAX_BODY_CHARS = 60_000
DEFAULT_REPORT_BRANCHES = ["main", "rel/*"]

# Why a finding has no automatic fix: (what to call it, what a person can do). {pr} is the dependency PR.
REASONS = {
    "attempted": ("Sent to the fix stage", "See \"Container fix\" above."),
    "no_fix": ("OS package, the scanner knows no fix",
               "Wait for a fix, or try a newer base image (not tested here). See the OS package table for critical and high."),
    "fix_below_severity": ("OS package with a fix, but medium or low",
                           "Automatic fixes only cover critical and high. Rebuilding on a newer image may pick these up (not tested here)."),
    "fix_not_selected": ("OS package with a fix, not selected by triage", "Check why in `triage/triage.py`, or update it by hand."),
    "inside_program": ("Inside a program that comes with the image",
                       "Usually can't be changed from this repo: a newer image brings a new build of the program."),
    "same_as_dependency_scan": ("Same vulnerability as the dependency scan", "Handled with the dependency findings: {pr}."),
    "app_library": ("App library the dependency scan did not report", "Update the dependency file it comes from by hand."),
}


def _name(finding: dict) -> str:
    return ((finding.get("location") or {}).get("package") or "").rsplit("@", 1)[0]


def _vulnerability(finding: dict) -> str:
    ids = finding.get("identifiers") or {}
    return ids.get("cve") or ids.get("rule_id") or finding.get("title") or "-"


def _key(finding: dict) -> tuple[str, str]:
    return (_vulnerability(finding), _name(finding).lower())


def _kind(finding: dict) -> str:
    return (finding.get("location") or {}).get("kind") or ""


def _fixable(finding: dict) -> bool:
    return bool((finding.get("remediation") or {}).get("fixable"))


def reason(finding: dict, attempted: set, in_dependency_scan: set) -> str:
    if finding.get("finding_id") in attempted:
        return "attempted"
    kind = _kind(finding)
    if kind == "dependency":
        return "same_as_dependency_scan" if _key(finding) in in_dependency_scan else "app_library"
    if kind == "os_package":
        if not _fixable(finding):
            return "no_fix"
        return "fix_not_selected" if finding.get("severity") in TOP_SEVERITIES else "fix_below_severity"
    return "inside_program"


def _rag_answer(findings: list[dict]) -> dict | None:
    """The RAG on the critical and high OS packages, the ones listed one by one in the report."""
    seen, ask = set(), []
    for finding in findings:
        if _kind(finding) == "os_package" and finding.get("severity") in TOP_SEVERITIES and _key(finding) not in seen:
            seen.add(_key(finding))
            ask.append(finding)
    return rag_client.response(ask[:MAX_LOOKUPS], "version_upgrade") if ask else None


def fix_availability(finding: dict, answer: dict | None) -> tuple[str, str]:
    """(paid | standard | newer | none | unknown, the words for the report), from the OS's own security data."""
    cve = (finding.get("identifiers") or {}).get("cve") or ""
    if answer is None or not cve:
        return "unknown", "unknown"
    if any(cve in warning for warning in answer.get("warnings") or []):
        return "unknown", "unknown (OSV.dev could not be asked)"
    package = _name(finding).split("/")[0]
    for reference in answer.get("references") or []:
        if reference.get("type") == "advisory" and reference.get("id", "").endswith(cve) and reference.get("package") == package:
            fixed = reference.get("fixed_in")
            if reference.get("subscription_only"):
                return "paid", f"Fix {fixed} only with a subscription: \"{reference.get('availability') or 'subscription required'}\""
            if reference.get("subscription_only") is None:  # a RAG image older than this report doesn't say
                return "unknown", f"Fix {fixed}; whether it needs a subscription is unknown"
            return "standard", f"Fix {fixed} in the OS's standard packages, so a rebuild may pick it up"
        if reference.get("type") == "os_release_fix" and reference.get("id", "").endswith(cve) and reference.get("package") == package:
            newer = ", ".join(f"{release} ({fixed})" for release, fixed in (reference.get("newer_release_fixes") or {}).items())
            return "newer", f"No fix for this OS release; fixed in newer releases: {newer}"
    if not any(u.get("kind") == "image" and u.get("ecosystem") for u in answer.get("upgrades") or []):
        return "unknown", "unknown (base OS not known)"
    return "none", "No fix listed by OSV.dev for this OS release"


def _links(entries: list[dict], batches: dict[str, dict], batch_type: str) -> list[dict]:
    return [e for e in entries if (batches.get(e.get("batch_id")) or {}).get("batch_type") == batch_type]


def _container_fix_lines(entries: list[dict], batches: dict[str, dict], top_with_fix: int) -> list[str]:
    container = _links(entries, batches, "container")
    if not container:
        if top_with_fix:
            return ["The fix stage produced no result for these findings, so check this run's log."]
        return ["Nothing was sent to the fix stage: automatic fixes need an OS package finding that is critical or high "
                "and has a known fix, and there is none."]
    lines = []
    for entry in container:
        if entry.get("pr_url"):
            lines.append(f"A PR was opened: {entry['pr_url']}")
        elif (entry.get("generation") or {}).get("method") == "test_first":
            lines += ["A newer base image was tried, but none passed the app's tests, so there is no PR.", ""]
            lines += [f"- `{f['path']}`: {f['reason']}" for f in entry.get("failed") or []]
        elif (entry.get("generation") or {}).get("method") == "rag":
            lines += ["**Held back, no PR:** nothing safe can be changed without a major version change, which can break "
                      "the app, so a person needs to decide.", ""]
            lines += [f"- `{f['path']}`: {f['reason']}" for f in entry.get("failed") or []]
        else:
            lines.append(f"The automatic fix did not produce a PR: {entry.get('message') or entry.get('status')}")
    return lines


def _option_row(name: str, counts: dict | None) -> str:
    if not counts:
        return f"| {name} | not scanned | not scanned | not scanned |"
    return f"| {name} | {counts['critical']} | {counts['high']} | {counts['total']} |"


def _options_section(findings: list[dict], entries: list[dict], batches: dict[str, dict]) -> list[str]:
    """What a reviewer can choose between for this app's OS packages."""
    today = severity_counts(distinct(findings, "container"))
    if not today["total"]:
        return []
    lines = ["", "### Your options for OS packages", "", "| Option | Critical | High | All |", "|---|---|---|---|",
             _option_row("Stay on the current OS", today)]
    for entry in _links(entries, batches, "container"):
        scan = (entry.get("generation") or {}).get("base_image_scan")
        if scan and entry.get("pr_url"):
            lines.append(_option_row(f"Merge the OS upgrade to `{scan['name']}`: {entry['pr_url']}", scan.get("after")))
        elif scan:
            lines.append(_option_row(f"OS upgrade to `{scan['name']}`: no PR, as it does not help", scan.get("after")))
    return lines


def _reason_table(findings: list[dict], grouped: dict[str, list[dict]], dependency_prs: str) -> list[str]:
    lines = ["| Why there is no automatic fix | Findings | Different vulnerabilities | Critical | High | What you can do |",
             "|---|---|---|---|---|---|"]
    for key, (label, action) in REASONS.items():
        rows = grouped.get(key)
        if rows:
            counts = Counter(f.get("severity") for f in rows)
            lines.append(f"| {label} | {len(rows)} | {len({_key(f) for f in rows})} | {counts['critical']} | {counts['high']} "
                         f"| {action.format(pr=dependency_prs)} |")
    return lines


def _os_package_section(findings: list[dict], answer: dict | None) -> list[str]:
    rows = sorted((f for f in findings if _kind(f) == "os_package" and f.get("severity") in TOP_SEVERITIES),
                  key=lambda f: (SEVERITIES.index(f["severity"]), _name(f)))
    if not rows:
        return []
    answers = [(f, *fix_availability(f, answer)) for f in rows]
    counts = Counter(state for _, state, _ in answers)
    lines = ["", "### OS packages, critical and high", ""]
    if answer is None:
        lines += ["The RAG was not available in this run, so where a fix is published is unknown.", ""]
    else:
        lines += [f"Where a fix is published, from the OS's own security data on OSV.dev: {counts['paid']} only with a paid "
                  f"subscription, {counts['standard']} in the standard packages, {counts['newer']} only in a newer OS release, "
                  f"{counts['none']} with no fix listed, "
                  f"{counts['unknown']} unknown.", ""]
    lines += ["| Package | Vulnerability | Severity | Scanner | Where a fix is published |", "|---|---|---|---|---|"]
    for finding, _, words in answers[:MAX_ROWS]:
        upgrade = (finding.get("remediation") or {}).get("upgrade_to")
        scanner = f"Fix: {upgrade}" if upgrade else "No fix known"
        lines.append(f"| `{(finding.get('location') or {}).get('package')}` | {_vulnerability(finding)} | {finding['severity']} "
                     f"| {scanner} | {words} |")
    if len(answers) > MAX_ROWS:
        lines.append(f"\n*{len(answers) - MAX_ROWS} more not shown.*")
    return lines


def _image_section(answer: dict | None) -> list[str]:
    """The RAG's newer image lines, when the image is one it can look up."""
    with_lines = dict(answer or {}, upgrades=[u for u in (answer or {}).get("upgrades") or [] if u.get("candidates")])
    text = asva_rag_client.pr_upgrades(with_lines)
    return ["", text.replace("### Upgrade summary", "### Newer versions of this image"),
            "", "*\"Checked CVEs\" are the critical and high OS package findings above.*"] if text else []


def _program_section(rows: list[dict]) -> list[str]:
    top = [f for f in rows if f.get("severity") in TOP_SEVERITIES]
    if not top:
        return []
    packages = defaultdict(list)
    for finding in top:
        packages[_name(finding)].append(finding)
    lines = ["", "### Inside programs in the image, critical and high", "",
             "| Library | Different vulnerabilities | Programs | Worst | Scanner's fixed version |", "|---|---|---|---|---|"]
    ordered = sorted(packages.items(), key=lambda kv: (-len({_vulnerability(f) for f in kv[1]}), kv[0]))
    for name, found in ordered[:MAX_ROWS]:
        worst = "critical" if any(f["severity"] == "critical" for f in found) else "high"
        targets = sorted({str((f.get("remediation") or {}).get("upgrade_to")) for f in found if (f.get("remediation") or {}).get("upgrade_to")})
        shown = ", ".join(f"`{t}`" for t in targets[:3]) + (", ..." if len(targets) > 3 else "") or "-"
        lines.append(f"| `{name}` | {len({_vulnerability(f) for f in found})} | {len({(f.get('location') or {}).get('file') for f in found})} "
                     f"| {worst} | {shown} |")
    if len(ordered) > MAX_ROWS:
        lines.append(f"\n*{len(ordered) - MAX_ROWS} more not shown.*")
    return lines


def _dependency_section(rows: list[dict]) -> list[str]:
    if not rows:
        return []
    files = Counter((f.get("location") or {}).get("file") for f in rows)
    return ["", "### Same vulnerabilities as the dependency scan", "",
            "These are the app's own libraries seen again inside the image, not extra container problems. A dependency fix "
            "only changes the files it edits, so check any file below that its PR does not touch.", "",
            "| File in the image | Findings |", "|---|---|", *[f"| `{name}` | {n} |" for name, n in files.most_common(MAX_ROWS)]]


def build_report(all_findings: list[dict], batches: dict[str, dict], entries: list[dict], commit_sha: str,
                 answer: dict | None) -> str:
    findings = [f for f in all_findings if f.get("finding_type") == "container"]
    attempted = {found.get("finding_id") for batch in batches.values() if batch.get("batch_type") == "container"
                 for fix in batch.get("files_to_fix") or [] for found in fix.get("findings") or []}
    in_dependency_scan = {_key(f) for f in all_findings if f.get("finding_type") == "sca"}
    grouped = defaultdict(list)
    for finding in findings:
        grouped[reason(finding, attempted, in_dependency_scan)].append(finding)

    counts = Counter(f.get("severity") for f in findings)
    images = sorted({f"{loc.get('image_name')}:{loc['image_tag']}" if loc.get("image_tag") else str(loc.get("image_name"))
                     for loc in (f.get("location") or {} for f in findings if _kind(f) == "os_package")})
    prs = [e["pr_url"] for e in _links(entries, batches, "sca") if e.get("pr_url")]
    dependency_prs = ", ".join(prs) or "no dependency PR in this run"
    with_fix = sum(1 for f in findings if _kind(f) == "os_package" and _fixable(f) and f.get("severity") in TOP_SEVERITIES)

    run = os.environ.get("GITHUB_RUN_ID")
    where = f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/{os.environ.get('GITHUB_REPOSITORY')}/actions/runs/{run}"
    lines = [
        "This report is updated on every run, so it always shows the latest scan.", "",
        f"- **Commit:** `{commit_sha[:8]}`" + (f" on `{os.environ['GITHUB_REF_NAME']}`" if os.environ.get("GITHUB_REF_NAME") else ""),
        *([f"- **Run:** {where}"] if run else []),
        *([f"- **Image:** {', '.join(f'`{i}`' for i in images)}"] if images else []),
        f"- **Findings:** {len(findings)} (" + ", ".join(f"{counts[s]} {s}" for s in SEVERITIES) + ")",
        "", "### Container fix", "", *_container_fix_lines(entries, batches, with_fix),
        *_options_section(findings, entries, batches),
        "", "### Why the findings have no automatic fix", "", *_reason_table(findings, grouped, dependency_prs),
        *_os_package_section(findings, answer),
        *_image_section(answer),
        *_program_section(grouped.get("inside_program") or []),
        *_dependency_section(grouped.get("same_as_dependency_scan") or []),
        "", "_Written from the scanner's data and the RAG's sources, not by an LLM. \"Unknown\" means they don't say. "
            "ASVA never auto-merges; a person decides what to do with these._",
    ]
    body = "\n".join(lines) + "\n"
    return body if len(body) <= MAX_BODY_CHARS else body[:MAX_BODY_CHARS].rsplit("\n", 1)[0] + "\n\n*Cut here to fit the issue.*\n"


def app_name(repo_name: str) -> str:
    return Path(config.FIX_PATH_PREFIX).name or repo_name


def posts_from_this_branch() -> bool:
    branch = os.environ.get("GITHUB_REF_NAME", "")
    patterns = os.environ.get("ASVA_REPORT_BRANCHES", "").split() or DEFAULT_REPORT_BRANCHES
    return any(fnmatch.fnmatchcase(branch, pattern) for pattern in patterns)


def post(title: str, body: str, has_findings: bool, repo_dir: str = ".") -> str:
    """Update this app's report, or open it if there is something to report."""
    existing = find_open_issue_by_title(title, repo_dir=repo_dir)
    if existing:
        update_issue(existing, body, repo_dir=repo_dir)
        return f"Updated issue #{existing}"
    if not has_findings:
        return "No container findings and no report open: nothing to post"
    return f"Opened: {open_issue(title, body, repo_dir=repo_dir, label=LABEL)}"


def _load_list(path: str) -> list[dict]:
    file = Path(path)
    data = json.loads(file.read_text(encoding="utf-8")) if file.exists() else []
    return data if isinstance(data, list) else data.get("findings") or []


def run(args: argparse.Namespace) -> None:
    findings = _load_list(args.findings)
    batches = {b.get("batch_id"): b for b in (json.loads(p.read_text(encoding="utf-8")) for p in sorted(Path(args.batch_dir).glob("*.json")))}
    container = [f for f in findings if f.get("finding_type") == "container"]
    title = f"ASVA container report for {app_name(args.repo_name)}"
    body = (build_report(findings, batches, _load_list(args.prs_json), args.commit_sha, _rag_answer(container)) if container
            else f"The latest scan (`{args.commit_sha[:8]}`) reported no container findings.\n")
    print(f"=== {title} ===")
    print(body)
    if args.execute and posts_from_this_branch():
        print(post(title, body, bool(container), args.repo_dir))
    elif args.execute:
        print(f"[NOT POSTED] {os.environ.get('GITHUB_REF_NAME') or 'This run'} is not a branch that posts the report: it is above, in this log.")
    else:
        print("[DRY RUN] Not posted. Re-run with --execute to open or update the issue.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Open or update this app's container report issue via gh.")
    parser.add_argument("--findings", required=True, metavar="FILE", help="ranked_unified_findings.json")
    parser.add_argument("--batch-dir", required=True, metavar="DIR", help="Directory of fix_batches/<batch_id>.json files.")
    parser.add_argument("--prs-json", required=True, metavar="FILE", help="Output of agent/agent_loop.py --output-json.")
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--repo-name", required=True)
    parser.add_argument("--repo-dir", default=".", metavar="DIR")
    parser.add_argument("--execute", action="store_true", help="Actually open or update the issue via gh.")
    args = parser.parse_args()
    try:
        run(args)
    except (GitOpError, OSError, ValueError, KeyError, TypeError) as e:
        print(f"::warning::The container report could not be posted: {e}")


if __name__ == "__main__":
    main()
