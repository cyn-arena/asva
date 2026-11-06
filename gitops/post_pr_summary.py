"""
gitops/post_pr_summary.py -- a table at the top of each fix PR: what is left if you merge it.

The rescan of each PR runs after the PRs open, so its result can't be in the description they open
with. This runs after the rescans and adds it, so a reviewer can choose between PRs without reading
logs: findings left by severity for each option, what the option adds, and whether the app's tests
passed. All from the scanner's rescan and the pipeline's validation, not an LLM. A rescan that is
missing says so rather than showing a number.

Only standard library, as this runs by itself in a job of its own. A problem warns and never fails the run.

Usage (the run's artifacts in one folder, each in a folder named after the artifact):
  python gitops/post_pr_summary.py --app <app-code> --artifacts <dir>   # dry run, prints each table
      [--execute]                                                       # actually edits the PRs via gh
"""

import argparse
import glob
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

START, END = "<!-- asva-summary-start -->", "<!-- asva-summary-end -->"
SEVERITIES = ("critical", "high", "medium", "low")
TOP = ("critical", "high")
SAME_MAJOR_SUFFIX = "_same_major"
MAJOR_LABEL = "major version upgrades"
KIND_LABELS = {"sca": "dependency findings", "sast": "code findings", "container": "OS package findings"}
MAX_LISTED = 40
MAX_BODY_CHARS = 64_000


def _in_scope(finding: dict, batch_type: str) -> bool:
    if batch_type == "container":
        return finding.get("finding_type") == "container" and (finding.get("location") or {}).get("kind") == "os_package"
    return finding.get("finding_type") == batch_type


def _package(finding: dict) -> str:
    return ((finding.get("location") or {}).get("package") or "").rsplit("@", 1)[0].lower()


def _cell(text: object) -> str:
    """Scanner text made safe inside a table cell: a stray "|" would end the cell early."""
    return " ".join(str(text).split()).replace("|", "\\|")


def _key(finding: dict) -> tuple[str, str]:
    ids = finding.get("identifiers") or {}
    return (ids.get("cve") or ids.get("rule_id") or finding.get("title") or "-",
            _package(finding) or (finding.get("location") or {}).get("file") or "")


def _route(finding: dict) -> tuple:
    """The steps the scanner traced from source to sink, or the flagged line if it traced none."""
    location = finding.get("location") or {}
    return (tuple((step.get("file"), step.get("line")) for step in finding.get("code_flow") or [])
            or ((location.get("file"), location.get("line")),))


def distinct(findings: list[dict], batch_type: str) -> dict[tuple, dict]:
    """One per vulnerability: the same one in several files is one thing to fix. Code findings are
    the exception, as each route the scanner traces is its own thing to fix, and one route reported at
    several lines (a call and the wrapper it goes through) is one. They are numbered within their rule
    and the file the route starts in rather than keyed by line, as a fix moves the lines of whatever stays."""
    found: dict[tuple, dict] = {}
    routes: dict[tuple, set] = {}
    for finding in findings:
        if _in_scope(finding, batch_type):
            key = _key(finding)
            if batch_type == "sast":
                route = _route(finding)
                seen = routes.setdefault((key[0], route[0][0] or key[1]), set())
                if route in seen:
                    continue
                seen.add(route)
                key = (key[0], route[0][0] or key[1], len(seen))
            found.setdefault(key, finding)
    return found


def still_flagged(targets: list[dict], today: dict, after: dict) -> list[tuple[str, str, int]]:
    """(rule, file, how many) of what a code fix set out to fix and the scanner still reports. If the
    fix had worked, each target would take one off its rule and file's count."""
    def count(found: dict) -> Counter:
        return Counter(key[:2] for key in found)

    aimed, before, left = count(distinct(targets, "sast")), count(today), count(after)
    return [(rule, file, min(number, left[(rule, file)] - before[(rule, file)] + number))
            for (rule, file), number in sorted(aimed.items())
            if left[(rule, file)] - before[(rule, file)] + number > 0]


def severity_counts(found: dict) -> dict[str, int]:
    counts = Counter(f.get("severity") for f in found.values())
    return {**{s: counts[s] for s in SEVERITIES}, "total": len(found)}


def _load(path: str | Path) -> list[dict]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return data if isinstance(data, list) else data.get("findings") or []


def _top(found: dict) -> int:
    return sum(f.get("severity") in TOP for f in found.values())


def label_of(batch: dict, batches: dict[str, dict]) -> str:
    if batch.get("pr_choice"):
        return batch["pr_choice"]
    return MAJOR_LABEL if f"{batch.get('batch_id')}{SAME_MAJOR_SUFFIX}" in batches else "this fix"


def _row(name: str, found: dict | None, new: int | str, tests: str) -> str:
    if found is None:
        return f"| {name} | - | - | - | - | rescan missing | - | {tests} |"
    counts = Counter(f.get("severity") for f in found.values())
    return f"| {name} | {' | '.join(str(counts[s]) for s in SEVERITIES)} | {len(found)} | {new} | {tests} |"


def _advice(options: list[dict], today: dict) -> str:
    """Only what the numbers show. The reviewer decides."""
    safe = next((o for o in options if o["batch_id"].endswith(SAME_MAJOR_SUFFIX)), None)
    major = next((o for o in options if safe and o is not safe), None)
    if not safe or not major or safe["found"] is None or major["found"] is None:
        return ""
    if len(major["found"]) >= len(safe["found"]) and _top(major["found"]) >= _top(safe["found"]):
        return ("**The safe PR is at least as good here:** the major version upgrades leave as many findings or more, "
                "so they add risk for no gain.")
    return (f"**The major version PR leaves {len(safe['found']) - len(major['found'])} fewer findings "
            f"({_top(safe['found']) - _top(major['found'])} fewer critical or high)**, but its upgrades need a closer look.")


def build_summary(me: dict, options: list[dict], today: dict, batch_type: str) -> str:
    """The block for one PR: every option for the same fix, with this PR marked."""
    lines = [START, "", f"## Compare your options: {KIND_LABELS.get(batch_type, 'findings')} left after merging", "",
             f"From the scanner's rescan of each PR. {'Each route the scanner traces' if batch_type == 'sast' else 'Each vulnerability'} counts once.", "",
             "| Option | Critical | High | Medium | Low | Total | New | App tests |", "|---|---|---|---|---|---|---|---|",
             _row("Don't merge (today)", today, "-", "-")]
    for option in options:
        name = f"**This PR: {option['label']}**" if option is me else f"[#{option['number']}]({option['pr_url']}): {option['label']}"
        new = "?" if option["found"] is None else len(set(option["found"]) - set(today))
        lines.append(_row(name, option["found"], new, option["tests"]))
    advice = _advice(options, today)
    if advice:
        lines += ["", advice]
    if me.get("still_flagged"):
        lines += ["", "**Still flagged after this fix.** This PR set out to fix these, but the scanner still reports them. "
                      "The fix may still work, as the scanner doesn't recognise every safety check, so check these by hand:", ""]
        lines += [f"- `{_cell(file)}`: {_cell(rule)}{f' ({number} of them)' if number > 1 else ''}" for rule, file, number in me["still_flagged"]]
    if me["found"] is not None:
        top = {k: f for k, f in me["found"].items() if f.get("severity") in TOP}
        new = [k for k in top if k not in today]
        rated_up = [k for k in top if k in today and today[k].get("severity") not in TOP]
        if new or rated_up:
            parts = []
            if new:
                parts.append(f"{len(new)} {'is' if len(new) == 1 else 'are'} new")
            if rated_up:
                parts.append("1 was already there, but the scanner rates it lower today" if len(rated_up) == 1
                             else f"{len(rated_up)} were already there, but the scanner rates them lower today")
            lines += ["", f"Of the critical and high ones left after this PR, {' and '.join(parts)}."]
        if top:
            ordered = sorted(top.items(), key=lambda kv: (SEVERITIES.index(kv[1]["severity"]), kv[0][1], kv[0][0]))
            lines += ["", f"<details><summary>The {len(top)} critical and high left after this PR</summary>", "",
                      "| Package or file | Vulnerability | Severity | Already there today? |", "|---|---|---|---|"]
            lines += [f"| `{_cell(k[1] or '-')}` | {_cell(k[0])} | {f['severity']} | {'yes' if k in today else '**no, new**'} |" for k, f in ordered[:MAX_LISTED]]
            if len(ordered) > MAX_LISTED:
                lines.append(f"\n*{len(ordered) - MAX_LISTED} more not shown.*")
            lines += ["", "</details>"]
        else:
            lines += ["", "No critical or high left in these findings after this PR."]
    lines += ["", END, ""]
    return "\n".join(lines)


def with_summary(body: str, block: str) -> str:
    """The description with the block at the top, replacing an earlier one if a rerun got here first."""
    if START in body and END in body:
        body = body[:body.index(START)] + body[body.index(END) + len(END):].lstrip("\n")
    return f"{block}\n{body}"[:MAX_BODY_CHARS]


def _tests_result(artifacts: Path, app: str, batch_id: str) -> str:
    files = glob.glob(str(artifacts / f"{app}-validation-{batch_id}" / "**" / "validation" / f"{batch_id}.json"), recursive=True)
    try:
        return json.loads(Path(files[0]).read_text(encoding="utf-8")).get("result") or "unknown" if files else "unknown"
    except (OSError, ValueError):
        return "unknown"


def collect(artifacts: Path, app: str) -> list[tuple[dict, list[dict], dict, str]]:
    """(this PR, every option for its fix, today's findings, batch type) for each PR of this run."""
    root = artifacts / f"{app}-fix-output"
    entries = json.loads((root / "prs.json").read_text(encoding="utf-8"))
    batches = {b["batch_id"]: b for b in (json.loads(p.read_text(encoding="utf-8")) for p in (root / "fix_batches").glob("*.json"))}
    today_all = _load(root / "findings" / "ranked_unified_findings.json")
    groups: dict[str, list[dict]] = {}
    for entry in entries:
        batch = batches.get(entry.get("batch_id"))
        if not batch or not entry.get("pr_url"):
            continue
        batch_id = batch["batch_id"]
        rescan = glob.glob(str(artifacts / f"{app}-after-fix-{batch_id}" / "**" / "ranked_unified_findings.json"), recursive=True)
        groups.setdefault(batch_id.removesuffix(SAME_MAJOR_SUFFIX), []).append({
            "batch_id": batch_id, "pr_url": entry["pr_url"], "number": entry["pr_url"].rsplit("/", 1)[-1],
            "label": label_of(batch, batches), "batch_type": batch.get("batch_type", ""),
            "found": distinct(_load(rescan[0]), batch.get("batch_type", "")) if rescan else None,
            "tests": _tests_result(artifacts, app, batch_id),
            "left_out": {f["path"] for f in (entry.get("blocked") or []) + (entry.get("failed") or [])}})
    result = []
    for options in groups.values():
        # the safe option first: the one to start from
        options.sort(key=lambda o: not o["batch_id"].endswith(SAME_MAJOR_SUFFIX))
        today = distinct(today_all, options[0]["batch_type"])
        for option in options:
            if option["batch_type"] == "sast" and option["found"] is not None:
                # A file that never reached the PR was not fixed and found wanting: the PR lists it as left out.
                targets = [f for fe in batches[option["batch_id"]].get("files_to_fix", [])
                           if fe.get("file") not in option["left_out"] for f in fe.get("findings", [])]
                option["still_flagged"] = still_flagged(targets, today, option["found"])
        result += [(option, options, today, option["batch_type"]) for option in options]
    return result


def _gh(*args: str, stdin: str | None = None) -> str:
    done = subprocess.run(["gh", *args], input=stdin, capture_output=True, text=True, encoding="utf-8", timeout=120, check=True)
    return done.stdout


def main() -> None:
    parser = argparse.ArgumentParser(description="Add a compare-your-options table to each fix PR.")
    parser.add_argument("--app", required=True)
    parser.add_argument("--artifacts", required=True, metavar="DIR")
    parser.add_argument("--execute", action="store_true", help="Actually edit the PRs via gh.")
    args = parser.parse_args()
    try:
        items = collect(Path(args.artifacts), args.app)
    except (OSError, ValueError, KeyError) as e:
        print(f"::warning::No PR summaries: {e}")
        return
    for me, options, today, batch_type in items:
        block = build_summary(me, options, today, batch_type)
        print(f"=== #{me['number']} {me['label']} ===\n{block}")
        if not args.execute:
            continue
        try:
            body = json.loads(_gh("pr", "view", me["pr_url"], "--json", "body"))["body"]
            _gh("pr", "edit", me["pr_url"], "--body-file", "-", stdin=with_summary(body, block))
            print(f"Updated {me['pr_url']}")
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as e:
            print(f"::warning::Could not update {me['pr_url']}: {e}")


if __name__ == "__main__":
    sys.exit(main())
