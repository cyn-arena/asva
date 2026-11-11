"""
agent/test_first.py -- test fixes before there is a PR (option A, ITP2 3.3).

Dependency fixes. "No major version change" keeps most apps working, but it still let PyYAML 5.4 through, which
cannot install on Python 3.11, and it holds back upgrades that would have worked. Only building and
testing tells them apart, so for a dependency batch:

  1. Test the safe candidate. If it works, it is the starting point. If not, add its upgrades one at
     a time and keep the ones that work.
  2. Go through the RAG's trial plan (security_context/app/trials.py) in order: apply one held-back
     upgrade, with the others it needs, on top of what has passed. Keep it if the app still works.
  3. An upgrade that fails gets the other versions the RAG lists for it, in order: a lower version
     the scanner names, or for a safe upgrade that won't install, a newer one with no known advisory.

Only what passed goes into the PR, and the PR says what was tried. If nothing passed there is no PR.

A major version change that passes the app's tests can still need a person to look at it, so when
one is kept the reviewer gets to choose: a second PR holds only the upgrades within the same major
version, tested exactly as it stands. Both edit the same files, so they merge one, and each PR says so.

Code and container fixes. These come from the LLM, so a failure goes back to it: at most
ASVA_TEST_FIRST_RETRIES rounds (default 2) with what went wrong, for the files the failure points
at, or all of them when it points nowhere. If it still fails, the PR opens as a draft with the best
attempt and the failure explained: such a PR usually holds several good fixes next to one bad one.

A candidate is never thrown away because the check itself is unusable: when a candidate fails, the
unchanged app is checked too, and if that also fails (or Docker is unavailable) the candidate goes
ahead marked as not verified, for the pipeline's later checks and the reviewer.

Holes the scanner can't see. With ASVA_MISUSE_FIX=1, once a code fix passes, the app's other security
tests run on it. For each that shows a hole, the LLM gets one try at the files the test is linked to
by its `# @a` comments, one test at a time. A fix that passes everything so far is kept as its own
commit in the same PR, so a reviewer can revert just that; one that doesn't is dropped and the hole
stays listed as still vulnerable. A passing test only proves that one attack is blocked, not that
legitimate users still get in, so the PR asks for a careful review.

What a fix adds. With ASVA_SCAN_BEFORE_PR=1, a code fix that passes is scanned (agent/code_scan.py). A
new critical or high goes back to the LLM once. A retry is kept only if it still passes and leaves
fewer of them. If any are left, the PR opens as a draft and names them. A kept misuse fix is scanned
too, without a retry, as it is its own commit a reviewer can revert.

A newer base image (agent/base_image.py) is a mechanical edit, so there is no LLM to go back to. If it
does not pass there is no PR, and a check that could not run does not count as passing: this changes
a whole OS.

On when ASVA_TEST_FIRST=1, for an app that has given agent/app_check.py its settings; without them
the PR says it was not tested. ASVA_TEST_FIRST_MINUTES (default 30) limits the time per batch: what
was not reached stays in the PR's list to try. A dependency file the trial loop cannot edit (it
knows requirements.txt and the npm path) is handled like a code fix: tested, retried, then a draft.
"""

from __future__ import annotations

import copy
import os
import re
import time
from pathlib import Path
from typing import Callable

from agent import app_check, base_image, code_scan, npm_remediation, pr_test_selector, rag_client, safe_upgrades
from agent.test_annotations import parse_annotated_files
from gitops import config

SAFE_LABEL = "safe upgrades, no major versions"
MAJOR_LABEL = "major version upgrades"
SAME_MAJOR_SUFFIX = "_same_major"

# Development tools are not in the running app, so the app's checks cannot tell if they work.
_TRIAL_KINDS = ("major_upgrade", "parent_upgrade", "lockfile_refresh")


def enabled() -> bool:
    return os.environ.get("ASVA_TEST_FIRST", "").strip() == "1"


def _minutes() -> float:
    return float(os.environ.get("ASVA_TEST_FIRST_MINUTES") or 30)


def _retries() -> int:
    return int(os.environ.get("ASVA_TEST_FIRST_RETRIES") or 2)


def misuse_fix_enabled() -> bool:
    return os.environ.get("ASVA_MISUSE_FIX", "").strip() == "1"


def set_version(text: str, name: str, version: str) -> str:
    """requirements.txt with one package pinned to another version (names compared as pip does)."""
    name_pattern = "[-_.]".join(re.escape(part) for part in re.split(r"[-_.]+", name))
    return re.sub(rf"(?im)^({name_pattern}\s*==\s*)\S+", lambda m: m.group(1) + version, text, count=1)


def _finding_id(finding: dict) -> str:
    ids = finding.get("identifiers") or {}
    return ids.get("cve") or ids.get("rule_id") or ""


def _package_name(finding: dict) -> str:
    return ((finding.get("location") or {}).get("package") or "").rsplit("@", 1)[0].lower()


def _trials(answer: dict | None) -> list[dict]:
    return [t for t in (answer or {}).get("trials") or []
            if t.get("kind") in _TRIAL_KINDS and not t.get("dev_only") and t.get("fixes")]


def _options(trial: dict) -> list[dict]:
    """The trial as planned, then as each other version to try if it fails."""
    return [trial, *(dict(trial, target=f["target"], also_needs=f.get("also_needs") or []) for f in trial.get("fallbacks") or [])]


def _version(text: str | None) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", text or ""))


def _retarget(findings: list[dict], name: str, version: str) -> None:
    """The findings of a package this version fixes, going by the scanner's own target for each: a
    lower version kept after a higher one failed does not fix what only the higher one does."""
    for f in findings:
        if _package_name(f) != name.lower():
            continue
        remediation = f["remediation"]
        wanted = remediation.get("scanner_upgrade_to") or remediation.get("upgrade_to") or ""
        if _version(wanted.rpartition("@")[2]) <= _version(version):
            remediation["upgrade_to"] = f"{name}@{version}"


def pinned_version(text: str, name: str) -> str:
    """The version requirements.txt pins a package to with `==`, or "" (names compared as pip does)."""
    name_pattern = "[-_.]".join(re.escape(part) for part in re.split(r"[-_.]+", name))
    match = re.search(rf"(?im)^{name_pattern}\s*==\s*(\S+)", text)
    return match.group(1) if match else ""


def _major_change(current: str, version: str) -> bool:
    """As for semantic versions: in 0.x, a change of the second number is a major one."""
    old, new = _version(current), _version(version)
    if not old or not new:
        return True
    return old[:2] != new[:2] if old[0] == 0 else old[0] != new[0]


def _choice_text(batch: dict, same_major: bool, other_id: str) -> None:
    text = (f"This PR has only safe upgrades, with no major version changes: lower risk, but it may fix less. Branch `fix/{other_id}` "
            "also has the major version upgrades that passed." if same_major else
            f"This PR includes major version upgrades that passed the app's tests: it may fix more, but needs a closer look. Branch "
            f"`fix/{other_id}` has only the safe upgrades. The table at the top compares them once the rescans finish.")
    _add_to_pr_text(batch, f"### Pick one of two\n\n> {text} Both edit the same files, so merge only one of them.")


def _offer_same_major(entry: dict, batch: dict, files: list[dict], generation: dict | None = None) -> None:
    """Attach the second PR's entry, for agent_loop to submit after this one."""
    other_id = f"{entry['batch']['batch_id']}{SAME_MAJOR_SUFFIX}"
    batch["batch_id"], batch["pr_choice"] = other_id, SAFE_LABEL
    entry["batch"]["pr_choice"] = MAJOR_LABEL
    _choice_text(batch, True, entry["batch"]["batch_id"])
    _choice_text(entry["batch"], False, other_id)
    print(f"    [test-first] two PRs for the reviewer to pick from: {other_id} also opens")
    entry["same_major"] = {"batch": batch, "files": files, "generation": generation or dict(entry.get("generation") or {})}


def _with_companions(text: str, option: dict) -> str:
    text = set_version(text, option["name"], option["target"])
    for companion in option.get("also_needs") or []:
        if companion.get("suggest"):
            text = set_version(text, companion["name"], companion["suggest"])
    return text


def _label(trial: dict) -> str:
    if trial["kind"] == "lockfile_refresh":
        return f"`{(trial.get('note') or 'npm update').split(':')[0].strip('`')}`"
    also = "".join(f" with `{c['name']}` {c.get('suggest')}" for c in trial.get("also_needs") or [] if c.get("suggest"))
    return f"`{trial['name']}` {trial.get('current') or ''} → {trial.get('target')}{also}"


def _why(result: app_check.Result) -> str:
    """One line for a table: every failure gets its share, so a long one can't hide the next."""
    failures = [" ".join(failure.split())[:300] for failure in result.detail.split(" | ")]
    return f"{result.stage}: {' | '.join(failures)}"[:900].replace("|", "\\|")


def _table(rows: list[tuple[str, str, str]], unverified: str) -> str:
    lines = ["### Tested before this PR", ""]
    if unverified:
        lines += [f"> **Not verified:** {unverified}", ""]
    if rows:
        lines += ["Each was built, started and smoke-tested. Only what is marked as kept is in this PR.", "",
                  "| Tried | Result | Why |", "|---|---|---|", *[f"| {a} | {b} | {c} |" for a, b, c in rows]]
    return "\n".join(lines)


def _pr_text(batch: dict, answer: dict | None, rows: list, tried: set[int], unverified: str = "") -> None:
    """The RAG's text, without the trials this run already tried, after what the tests showed."""
    remaining = dict(answer or {}, trials=[t for t in (answer or {}).get("trials") or [] if t.get("order") not in tried])
    safe_upgrades.add_pr_text(batch, [remaining] if answer else [])
    batch["rag_pr_text"] = "\n\n".join(p for p in (_table(rows, unverified), batch.get("rag_pr_text")) if p)


def _nothing_passed(entry: dict, path: str, rows: list) -> dict:
    print("    [test-first] nothing passed: no PR for this batch")
    reason = "every candidate failed the app check: " + "; ".join(f"{a} ({c})" for a, _, c in rows)[:900]
    entry["files"] = []
    entry["generation"] = {"method": "test_first", "status": "no_candidate", "message": "No candidate passed the app check",
                           "files": [{"path": path, "status": reason}], "rag_text": _table(rows, "")}
    return entry


def _candidate_stands(result: app_check.Result, repo_dir: str) -> tuple[bool, str]:
    """(usable, why not verified). A failed candidate only counts if the unchanged app passes."""
    if result.passed:
        return True, ""
    if result.stage == "unavailable":
        return True, f"the app check could not run ({result.detail})."
    baseline = app_check.check({}, repo_dir)
    if not baseline.passed:
        return True, f"the unchanged app also fails the check ({_why(baseline)}), so it cannot judge this fix."
    return False, ""


# -- requirements.txt (the LLM wrote the first candidate) ------------------------------------------

def _requirements(entry: dict, repo_dir: str, upgrade_map: Callable, notes: Callable | None) -> dict:
    batch = entry["batch"]
    file = entry["files"][0]
    path = file["path"]
    fe = next(e for e in batch["files_to_fix"] if e["file"] == path)
    findings = fe["findings"]
    original = (Path(repo_dir) / config.FIX_PATH_PREFIX / path).read_text(encoding="utf-8")
    deadline = time.monotonic() + _minutes() * 60
    rows: list[tuple[str, str, str]] = []
    answer = rag_client.manifest_response(path, original, findings, fe["fix_type"])

    print(f"    [test-first] checking the safe candidate for {path}")
    first = app_check.check({path: file["content"]}, repo_dir)
    usable, unverified = _candidate_stands(first, repo_dir)
    if unverified:
        print(f"    [test-first] {unverified}")
        _pr_text(batch, answer, [], set(), unverified)
        return entry
    current = file["content"]
    # What stays within the same major version, kept alongside, for the reviewer's other choice.
    same, kept_same, rows_same = current, {}, []
    if usable:
        rows.append(("The safe upgrades together", "kept", ""))
        kept_same = dict(upgrade_map(findings))
        rows_same.append(rows[-1])
    else:
        rows.append(("The safe upgrades together", "failed", _why(first)))
        rows_same.append(rows[-1])
        current = same = original
        for name, version in upgrade_map(findings).items():
            if time.monotonic() >= deadline:
                rows.append((f"`{name}` {version}", "not tried", "out of time"))
                _drop(findings, name)
                continue
            attempt = set_version(current, name, version)
            result = app_check.check({path: attempt}, repo_dir) if attempt != current else app_check.Result(True, "passed")
            print(f"    [test-first] {name} {version}: {result.stage}")
            if result.passed:
                current = attempt
                rows.append((f"`{name}` {version}", "kept", ""))
                rows_same.append(rows[-1])
                same = set_version(same, name, version)
                kept_same[name] = version
                continue
            rows.append((f"`{name}` {version}", "failed", _why(result)))
            rows_same.append(rows[-1])
            _drop(findings, name)
            for fallback in _safe_fallbacks(answer, name):
                if time.monotonic() >= deadline:
                    break
                option = {"name": name, "target": fallback["target"], "also_needs": fallback.get("also_needs") or []}
                attempt = _with_companions(current, option)
                result = app_check.check({path: attempt}, repo_dir)
                print(f"    [test-first] {name} {fallback['target']} instead: {result.stage}")
                if result.passed:
                    current = attempt
                    _retarget(findings, name, fallback["target"])
                    rows.append((f"`{name}` {fallback['target']} instead of {version}", "kept", ""))
                    if not _major_change(pinned_version(original, name), fallback["target"]):
                        rows_same.append(rows[-1])
                        same = _with_companions(same, option)
                        kept_same[name] = fallback["target"]
                    break
                rows.append((f"`{name}` {fallback['target']} instead of {version}", "failed", _why(result)))
                if not _major_change(pinned_version(original, name), fallback["target"]):
                    rows_same.append(rows[-1])

    tried: set[int] = set()
    for trial in _trials(answer):
        if time.monotonic() >= deadline:
            print("    [test-first] out of time for more trials")
            break
        tried.add(trial["order"])
        for option in _options(trial):
            if time.monotonic() >= deadline:
                rows.append((_label(option), "not tried", "out of time"))
                break
            attempt = _with_companions(current, option)
            result = app_check.check({path: attempt}, repo_dir)
            print(f"    [test-first] trial {trial['order']} {option['name']} {option['target']}: {result.stage}")
            if result.passed:
                current = attempt
                rows.append((_label(option), "kept", ""))
                _retarget(findings, option["name"], option["target"])
                if trial["kind"] != "major_upgrade":
                    rows_same.append(rows[-1])
                    same = _with_companions(same, option)
                    kept_same[option["name"]] = option["target"]
                break
            rows.append((_label(option), "failed", _why(result)))

    if current == original:
        return _nothing_passed(entry, path, rows)
    file["content"] = current
    _pr_text(batch, answer, rows, tried)
    _add_review_notes(batch, path, repo_dir, upgrade_map(findings), notes)
    if same not in (original, current):
        _same_major_requirements(entry, path, same, kept_same, rows_same, answer, repo_dir)
    return entry


def _same_major_requirements(entry: dict, path: str, same: str, kept: dict[str, str], rows: list, answer: dict | None, repo_dir: str) -> None:
    """The second PR, if the same-major upgrades pass by themselves. They were tested along with the
    others until now, and each PR is tested exactly as it would ship."""
    result = app_check.check({path: same}, repo_dir)
    print(f"    [test-first] same major versions only: {result.stage}")
    if not result.passed:
        return
    batch = copy.deepcopy(entry["batch"])
    batch.pop("rag_pr_text", None)
    batch.pop("review_notes", None)
    wanted = {name.lower(): version for name, version in kept.items()}
    for fe in batch["files_to_fix"]:
        for f in fe["findings"]:
            remediation = f["remediation"]
            scanner = remediation.get("scanner_upgrade_to") or remediation.get("upgrade_to") or ""
            name = scanner.rpartition("@")[0].lower() or _package_name(f)
            version = wanted.get(name)
            covers = version and _version(scanner.rpartition("@")[2]) <= _version(version)
            remediation["upgrade_to"] = f"{name}@{version}" if covers else None
    _pr_text(batch, answer, rows, set())
    _offer_same_major(entry, batch, [{"path": path, "content": same}])


def _safe_fallbacks(answer: dict | None, name: str) -> list[dict]:
    return next((u.get("fallbacks") or [] for u in (answer or {}).get("upgrades") or []
                 if u.get("kind") == "package" and u.get("name", "").lower() == name.lower()), [])


def _drop(findings: list[dict], name: str) -> None:
    for f in findings:
        remediation = f.get("remediation") or {}
        if (remediation.get("upgrade_to") or "").rpartition("@")[0].lower() == name.lower():
            remediation["upgrade_to"] = None


# -- npm (npm writes the package.json and package-lock.json pair) --------------------------------

def _pair(result: dict) -> dict[str, str]:
    return {f["path"]: f["content"] for f in result.get("files") or []}


def _npm(entry: dict, repo_dir: str, notes: Callable | None) -> dict:
    # generate() returns a copy of the batch: this one stays the source of truth for every attempt.
    batch = entry["batch"]
    fe = next(e for e in batch["files_to_fix"] if e.get("findings"))
    findings = fe["findings"]
    deadline = time.monotonic() + _minutes() * 60
    rows: list[tuple[str, str, str]] = []

    print("    [test-first] checking the safe npm candidate")
    first = app_check.check(_pair(entry), repo_dir)
    usable, unverified = _candidate_stands(first, repo_dir)
    pair = _pair(entry)
    if unverified:
        print(f"    [test-first] {unverified}")
        answer = rag_client.npm_response(findings, fe.get("fix_type"), pair["package.json"], pair["package-lock.json"])
        _pr_text(batch, answer, [], set(), unverified)
        return entry
    updates: list[str] = []
    if usable:
        rows.append(("The safe upgrades together", "kept", ""))
    else:
        rows.append(("The safe upgrades together", "failed", _why(first)))
        planned = {name: u["to"] for name, u in (batch.get("npm_upgrades") or {}).items()}
        saved = {id(f): (f.get("remediation") or {}).get("upgrade_to") for f in findings}
        for f in findings:
            if f.get("remediation"):
                f["remediation"]["upgrade_to"] = None
        best: dict | None = None
        for name, version in planned.items():
            chosen = [f for f in findings if (saved[id(f)] or "").rpartition("@")[0] == name]
            for f in chosen:
                f["remediation"]["upgrade_to"] = saved[id(f)]
            result = npm_remediation.generate(batch, repo_dir)
            check = app_check.check(_pair(result), repo_dir) if _pair(result) else app_check.Result(False, "build", result["generation"].get("message", ""))
            print(f"    [test-first] {name} {version}: {check.stage}")
            if check.passed:
                best = result
                rows.append((f"`{name}` {version}", "kept", ""))
            else:
                for f in chosen:
                    f["remediation"]["upgrade_to"] = None
                rows.append((f"`{name}` {version}", "failed", _why(check)))
        if best is None:
            return _nothing_passed(entry, "package.json", rows)
        entry.update(best)

    pair = _pair(entry)
    answer = rag_client.npm_response(findings, fe.get("fix_type"), pair["package.json"], pair["package-lock.json"])
    tried: set[int] = set()
    # Major upgrades come last in the plan, so what has passed by then is the same-major choice, as tested.
    before_majors: tuple | None = None
    major_kept = False
    for trial in _trials(answer):
        if time.monotonic() >= deadline:
            print("    [test-first] out of time for more trials")
            break
        if trial["kind"] == "major_upgrade" and before_majors is None:
            before_majors = (copy.deepcopy(entry), list(rows), set(tried))
        tried.add(trial["order"])
        changed = [f for f in findings if _finding_id(f) in trial["fixes"]]
        before = [(f, (f.get("remediation") or {}).get("upgrade_to")) for f in changed]
        for option in _options(trial):
            if time.monotonic() >= deadline:
                rows.append((_label(option), "not tried", "out of time"))
                break
            attempt_updates = list(updates)
            if trial["kind"] == "lockfile_refresh":
                attempt_updates += sorted({_package_name(f) for f in changed} - {""})
            else:
                for f in changed:
                    f["remediation"]["upgrade_to"] = f"{option['name']}@{option['target']}"
            result = npm_remediation.generate(batch, repo_dir, update=attempt_updates)
            planned = (result["batch"].get("npm_upgrades") or {}).get(option["name"], {}).get("to")
            if trial["kind"] != "lockfile_refresh" and planned != option["target"]:
                # Not a direct dependency: package.json cannot set it, so there is nothing to test.
                for f, value in before:
                    f["remediation"]["upgrade_to"] = value
                print(f"    [test-first] trial {trial['order']} {_label(option)}: not a direct dependency")
                rows.append((_label(option), "not tried", "not a direct dependency of the app"))
                break
            check = app_check.check(_pair(result), repo_dir) if _pair(result) else app_check.Result(False, "build", result["generation"].get("message", ""))
            print(f"    [test-first] trial {trial['order']} {_label(option)}: {check.stage}")
            if check.passed:
                entry.update(result)
                updates = attempt_updates
                rows.append((_label(option), "kept", ""))
                major_kept = major_kept or trial["kind"] == "major_upgrade"
                break
            for f, value in before:
                f["remediation"]["upgrade_to"] = value
            rows.append((_label(option), "failed", _why(check)))

    _pr_text(entry["batch"], answer, rows, tried)
    _add_review_notes(entry["batch"], "package.json", repo_dir,
                      {name: u["to"] for name, u in (entry["batch"].get("npm_upgrades") or {}).items()}, notes)
    if major_kept and before_majors and _pair(before_majors[0]) != _pair(entry):
        same_entry, same_rows, same_tried = before_majors
        same_entry["batch"].pop("rag_pr_text", None)
        same_entry["batch"].pop("review_notes", None)
        _pr_text(same_entry["batch"], answer, same_rows, same_tried)
        _offer_same_major(entry, same_entry["batch"], same_entry["files"], same_entry.get("generation"))
    return entry


def _add_review_notes(batch: dict, path: str, repo_dir: str, upgrades: dict[str, str], notes: Callable | None) -> None:
    """Point the reviewer at the code that uses a package whose major version this PR now changes.
    Only a help for the reviewer, so a problem here must not cost the fixes that were tested."""
    if not notes:
        return
    try:
        original = (Path(repo_dir) / config.FIX_PATH_PREFIX / path).read_text(encoding="utf-8")
        found = notes(path, original, upgrades)
    except Exception as e:  # noqa: BLE001
        print(f"    [test-first] [WARN] no reviewer notes for {path} ({e})")
        return
    if found:
        batch.setdefault("review_notes", {})[path] = found


# -- code and container fixes (the LLM wrote them, so a failure goes back to it) -------------------

def _security_test_source() -> str:
    """The app's security tests (ASVA_APP_SECURITY_TESTS_FILE), linked to the files they cover by
    `# @a <file>` comments. "" when the app has none."""
    setting = os.environ.get("ASVA_APP_SECURITY_TESTS_FILE", "").strip()
    path = app_check.ROOT / setting
    return path.read_text(encoding="utf-8") if setting and path.is_file() else ""


def _security_tests(batch: dict) -> list[str]:
    """The security tests this batch really aims at. A known case that only shares a file with it
    can still be vulnerable by design, so it says nothing about these fixes."""
    source = _security_test_source()
    if not source or not app_check.has_security_command():
        return []
    report = pr_test_selector.build_match_report(pr_test_selector.batch_changed_files(batch), source,
                                                 pr_test_selector.batch_rule_ids(batch))
    return [t["test_name"] for t in report["matched_tests"] if t.get("attempted") is not False]


def _suspects(result: app_check.Result, paths: list[str]) -> list[str]:
    """The files this failure points at: named in the error, or linked to a failed security test by
    its `# @a` annotation. All of them as soon as one failure points nowhere: narrowing to the files
    another failure names would leave it unfixed. An app that did not start has one failure, and its
    log's traceback is what names the file. After that the log is left out, as it can name any file."""
    annotated = parse_annotated_files(_security_test_source())
    texts = [f"{result.detail}\n{result.log}"] if result.stage != "smoke" else result.detail.split(" | ")
    named = set()
    for text in texts:
        found = {p for p in paths if p in text}
        for test, files in annotated.items():
            if test in text:
                found |= set(files) & set(paths)
        if not found:
            return paths
        named |= found
    return [p for p in paths if p in named]


def _remember_failures(entry: dict, failures: dict[str, str]) -> None:
    """What still fails, per file, after the retries: saved to memory (3.5) after submission, so the
    next run's prompt says what this pass broke ("errors from pass N-1")."""
    entry.setdefault("check_failures", {}).update(failures)


def _reason(result: app_check.Result) -> str:
    what = {"build": "the app did not build", "start": "the app did not start",
            "smoke": "the app's tests failed"}.get(result.stage, result.stage)
    return f"{what}: {result.detail}" + (f"\n\nEnd of the app's log:\n{result.log}" if result.log else "")


def _score(result: app_check.Result) -> tuple[int, int]:
    """Which attempt got furthest: a later stage beats an earlier one, then fewer failed tests."""
    stage = {"build": 0, "start": 1, "smoke": 2, "passed": 3}.get(result.stage, 0)
    return stage, -result.detail.count(" | ")


def _code_table(rows: list[tuple[str, str, str]], note: str) -> str:
    lines = ["### Tested before this PR", ""]
    if note:
        lines += [f"> {note}", ""]
    lines += ["Built, started and tested with the changes in this PR.", "",
              "| Attempt | Result | Why |", "|---|---|---|", *[f"| {a} | {b} | {c} |" for a, b, c in rows]]
    return "\n".join(lines)


def _add_to_pr_text(batch: dict, text: str) -> None:
    batch["rag_pr_text"] = "\n\n".join(p for p in (text, batch.get("rag_pr_text")) if p)


def _failure_of(test: str, detail: str) -> str:
    return next((part.strip() for part in detail.split(" | ") if test in part), detail)


def _same_ending(fixed: str, original: str) -> str:
    """The LLM's answers lose the file's last newline, which is not a change anyone asked for."""
    return fixed.rstrip("\n") + ("\n" if original.endswith("\n") else "")


def _test_code(test: str) -> str:
    """The test's own code. A failure like `assert 404 == 200` doesn't say what it was checking."""
    found = re.search(rf"^(?:@.*\n)*def {re.escape(test)}\b.*?(?=^\S|\Z)", _security_test_source(), re.M | re.S)
    return found.group(0).strip() if found else ""


def _changes_from(files: dict[str, str], answer: dict[str, str]) -> dict[str, str]:
    return {path: _same_ending(content, files[path]) for path, content in answer.items()
            if content.strip() and content.rstrip() != files[path].rstrip()}


def _misuse_retry(test: str, files: dict[str, str], changed: dict[str, str], hole: str, failed: app_check.Result,
                  logic_fix: Callable) -> dict[str, str]:
    """One more try at a fix that failed, with the fix itself, how it failed and what the test checks.
    Returns its changes from `files`, or {} when there is nothing new to test. A problem here must
    not cost the fixes already kept."""
    detail = "\n\n".join([
        f"The hole, as the test first showed it:\n{hole}",
        "An earlier fix for it is in the files below, and it failed.",
        f"How it failed: {_reason(failed)}",
        f"The test:\n{_test_code(test)}",
        "Correct the earlier fix. The attack must stay blocked and the legitimate use the test checks must keep "
        "working. Fix the cause for every user: do not special-case the users, IDs or values this test uses."])
    try:
        answer = logic_fix({**files, **changed}, detail)
    except Exception as e:  # noqa: BLE001
        print(f"    [test-first] [WARN] misuse retry for {test} stopped ({e})")
        return {}
    retried = _changes_from(files, {**changed, **answer})
    return {} if retried == changed else retried


def _misuse_round(entry: dict, repo_dir: str, logic_fix: Callable | None, passing: list[str], deadline: float) -> None:
    """Try to fix the holes the app's other security tests show, on top of a code fix that passed. A fix
    that fails gets one retry. Adds what passes to batch["misuse_fixes"], for its own commit, names
    what doesn't in batch["misuse_dropped"], and says what happened in the PR."""
    batch = entry["batch"]
    annotated = parse_annotated_files(_security_test_source())
    decided = pr_test_selector.reviewer_skipped_tests(batch)  # a reviewer kept these out of the PR
    others = [test for test in annotated if test not in passing and test not in decided]
    if batch.get("batch_type") != "sast" or logic_fix is None or not others:
        return
    current = {f["path"]: f["content"] for f in entry["files"]}
    kept_tests, fixes, rows, dropped = list(passing), [], [], []
    rows += [(f"`{test}`", "not tried", "skipped, reviewer decision") for test in annotated if test in decided]
    for test in others:
        if time.monotonic() >= deadline:
            rows.append((f"`{test}`", "not tried", "out of time"))
            continue
        result = app_check.check(current, repo_dir, [test])
        if result.passed:
            continue
        if result.stage != "smoke" or test not in result.detail:
            rows.append((f"`{test}`", "not tried", _why(result)))
            continue
        print(f"    [test-first] misuse test shows a hole: {test}")
        files = {path: current[path] if path in current else (Path(repo_dir) / config.FIX_PATH_PREFIX / path).read_text(encoding="utf-8")
                 for path in annotated[test] if path in current or (Path(repo_dir) / config.FIX_PATH_PREFIX / path).is_file()}
        hole = _failure_of(test, result.detail)
        changed = _changes_from(files, logic_fix(files, hole))
        if not changed:
            dropped.append(test)
            rows.append((f"`{test}`", "dropped", "the LLM returned no change"))
            continue
        attempt = {**current, **changed}
        latest = app_check.check(attempt, repo_dir, [*kept_tests, test])
        print(f"    [test-first] misuse fix for {test}: {'passed' if latest.passed else _why(latest)}")
        why, retried = _why(latest), False
        if not latest.passed and time.monotonic() < deadline:
            second = _misuse_retry(test, files, changed, hole, latest, logic_fix)
            if second:
                changed, attempt, retried = second, {**current, **second}, True
                latest = app_check.check(attempt, repo_dir, [*kept_tests, test])
                print(f"    [test-first] misuse retry for {test}: {'passed' if latest.passed else _why(latest)}")
                why = f"first try, {why}; retry, {_why(latest)}"
        if latest.passed:
            current = attempt
            kept_tests.append(test)
            fixes.append({"test": test, "files": [{"path": path, "content": content} for path, content in changed.items()]})
            rows.append((f"`{test}`: {', '.join(f'`{p}`' for p in changed)}",
                         "fixed on the retry, own commit" if retried else "fixed, own commit", ""))
        else:
            dropped.append(test)
            rows.append((f"`{test}`", "dropped", why))
    if fixes:
        batch["misuse_fixes"] = fixes
    if dropped:
        batch["misuse_dropped"] = dropped
    if rows:
        _add_to_pr_text(batch, "\n".join([
            "### Security tests the scanner did not cover", "",
            "These holes came from the app's own security tests, not the scanner. A kept fix is its own commit, so it "
            "can be reverted alone. **Review these carefully:** a passing test proves that attack is blocked, not that "
            "legitimate users still get in.", "",
            "| Test | Result | Why |", "|---|---|---|", *[f"| {a} | {b} | {c} |" for a, b, c in rows]]))


def _misuse_after_pass(entry: dict, repo_dir: str, logic_fix: Callable | None, passing: list[str], deadline: float) -> None:
    """A problem here must not cost the code fix that already passed."""
    if not misuse_fix_enabled():
        return
    try:
        _misuse_round(entry, repo_dir, logic_fix, passing, deadline)
    except Exception as e:  # noqa: BLE001
        print(f"    [test-first] [WARN] misuse round stopped ({e}) — keeping the code fix as tested")


def _flag_new_findings(batch: dict, new: list[dict], rows: list[tuple[str, str, str]]) -> None:
    """A draft that names them, so a person decides: it still holds the fixes that worked."""
    batch["draft"] = True
    batch["new_before_pr"] = [code_scan.describe(item) for item in new]
    print(f"    [test-first] the scan shows {code_scan.extra(new)} new critical or high: the PR opens as a draft")
    _add_to_pr_text(batch, "\n".join([
        "### Scanned before this PR", "",
        "> **This fix adds findings the scanner didn't report before, so this is a draft.** Do not merge it until someone "
        "has checked these. A rewrite of the flagged code can also look new, so check whether the code is really less safe.", "",
        *[f"- {line}" for line in batch["new_before_pr"]],
        *(["", "| Attempt | Result | Why |", "|---|---|---|", *[f"| {a} | {b} | {c} |" for a, b, c in rows]] if rows else [])]))


def _scan_round(entry: dict, repo_dir: str, make_refix: Callable | None, tests: list[str], deadline: float, findings_path: str | None) -> None:
    """Scan a code fix that passed. New critical or high findings get one LLM retry, kept only if it
    still passes and leaves fewer. Whatever is left makes the PR a draft."""
    batch = entry["batch"]
    current = {f["path"]: f["content"] for f in entry["files"]}
    before = code_scan.today(findings_path)
    after = code_scan.scan(current, repo_dir) if before is not None else None
    if after is None:
        _add_to_pr_text(batch, "### Scanned before this PR\n\n> **Not scanned:** the scanner could not run, so nothing "
                               "checked for new findings before this PR. Check the table at the top.")
        return
    new = code_scan.new_findings(before, after, set(current))
    if not new:
        _add_to_pr_text(batch, "### Scanned before this PR\n\nNo new critical or high findings.")
        return
    print(f"    [test-first] the scan shows new findings: {'; '.join(code_scan.describe(item) for item in new)}")
    rows = [("First scan", f"{code_scan.extra(new)} new", "")]
    refix = make_refix(entry) if make_refix else None
    if refix is not None and time.monotonic() < deadline:
        findings = {fe["file"]: fe.get("findings", []) for fe in batch.get("files_to_fix", [])}
        changed = {}
        for path in code_scan.suspects(new, list(current)):
            content = refix(path, findings.get(path, []), 1, reason=code_scan.reason(new))
            if content and content != current[path]:
                changed[path] = content
        if not changed:
            rows.append(("Retry", "dropped", "the LLM returned no change"))
        else:
            attempt = {**current, **changed}
            latest = app_check.check(attempt, repo_dir, tests)
            scanned = code_scan.scan(attempt, repo_dir) if latest.passed else None
            again = None if scanned is None else code_scan.new_findings(before, scanned, set(attempt))
            print(f"    [test-first] retry after the scan ({', '.join(changed)}): {_why(latest) if not latest.passed else 'scan could not run' if again is None else f'{code_scan.extra(again)} new'}")
            if not latest.passed:
                rows.append(("Retry", "dropped", _why(latest)))
            elif again is None:
                rows.append(("Retry", "dropped", "the scanner could not run on it"))
            elif code_scan.extra(again) >= code_scan.extra(new):
                rows.append(("Retry", "dropped", f"{code_scan.extra(again)} new, no better"))
            else:
                rows.append(("Retry", f"kept, {code_scan.extra(again)} new", ""))
                new = again
                for f in entry["files"]:
                    f["content"] = attempt[f["path"]]
    if new:
        _remember_failures(entry, {p: code_scan.reason(new) for p in code_scan.suspects(new, list(current))})
        _flag_new_findings(batch, new, rows)
    else:
        _add_to_pr_text(batch, "\n".join(["### Scanned before this PR", "", "The first attempt added a new finding and the retry removed it.", "",
                                          "| Attempt | Result | Why |", "|---|---|---|", *[f"| {a} | {b} | {c} |" for a, b, c in rows]]))


def _scan_misuse_fixes(entry: dict, repo_dir: str, findings_path: str | None) -> None:
    """The misuse fixes change the code after the scan above. No retry: each is its own commit."""
    batch = entry["batch"]
    combined = {f["path"]: f["content"] for f in entry["files"]}
    for fix in batch["misuse_fixes"]:
        combined.update({f["path"]: f["content"] for f in fix["files"]})
    before = code_scan.today(findings_path)
    after = code_scan.scan(combined, repo_dir) if before is not None else None
    if after is None:
        _add_to_pr_text(batch, "### Scanned before this PR\n\n> **Misuse fixes not scanned:** the scanner could not run on them. "
                               "Check the table at the top.")
        return
    new = code_scan.new_findings(before, after, set(combined))
    known = set(batch.get("new_before_pr") or [])
    if [item for item in new if code_scan.describe(item) not in known]:
        _flag_new_findings(batch, new, [])


def _after_pass(entry: dict, repo_dir: str, make_refix: Callable | None, logic_fix: Callable | None, tests: list[str],
                deadline: float, findings_path: str | None) -> None:
    """What runs on a code fix that passed. A problem with a scan must not cost the fix."""
    scan = code_scan.enabled() and entry["batch"].get("batch_type") == "sast"
    try:
        if scan:
            _scan_round(entry, repo_dir, make_refix, tests, deadline, findings_path)
    except Exception as e:  # noqa: BLE001
        print(f"    [test-first] [WARN] scan round stopped ({e}) — keeping the code fix as tested")
        _add_to_pr_text(entry["batch"], f"### Scanned before this PR\n\n> **Not scanned:** the check stopped ({str(e)[:200]}). Check the table at the top.")
    _misuse_after_pass(entry, repo_dir, logic_fix, tests, deadline)
    try:
        if scan and entry["batch"].get("misuse_fixes"):
            _scan_misuse_fixes(entry, repo_dir, findings_path)
    except Exception as e:  # noqa: BLE001
        print(f"    [test-first] [WARN] scan of the misuse fixes stopped ({e})")
        _add_to_pr_text(entry["batch"], f"### Scanned before this PR\n\n> **Misuse fixes not scanned:** the check stopped ({str(e)[:200]}). Check the table at the top.")


def _code(entry: dict, repo_dir: str, make_refix: Callable | None, logic_fix: Callable | None = None, findings_path: str | None = None) -> dict:
    batch = entry["batch"]
    files = {f["path"]: f["content"] for f in entry["files"]}
    findings = {fe["file"]: fe.get("findings", []) for fe in batch.get("files_to_fix", [])}
    tests = _security_tests(batch)
    deadline = time.monotonic() + _minutes() * 60

    print(f"    [test-first] checking {len(files)} file(s)" + (f" and {len(tests)} security test(s)" if tests else ""))
    result = app_check.check(files, repo_dir, tests)
    if result.passed:
        _add_to_pr_text(batch, _code_table([("First attempt", "passed", "")], ""))
        _after_pass(entry, repo_dir, make_refix, logic_fix, tests, deadline, findings_path)
        return entry
    usable, unverified = _candidate_stands(result, repo_dir)
    if unverified:
        print(f"    [test-first] {unverified}")
        _add_to_pr_text(batch, f"### Tested before this PR\n\n> **Not verified:** {unverified}")
        return entry

    rows = [("First attempt", "failed", _why(result))]
    print(f"    [test-first] first attempt failed: {_why(result)}")
    refix = make_refix(entry) if make_refix else None
    best, best_result, current, latest = dict(files), result, dict(files), result
    for round_number in range(1, _retries() + 1):
        if refix is None or time.monotonic() >= deadline:
            break
        suspects = _suspects(latest, list(current))
        changed = {}
        for path in suspects:
            content = refix(path, findings.get(path, []), round_number, reason=_reason(latest))
            if content:
                changed[path] = content
        if not changed:
            break
        current = {**current, **changed}
        latest = app_check.check(current, repo_dir, tests)
        print(f"    [test-first] retry {round_number} ({', '.join(changed)}): {_why(latest) if not latest.passed else 'passed'}")
        rows.append((f"Retry {round_number}: {', '.join(f'`{p}`' for p in changed)}",
                     "passed" if latest.passed else "failed", "" if latest.passed else _why(latest)))
        if _score(latest) > _score(best_result):
            best, best_result = dict(current), latest
        if latest.passed:
            break

    for f in entry["files"]:
        f["content"] = best[f["path"]]
    if best_result.passed:
        _add_to_pr_text(batch, _code_table(rows, ""))
        _after_pass(entry, repo_dir, make_refix, logic_fix, tests, deadline, findings_path)
    else:
        batch["draft"] = True
        _remember_failures(entry, {p: _reason(best_result) for p in _suspects(best_result, list(best))})
        print("    [test-first] still failing: the PR opens as a draft")
        _add_to_pr_text(batch, _code_table(rows, "**This did not pass, so it is a draft.** It holds the attempt that got "
                                                 "furthest. Do not merge it until the failure below is fixed."))
    return entry


# -- a newer base image (agent/base_image.py) ------------------------------------------------------

def _base_image(entry: dict, repo_dir: str) -> dict:
    batch = entry["batch"]
    file = entry["files"][0]
    path = file["path"]
    deadline = time.monotonic() + _minutes() * 60
    rows: list[tuple[str, str, str]] = []
    scan = None
    for option in batch["base_image_options"]:
        label = f"OS release {option['release']} (`{option['name']}`)"
        if time.monotonic() >= deadline:
            rows.append((label, "not tried", "out of time"))
            continue
        result = app_check.check({path: option["text"]}, repo_dir)
        print(f"    [test-first] base image {option['name']}: {result.stage}")
        if not result.passed:
            rows.append((label, "failed", _why(result)))
            continue
        today, after = batch.get("os_findings_today") or {}, base_image.scan_candidate(option["text"], path, repo_dir)
        scan = {"name": option["name"], "today": today, "after": after}
        if after and today and not base_image.worth_opening(today, after):
            print(f"    [test-first] base image {option['name']}: not worth opening, by the scan")
            rows.append((label, "not opened", f"the scan shows no gain: critical {today['critical']} → {after['critical']}, "
                                              f"all OS findings {today['total']} → {after['total']}"))
            continue
        rows.append((label, "kept", ""))
        entry["generation"]["base_image_scan"] = scan
        file["content"] = option["text"]
        fe = batch["files_to_fix"][0]
        fe["findings"] = option["fixes"]
        fe["finding_count"] = batch["total_findings"] = len(option["fixes"])
        _add_to_pr_text(batch, "\n".join([
            "### Newer base image", "",
            f"> **Review this carefully:** it moves the app to OS release {option['release']}. The OS's own data says this fixes "
            "the findings listed here, but it changes every OS package in the image, and the app's tests only cover part of the "
            "app. It can also bring vulnerabilities of its own: the table at the top shows them once the rescan finishes.", "",
            *(["> **Not scanned before this PR:** the scanner could not run, so the rule that stops an OS upgrade with no gain was "
               "not applied. Check the table at the top.", ""] if not (after and today) else []),
            "| Tried | Result | Why |", "|---|---|---|", *[f"| {a} | {b} | {c} |" for a, b, c in rows]]))
        return entry
    entry = _nothing_passed(entry, path, rows)
    if scan:
        entry["generation"]["base_image_scan"] = scan
    return entry


# -- the entry point -------------------------------------------------------------------------------

def run(entry: dict, repo_dir: str, upgrade_map: Callable, *, make_refix: Callable | None = None,
        notes: Callable | None = None, logic_fix: Callable | None = None, findings_path: str | None = None) -> dict:
    """Test one generated batch. Anything unexpected leaves the candidate as it was: the pipeline's
    later checks still run on it. `make_refix(entry)` gives the LLM retry; `notes(path, original,
    upgrades)` the reviewer notes for major version changes; `logic_fix(files, failure)` the LLM's
    fix for a hole a security test shows; `findings_path` today's findings, for the scan before a PR."""
    batch = entry.get("batch") or {}
    if not enabled() or batch.get("batch_type") not in ("sca", "sast", "container") or not entry.get("files"):
        return entry
    if not app_check.supported():
        print("    [test-first] no app check settings for this app: not tested before the PR")
        _add_to_pr_text(batch, "### Tested before this PR\n\n> **Not tested:** this app has no app check settings "
                               "(see agent/app_check.py), so nothing here was built or run before this PR.")
        return entry
    snapshot = copy.deepcopy(entry)
    try:
        if batch.get("remediation_method") == base_image.METHOD:
            return _base_image(entry, repo_dir)
        if batch["batch_type"] != "sca":
            return _code(entry, repo_dir, make_refix, logic_fix, findings_path)
        if batch.get("remediation_method") == "npm":
            return _npm(entry, repo_dir, notes)
        if len(entry["files"]) == 1 and entry["files"][0]["path"].lower().endswith("requirements.txt"):
            return _requirements(entry, repo_dir, upgrade_map, notes)
        return _code(entry, repo_dir, make_refix)
    except Exception as e:  # noqa: BLE001 -- never let the check cost us the fix
        print(f"    [test-first] [WARN] stopped ({e}) — keeping the candidate as generated")
        if batch.get("remediation_method") == base_image.METHOD:  # never open this one untested
            return _nothing_passed(snapshot, snapshot["files"][0]["path"], [("Newer base image", "not tried", str(e)[:300])])
        return snapshot
