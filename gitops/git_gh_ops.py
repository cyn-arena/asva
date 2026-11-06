"""
gitops/git_gh_ops.py -- ASVA GitHub write operations via native git + gh.

Uses the tools already present on the runners:
  - git : create branch, stage files, commit, push
  - gh  : open the pull request

Git uses checkout-persisted credentials; gh uses GH_TOKEN. CI workflows select the
credential (PAT for candidate pushes and PRs); local runs use `gh auth login` and
`gh auth setup-git`. This module does not read or store token values.

Granularity — ONE pull request per batch, normally ONE commit per file:
    1 triage batch  ->  1 fix branch (fix/<batch_id>)  ->  1 commit per fixed file  ->  1 PR
A scan cycle is just all the batches triage produced for one scan; each batch is processed
independently and opens its own PR. ASVA never merges — it opens PRs for human review only.
The npm path commits the dependency manifest and lockfile together.

Per-file fix/test/retry loop:
    Fix 1 file -> Test -> if tests fail, ask the LLM for another fix -> repeat -> commit.
The test step and the LLM re-fix are INJECTED by the agent loop:
  - test_fn(path) -> bool        : run the app's tests against the working tree
  - refix_fn(path, findings, n)  : ask the LLM for another fix, or None to give up
If test_fn is omitted, each file's fix is committed without testing.

Pipeline: Build -> Scan -> Triage -> Fix -> [ open 1 PR per batch ] -> Review -> Merge (human).

Public API:
  submit_scan_cycle(cycle, *, test_fn=None, refix_fn=None) -> aggregate (1 PR per batch)
  submit_fix_batch(batch, files, *, test_fn=None, refix_fn=None) -> result (the batch's PR)
  create_branch / write_file / revert_uncommitted / commit / push / open_pr  (primitives)
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Callable, Optional

from secrets_scan.gitleaks_gate import GitleaksError, added_leaks, scan_files

from . import config
from .dependency_validation import validate_pair

# Injected by the agent loop. Kept as type aliases for clarity.
TestFn = Callable[[str], bool]                          # test_fn(path) -> passed?
RefixFn = Callable[[str, list, int], Optional[str]]     # refix_fn(path, findings, attempt) -> new content | None

DEFAULT_MAX_ATTEMPTS = 3


class GitOpError(RuntimeError):
    """Raised when a git or gh command fails, or a batch is missing required identity."""


def _safe_rel(path: str) -> str:
    """Normalise an app-relative path and reject directory traversal.

    Finding/LLM-supplied paths must never escape the target tree, so a `..` segment is a
    hard error rather than something we silently resolve.
    """
    rel = path.replace("\\", "/").lstrip("/")
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    if ".." in parts:
        raise GitOpError(f"Unsafe path (directory traversal): {path!r}")
    return "/".join(parts)


def _where(leaks: list[dict]) -> str:
    """Where gitleaks found these, never what it found: "lines 8, 12 (`generic-api-key`)"."""
    rules: dict[str, list[int]] = {}
    for leak in leaks:
        if leak.get("rule") and leak.get("line"):
            rules.setdefault(leak["rule"], []).append(leak["line"])
    return "; ".join(
        f"line{'s' if len(lines) > 1 else ''} {', '.join(str(n) for n in sorted(lines))} (`{rule}`)"
        for rule, lines in rules.items()
    )


def _stopped_by(leaks: list[dict]) -> str:
    where = _where(leaks)
    return f"secrets detected: {where}" if where else "secrets detected"


def gate_file(path: str, content: str, repo_dir: str | None = None,
              already_there: dict[str, str] | None = None) -> tuple[bool, Optional[str]]:
    """Run the secrets gate (secrets_scan.gitleaks_gate) on one candidate file. Returns (clean, reason_if_blocked).

    With `repo_dir`, what the file in the working tree already had doesn't stop the fix, as it
    isn't what the fix leaks and blocking the fix doesn't remove it: `already_there` gets where
    they are, for the reviewer. A file with no original has nothing to compare, so any secret stops it.

    Fail-closed: ANY error running the gate is reported as not-clean, never silently passed.
    """
    try:
        scan = scan_files([{"path": path, "content": content}])
        if scan.clean:
            return True, None
        original = Path(repo_dir) / repo_path(path) if repo_dir is not None else None
        if original is None or not original.is_file() or not scan.leaks:
            return False, _stopped_by(scan.leaks)
        before = scan_files([{"path": path, "content": original.read_text(encoding="utf-8")}])
        added = added_leaks(before, scan)
    except GitleaksError as e:
        return False, f"scan error: {e}"
    except Exception as e:  # noqa: BLE001 — a gate that errors must fail closed, not open
        return False, f"gate error: {e!r}"
    if added:
        return False, _stopped_by(added)
    if already_there is not None:
        already_there[path] = _where(scan.leaks)
    return True, None


def _run(cmd: list[str], repo_dir: str = ".", input_text: str | None = None) -> str:
    proc = subprocess.run(
        cmd, cwd=repo_dir, input=input_text, capture_output=True, text=True
    )
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or "no output"
        raise GitOpError(f"`{' '.join(cmd)}` failed (exit {proc.returncode}): {detail}")
    return proc.stdout.strip()


# --------------------------------------------------------------------------------------
# Batch identity + builders (pure functions, derived from a single batch)
# --------------------------------------------------------------------------------------

def batch_identity(batch: dict) -> tuple[str, str]:
    """Return (repo_name, short_sha) for one batch — used in the PR title/body."""
    return batch.get("repo_name", "repo"), str(batch.get("commit_sha", "00000000"))[:8]


# A batch_id safe to embed in a git ref: triage emits scan_run_id + type + index, all of
# which are word chars / dots / dashes. Anything else (spaces, slashes, '~', ':') — or a
# '..' sequence, which git refs forbid — is rejected up front so it fails clearly here
# instead of as a cryptic git error later.
_REF_SAFE_BATCH_ID = re.compile(r"[\w.-]+")


def batch_branch_name(batch: dict) -> str:
    """fix/<batch_id> — one branch per batch (e.g. fix/asva_sast_239f8ach_1).

    batch_id is unique within a scan (including SAST _sast_1/_sast_2 splits), so per-batch
    branches never collide with sibling batches from the same scan.
    """
    batch_id = batch.get("batch_id")
    if not batch_id:
        raise GitOpError("Batch is missing 'batch_id'; cannot name its fix branch.")
    bid = str(batch_id)
    if not _REF_SAFE_BATCH_ID.fullmatch(bid) or ".." in bid:
        raise GitOpError(f"batch_id {batch_id!r} is not a valid git ref name.")
    return f"fix/{batch_id}"


def file_commit_message(ff: dict) -> str:
    """One commit per file."""
    n = len(ff.get("findings", []))
    return (
        f"fix(security): {ff['batch_type']} remediation in {ff['path']} "
        f"({n} finding(s)) [{ff['batch_id']}]"
    )


def _commit_misuse_fixes(batch: dict, blocked: list[dict], repo_dir: str, run_secret_scan: bool,
                         already_there: dict[str, str] | None = None) -> list[str]:
    """Each fix for a hole a security test showed (agent/test_first.py) as its own commit on top of
    the batch's, so a reviewer can revert it alone. A file the secrets gate stops drops that whole fix."""
    done = []
    for fix in batch.get("misuse_fixes") or []:
        stopped = False
        found: dict[str, str] = {}
        for f in fix["files"]:
            clean, reason = gate_file(f["path"], f["content"], repo_dir, found) if run_secret_scan else (True, "")
            if not clean:
                blocked.append({"path": f["path"], "reason": f"{reason} (fix for {fix['test']})"})
                stopped = True
        if stopped:
            continue
        for f in fix["files"]:
            write_file(f["path"], f["content"], repo_dir)
        paths = [f["path"] for f in fix["files"] if path_has_change(f["path"], repo_dir)]
        if paths:
            commit(paths, f"fix(security): hole shown by {fix['test']} [{batch.get('batch_id')}]", repo_dir)
            done.append(fix["test"])
            if already_there is not None:
                already_there.update(found)
    return done


def _held_back(finding: dict) -> bool:
    """agent/safe_upgrades.py found no safe version for this finding: this PR does not address it."""
    remediation = finding.get("remediation") or {}
    return bool(remediation.get("scanner_upgrade_to")) and not remediation.get("upgrade_to")


def _finding_ids(findings: list[dict]) -> str:
    ids = []
    for f in findings:
        if _held_back(f):
            continue
        ident = f.get("identifiers") or {}
        ids.append(ident.get("cve") or ident.get("cwe") or ident.get("rule_id") or "-")
    held = sum(_held_back(f) for f in findings)
    return (", ".join(ids) or "-") + (f" (not addressed here: {held} held back, see below)" if held else "")


def _markdown_table_text(value: object) -> str:
    """Keep scanner-supplied text on one safe Markdown table line."""
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ").strip()


def _group_sast_findings(findings: list[dict]) -> list[tuple[str, str, int]]:
    """Group equivalent SAST records while preserving Snyk's first-seen order."""
    grouped: dict[tuple[str, str], int] = {}
    for finding in findings:
        identifiers = finding.get("identifiers") or {}
        identifier = (
            identifiers.get("cwe")
            or identifiers.get("rule_id")
            or identifiers.get("cve")
            or "-"
        )
        title = finding.get("title") or identifier
        key = (_markdown_table_text(title) or "-", _markdown_table_text(identifier) or "-")
        grouped[key] = grouped.get(key, 0) + 1
    return [(title, identifier, count) for (title, identifier), count in grouped.items()]


def batch_pr_title(batch: dict, committed: list[dict]) -> str:
    repo, short_sha = batch_identity(batch)
    btype = batch.get("batch_type", "security")
    findings = sum(not _held_back(f) for ff in committed for f in ff.get("findings", []))
    choice = f" ({batch['pr_choice']})" if batch.get("pr_choice") else ""
    return f"[ASVA] {btype} fixes{choice} for {repo} @ {short_sha} - {len(committed)} file(s), {findings} finding(s)"


def batch_pr_body(
    batch: dict, committed: list[dict], blocked: list[dict], failed: list[dict],
    already_there: dict[str, str] | None = None,
) -> str:
    repo, short_sha = batch_identity(batch)
    btype = batch.get("batch_type", "security")
    bid = batch.get("batch_id", "-")
    coordinated = batch.get("remediation_method") == "npm"
    lines = [
        "## ASVA automated security remediation",
        "",
        "> :warning: **Requires human review. ASVA does NOT auto-merge.** "
        "A human approves and merges this PR.",
        "",
        f"- **Repo / scan commit:** `{repo}` @ `{short_sha}`",
        f"- **Batch:** `{bid}` ({btype})",
        f"- **Commits in this PR:** {1 if coordinated else len(committed) + len(batch.get('misuse_fixes') or [])} "
        + ("(coordinated npm dependency update)" if coordinated else "(one per fixed file)"),
        "",
        ("npm generated this dependency pair from scanner-recommended upgrades. "
         "Both files are committed together; installation and security validation are still required."
         if coordinated else
         "This pull request covers one triage batch; each file below is a separate commit."),
        "",
    ]
    if coordinated:
        lines += ["### npm upgrade plan", *[
            f"- `{_markdown_table_text(name)}`: `{_markdown_table_text(u['from'])}` -> "
            f"`{u['to']}` ({u['section']})" for name, u in batch.get("npm_upgrades", {}).items()],
            f"- Findings without a supported upgrade: {batch.get('npm_unresolved_count', 0)}", ""]
    if btype == "sast":
        lines += [
            "### Changed files",
            "| File | Security finding | Occurrences |",
            "|---|---|---:|",
        ]
        for ff in committed:
            groups = _group_sast_findings(ff.get("findings", []))
            if not groups:
                lines.append(f"| `{ff['path']}` | - | 0 |")
                continue
            for title, identifier, count in groups:
                lines.append(f"| `{ff['path']}` | {title} ({identifier}) | {count} |")
    else:
        lines += [
            "### Changed files",
            "| File | Type | Findings |",
            "|---|---|---|",
        ]
        for ff in committed:
            lines.append(
                f"| `{ff['path']}` | {ff['batch_type']} | {_finding_ids(ff['findings'])} |"
            )
    notes = batch.get("review_notes") or {}
    committed_paths = {ff["path"] for ff in committed}
    review = [(path, n) for path, ns in sorted(notes.items()) if path in committed_paths for n in ns]
    if review:
        # Set by agent_loop for breaking dependency upgrades: the fix only edits the
        # manifest, so code relying on the old API must be checked by the reviewer.
        lines += [
            "",
            "### :mag: Check before merging",
            *[f"- `{path}`: {note}" for path, note in review],
        ]
    if already_there:
        lines += [
            "",
            "### :warning: Possible secrets already in this code",
            "Gitleaks flagged these in the files this PR changes. This fix didn't add them, so they "
            "didn't stop it. Check whether they are real, and rotate any that are.",
            *[f"- `{path}`: {where}" for path, where in sorted(already_there.items())],
        ]
    if blocked:
        lines += [
            "",
            "### :no_entry: Withheld by the secrets gate",
            *[f"- `{b['path']}`: {b['reason']}" for b in blocked],
        ]
    if failed:
        lines += [
            "",
            "### :x: Not fixed (tests still failing)",
            *[f"- `{b['path']}`: {b['reason']}" for b in failed],
        ]
    if batch.get("rag_pr_text"):
        lines += ["", "---", "", "*From the RAG (security context service):*", "", batch["rag_pr_text"]]
    lines += [
        "",
        "_Pipeline: Build -> Scan -> Triage -> Fix -> **Review (you are here)** -> Merge_",
    ]
    return "\n".join(lines)


def repo_path(path: str) -> str:
    """Map an app-relative finding path into the repo working tree via FIX_PATH_PREFIX."""
    rel = _safe_rel(path)
    return f"{config.FIX_PATH_PREFIX}/{rel}" if config.FIX_PATH_PREFIX else rel


# --------------------------------------------------------------------------------------
# Primitives (the agent loop can orchestrate these directly)
# --------------------------------------------------------------------------------------

def prepare_fix_source(base_branch: str, repo_dir: str = ".") -> str:
    """Fetch the PR target and verify an explicitly selected scan revision belongs to it.

    Call before paid AI requests as well as before each batch. Callers that do not
    provide ASVA_SCANNED_SHA retain the existing latest-base behaviour.
    """
    scanned_sha = os.environ.get("ASVA_SCANNED_SHA", "").strip()
    if scanned_sha and not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", scanned_sha):
        raise GitOpError("ASVA_SCANNED_SHA must be a full Git commit SHA")
    _run(["git", "fetch", "origin", base_branch], repo_dir)
    if scanned_sha:
        _run(["git", "rev-parse", "--verify", f"{scanned_sha}^{{commit}}"], repo_dir)
        _run(["git", "merge-base", "--is-ancestor", scanned_sha, "FETCH_HEAD"], repo_dir)
    return scanned_sha or "FETCH_HEAD"


def create_branch(branch: str, base_branch: str, repo_dir: str = ".") -> str:
    """Create `branch` at the scanned commit, or the latest PR target when unset.

    Uses `switch -C` so re-running the same batch resets the local branch instead of
    aborting because it already exists. Each batch starts at the same selected revision,
    rather than inheriting changes from a sibling batch or newer target commits.
    """
    revision = prepare_fix_source(base_branch, repo_dir)
    _run(["git", "switch", "-C", branch, revision], repo_dir)
    return branch


def current_branch(repo_dir: str = ".") -> str:
    """Name of the branch HEAD is on, or "" when HEAD is detached (e.g. a CI checkout at a SHA)."""
    return _run(["git", "branch", "--show-current"], repo_dir)


def restore_branch(branch: str, repo_dir: str = ".") -> None:
    """Best-effort switch back to `branch` (no-op if empty). Never raises: restoring the
    caller's branch must not mask the real result or hide a real error."""
    if not branch:
        return
    try:
        _run(["git", "switch", branch], repo_dir)
    except GitOpError:
        pass


def write_file(path: str, content: str, repo_dir: str = ".") -> None:
    """Write fixed content into the working tree (at its prefixed path). Does NOT commit."""
    root = Path(repo_dir).resolve()
    dest = (root / repo_path(path)).resolve()
    # Defense in depth: never write outside the repo even if repo_path is bypassed.
    if dest != root and root not in dest.parents:
        raise GitOpError(f"Refusing to write outside the repo: {path!r}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(content, encoding="utf-8")


def revert_uncommitted(path: str, repo_dir: str = ".") -> None:
    """Undo an uncommitted change to `path` (e.g. after a failed test) so the next attempt
    starts clean. Restores the committed version, or removes the file if it was new."""
    rp = repo_path(path)
    try:
        _run(["git", "restore", "--worktree", "--staged", "--", rp], repo_dir)
    except GitOpError:
        p = Path(repo_dir) / rp
        if p.exists():
            p.unlink()


def path_has_change(path: str, repo_dir: str = ".") -> bool:
    """True if `path` differs from HEAD in the working tree (an actual edit to commit).

    Lets the caller spot a no-op "fix" (LLM returned content identical to the original) and
    report it clearly, instead of letting `git commit` fail with a cryptic "nothing to commit".
    An LLM often returns the file without its final newline, or with other trailing whitespace
    changed. That is not an edit either: it must not become a PR with no fix in it.
    """
    rp = str(Path(repo_dir) / repo_path(path))
    status = _run(["git", "status", "--porcelain", "--", rp], repo_dir)
    if status.startswith("??"):  # a new file: nothing to compare it with
        return True
    return bool(status) and bool(_run(["git", "diff", "--ignore-space-at-eol", "HEAD", "--", rp], repo_dir))


def commit(paths: list[str], message: str, repo_dir: str = ".") -> None:
    """Stage the given working-tree paths and commit ONLY those paths.

    The commit is scoped to `paths` (via a `-- <pathspec>`) so a pre-existing staged change
    in the working tree can't be swept into ASVA's per-file commit.
    """
    rps = [str(Path(repo_dir) / repo_path(path)) for path in paths]
    for rp in rps:
        _run(["git", "add", "--", rp], repo_dir)
    _run([
        "git",
        "-c", f"user.name={config.GIT_AUTHOR_NAME}",
        "-c", f"user.email={config.GIT_AUTHOR_EMAIL}",
        "commit", "-m", message, "--", *rps,
    ], repo_dir)


def push(branch: str, repo_dir: str = ".") -> None:
    """Push the fix branch to origin."""
    _run(["git", "push", "-u", "origin", branch], repo_dir)


def open_pr(title: str, body: str, branch: str, base_branch: str, repo_dir: str = ".", draft: bool = False) -> str:
    """Open ONE PR from `branch` into `base_branch` via gh. Returns the PR URL. Never merges."""
    # Pass the body via stdin (--body-file -) so a large findings table can't hit OS arg limits.
    cmd = ["gh", "pr", "create", "--base", base_branch, "--head", branch,
           "--title", title, "--body-file", "-"]
    if draft or os.environ.get("ASVA_FIX_DRAFT") == "true":
        cmd.append("--draft")
    if config.GITHUB_TARGET_REPO:
        cmd += ["--repo", config.GITHUB_TARGET_REPO]
    return _run(cmd, repo_dir, input_text=body)  # gh prints the PR URL on success


def comment_on_pr(pr: str, body: str, repo_dir: str = ".") -> str:
    """Post a comment on an existing PR (number or URL) via gh. Returns the comment URL.

    Used to surface a pre-merge verification result (e.g. the smoke suite) on the PR so the
    human reviewer sees it without having to re-run anything themselves.
    """
    cmd = ["gh", "pr", "comment", pr, "--body-file", "-"]
    if config.GITHUB_TARGET_REPO:
        cmd += ["--repo", config.GITHUB_TARGET_REPO]
    return _run(cmd, repo_dir, input_text=body)


def convert_pr_to_draft(pr: str, repo_dir: str = ".") -> str:
    """Flip an existing PR back to draft (number or URL) via gh. Returns gh's output.

    Used when pr-check finds the fix breaks the app or leaves the vulnerability unfixed, so
    merging is structurally blocked rather than just discouraged by a comment.
    """
    cmd = ["gh", "pr", "ready", pr, "--undo"]
    if config.GITHUB_TARGET_REPO:
        cmd += ["--repo", config.GITHUB_TARGET_REPO]
    return _run(cmd, repo_dir)


def open_issue(title: str, body: str, repo_dir: str = ".", label: str | None = None) -> str:
    """Open a new GitHub issue via gh. Returns the issue URL.

    Used for a `no_commits` batch: there's no PR to attach a warning to, so the failure
    needs its own carrier. A label only helps people filter, so the issue still opens
    without one if it can't be created or applied.
    """
    cmd = ["gh", "issue", "create", "--title", title, "--body-file", "-"]
    if config.GITHUB_TARGET_REPO:
        cmd += ["--repo", config.GITHUB_TARGET_REPO]
    if label:
        try:
            create = ["gh", "label", "create", label, "--force"]
            if config.GITHUB_TARGET_REPO:
                create += ["--repo", config.GITHUB_TARGET_REPO]
            _run(create, repo_dir)
            return _run([*cmd, "--label", label], repo_dir, input_text=body)
        except GitOpError as e:
            print(f"[WARN] Could not use label {label}: {e}")
    return _run(cmd, repo_dir, input_text=body)


def update_issue(number: str, body: str, repo_dir: str = ".") -> str:
    """Replace an open issue's description via gh."""
    cmd = ["gh", "issue", "edit", str(number), "--body-file", "-"]
    if config.GITHUB_TARGET_REPO:
        cmd += ["--repo", config.GITHUB_TARGET_REPO]
    return _run(cmd, repo_dir, input_text=body)


def find_open_issue(search: str, repo_dir: str = ".") -> Optional[str]:
    """Return the number of an open issue matching `search` (gh's search syntax, e.g.
    "<batch_id> in:title"), or None if there isn't one. Used to avoid opening a duplicate
    issue for the same batch on repeated runs.
    """
    cmd = ["gh", "issue", "list", "--state", "open", "--search", search,
           "--json", "number", "--limit", "1"]
    if config.GITHUB_TARGET_REPO:
        cmd += ["--repo", config.GITHUB_TARGET_REPO]
    out = _run(cmd, repo_dir)
    results = json.loads(out or "[]")
    return str(results[0]["number"]) if results else None


def find_open_issue_by_title(title: str, repo_dir: str = ".") -> Optional[str]:
    """The number of the open issue with exactly this title, or None. GitHub's search also matches
    titles that only contain the words, so its results are compared here.
    """
    cmd = ["gh", "issue", "list", "--state", "open", "--search", f'"{title}" in:title',
           "--json", "number,title", "--limit", "30"]
    if config.GITHUB_TARGET_REPO:
        cmd += ["--repo", config.GITHUB_TARGET_REPO]
    results = json.loads(_run(cmd, repo_dir) or "[]")
    return next((str(r["number"]) for r in results if r["title"] == title), None)


# --------------------------------------------------------------------------------------
# Helpers + orchestrator
# --------------------------------------------------------------------------------------

def iter_file_fixes(cycle: list[dict]):
    """Flatten a list of {batch, files} into per-file fix items carrying their finding
    context. `files` = [{"path", "content"}, ...]. Normally called with a single batch.

    Deduped by path so each file is fixed and committed exactly once. If the same path
    appears more than once, the findings are merged and the first content is kept.
    """
    seen: dict[str, dict] = {}
    order: list[str] = []
    for c in cycle:
        batch = c["batch"]
        findings_by_file = {e["file"]: e for e in batch.get("files_to_fix", [])}
        for f in c["files"]:
            path = f["path"]
            findings = findings_by_file.get(path, {}).get("findings", [])
            if path in seen:
                seen[path]["findings"].extend(findings)  # merge, keep first content
                continue
            seen[path] = {
                "path": path,
                "content": f["content"],
                "batch_id": batch.get("batch_id", "-"),
                "batch_type": batch.get("batch_type", "security"),
                "findings": list(findings),
            }
            order.append(path)
    for path in order:
        yield seen[path]


def _submit_dependency_pair(batch: dict, files: list[dict], base_branch: str, repo_dir: str,
                            run_secret_scan: bool, test_fn: TestFn | None) -> dict:
    """An npm app's dependency fix: gate and commit both dependency files, or neither."""
    if len(files) != 2 or {f["path"] for f in files} != {"package.json", "package-lock.json"}:
        raise GitOpError("npm submission requires both package.json and package-lock.json")
    contents = {f["path"]: f["content"] for f in files}
    validate_pair(json.loads(contents["package.json"]), json.loads(contents["package-lock.json"]))
    findings = [f for entry in batch.get("files_to_fix", []) for f in entry.get("findings", [])]
    fixes = list(iter_file_fixes([{"batch": batch, "files": files}]))
    for i, ff in enumerate(fixes):
        ff["findings"] = findings if i == 0 else []
    blocked, failed = [], []
    result = {"status": "no_commits", "batch_id": batch.get("batch_id"), "pr_url": None,
              "committed": [], "blocked": blocked, "failed": failed,
              "message": "Dependency pair was rejected; neither file was committed"}
    if run_secret_scan:
        for ff in fixes:
            clean, reason = gate_file(ff["path"], ff["content"])
            if not clean:
                blocked.append({"path": ff["path"], "reason": reason})
        if blocked:
            return result
    original_branch = current_branch(repo_dir)
    branch = batch_branch_name(batch)
    wrote_files, committed = False, False
    try:
        create_branch(branch, base_branch, repo_dir)
        wrote_files = True
        for ff in fixes:
            write_file(ff["path"], ff["content"], repo_dir)
        if test_fn:
            for ff in fixes:
                if not test_fn(ff["path"]):
                    failed.append({"path": ff["path"], "reason": "Dependency pair failed validity gate"})
        if failed:
            return result
        if not any(path_has_change(ff["path"], repo_dir) for ff in fixes):
            result["message"] = "Dependency generation made no changes"
            return result
        commit([ff["path"] for ff in fixes],
               f"fix(security): regenerate npm dependency pair [{batch['batch_id']}]", repo_dir)
        committed = True
        push(branch, repo_dir)
        url = open_pr(batch_pr_title(batch, fixes), batch_pr_body(batch, fixes, [], []),
                      branch, base_branch, repo_dir)
        result.update(status="pr_opened", branch=branch, base=base_branch, pr_url=url,
                      committed=[ff["path"] for ff in fixes],
                      message="1 PR opened for coordinated npm dependency update; candidate checks required")
        return result
    finally:
        if wrote_files and not committed:
            for ff in fixes:
                revert_uncommitted(ff["path"], repo_dir)
        restore_branch(original_branch, repo_dir)


def submit_fix_batch(
    batch: dict,
    files: list[dict],
    base_branch: str | None = None,
    *,
    repo_dir: str = ".",
    run_secret_scan: bool = True,
    test_fn: TestFn | None = None,
    refix_fn: RefixFn | None = None,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> dict:
    """Submit one PR per batch; npm dependency pairs share one commit.

    `files` = [{"path","content"}, ...] — candidate contents generated for this batch.

    For each file: run the secrets gate, which stops only secrets the fix adds; write the fix;
    if `test_fn` passes (or is not provided) commit it; otherwise revert and, if `refix_fn` is
    provided, ask for another fix and retry up to `max_attempts`. After all files: push and open
    ONE PR, which lists any secrets the changed files already had. ASVA never merges.

    The caller's branch is restored at the end (even on error) so a local run doesn't leave
    the working copy sitting on the fix branch.
    """
    if batch.get("remediation_method") == "npm":
        return _submit_dependency_pair(batch, files, base_branch or config.GITHUB_BASE_BRANCH,
                                       repo_dir, run_secret_scan, test_fn)
    if not files:
        return {"status": "noop", "batch_id": batch.get("batch_id"), "pr_url": None,
                "message": "No files in this batch."}

    base_branch = base_branch or config.GITHUB_BASE_BRANCH
    branch = batch_branch_name(batch)
    suffix = os.environ.get("ASVA_FIX_BRANCH_SUFFIX", "")
    if suffix:
        if not re.fullmatch(r"[A-Za-z0-9_-]+", suffix):
            raise GitOpError("Unsafe fix branch suffix")
        branch += "-" + suffix
    file_fixes = list(iter_file_fixes([{"batch": batch, "files": files}]))

    # Remember where the caller was so we can switch back afterwards (detached HEAD -> "").
    original_branch = current_branch(repo_dir)

    try:
        create_branch(branch, base_branch, repo_dir)

        committed: list[dict] = []
        blocked: list[dict] = []
        failed: list[dict] = []
        already_there: dict[str, str] = {}

        for ff in file_fixes:
            # Reject traversal up front so it never reaches the gate or the working tree.
            try:
                _safe_rel(ff["path"])
            except GitOpError as e:
                blocked.append({"path": ff["path"], "reason": str(e)})
                continue

            content = ff["content"]
            for attempt in range(1, max_attempts + 1):
                # Never blank a file to "fix" it — an empty/whitespace fix is a failed fix.
                if not (content or "").strip():
                    failed.append({"path": ff["path"], "reason": "empty fix content"})
                    break

                # --- secrets gate (pre-commit), fail-closed ---
                found: dict[str, str] = {}
                if run_secret_scan:
                    clean, reason = gate_file(ff["path"], content, repo_dir, found)
                    if not clean:
                        blocked.append({"path": ff["path"], "reason": reason})
                        break

                write_file(ff["path"], content, repo_dir)

                # A fix that changes nothing isn't a fix — don't try to make an empty commit.
                if not path_has_change(ff["path"], repo_dir):
                    revert_uncommitted(ff["path"], repo_dir)  # a whitespace-only difference stays out of the next file's commit
                    failed.append({"path": ff["path"], "reason": "fix made no change to the file"})
                    break

                # --- fix 1 file -> test -> retry via LLM ---
                if test_fn is None or test_fn(ff["path"]):
                    commit([ff["path"]], file_commit_message(ff), repo_dir)
                    committed.append(ff)
                    already_there.update(found)
                    break

                revert_uncommitted(ff["path"], repo_dir)
                new_content = refix_fn(ff["path"], ff["findings"], attempt) if refix_fn else None
                if not new_content or attempt == max_attempts:
                    failed.append({"path": ff["path"], "reason": f"tests failed after {attempt} attempt(s)"})
                    break
                content = new_content

        if not committed:
            return {
                "status": "no_commits",
                "batch_id": batch.get("batch_id"),
                "branch": branch,
                "pr_url": None,
                "committed": [], "blocked": blocked, "failed": failed,
                "message": "No file passed the gate/tests; no commits or PR were created for this batch.",
            }

        misuse_fixed = _commit_misuse_fixes(batch, blocked, repo_dir, run_secret_scan, already_there)
        push(branch, repo_dir)
        pr_url = open_pr(
            batch_pr_title(batch, committed),
            batch_pr_body(batch, committed, blocked, failed, already_there),
            branch, base_branch, repo_dir, draft=bool(batch.get("draft")),
        )

        return {
            "status": "pr_opened",
            "batch_id": batch.get("batch_id"),
            "branch": branch,
            "base": base_branch,
            "pr_url": pr_url,
            "committed": [ff["path"] for ff in committed],
            "misuse_fixed": misuse_fixed,
            "blocked": blocked,
            "failed": failed,
            "secrets_already_there": already_there,
            "message": (
                f"1 PR opened for batch {batch.get('batch_id')}: {len(committed)} file(s) committed, "
                f"{len(blocked)} blocked by secrets, {len(failed)} failed tests. Human reviews and merges."
            ),
        }
    finally:
        # Return to the caller's branch even if something failed partway through.
        restore_branch(original_branch, repo_dir)


def submit_scan_cycle(
    cycle: list[dict],
    base_branch: str | None = None,
    *,
    repo_dir: str = ".",
    run_secret_scan: bool = True,
    test_fn: TestFn | None = None,
    refix_fn: RefixFn | None = None,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> dict:
    """Submit a whole scan cycle — ONE pull request per batch (not per scan).

    `cycle` = [{"batch": <batch dict>, "files": [{"path","content"}, ...]}, ...]. Each batch
    is handled independently by submit_fix_batch: its own fix branch (fix/<batch_id>), one
    commit per fixed file (or one per npm dependency pair), and its own PR. Returns an aggregate; the
    per-batch results are under "prs". ASVA never merges.
    """
    if not cycle:
        return {"status": "noop", "prs": [], "pr_urls": [], "message": "No batches to submit."}

    # One batch failing (push rejected, "PR already exists", a transient gh error) must not
    # abort the rest of the cycle — record it and carry on so every batch is attempted and
    # the caller gets a complete report.
    prs: list[dict] = []
    for c in cycle:
        try:
            generation = c.get("generation")
            if generation and generation.get("status") not in ("generated", "partial"):
                prs.append({"status": "error" if generation["status"] == "error" else "no_commits",
                            "batch_id": c["batch"]["batch_id"], "pr_url": None,
                            "message": generation["message"], "generation": generation,
                            "failed": [{"path": f["path"], "reason": f["status"]}
                                       for f in generation.get("files", []) if f["status"] != "generated"]
                                      or [{"path": "package-lock.json", "reason": generation["message"]}]})
                continue
            prs.append(submit_fix_batch(
                c["batch"], c["files"], base_branch,
                repo_dir=repo_dir, run_secret_scan=run_secret_scan,
                test_fn=test_fn, refix_fn=refix_fn, max_attempts=max_attempts,
            ))
        except Exception as e:  # noqa: BLE001 — isolate batch failures from the cycle
            prs.append({
                "status": "error",
                "batch_id": c.get("batch", {}).get("batch_id"),
                "pr_url": None,
                "message": f"batch failed: {e}",
            })
        if c.get("generation"):
            prs[-1]["generation"] = c["generation"]
    pr_urls = [r["pr_url"] for r in prs if r.get("pr_url")]
    opened = len(pr_urls)
    errored = sum(1 for r in prs if r.get("status") == "error")
    if opened:
        status = "prs_opened"
    elif errored:
        status = "error"
    else:
        status = "no_commits"
    return {
        "status": status,
        "prs": prs,
        "pr_urls": pr_urls,
        "message": (
            f"{len(cycle)} batch(es): {opened} PR(s) opened, "
            f"{len(cycle) - opened - errored} with no PR, {errored} errored. Human reviews and merges."
        ),
    }
