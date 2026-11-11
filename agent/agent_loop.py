#!/usr/bin/env python3
"""
agent/agent_loop.py -- ASVA Fix Agent (Stage B)
=================================================
Reads batches, generates candidates using the LLM or the npm path,
then hands off to gitops.git_gh_ops.submit_scan_cycle
which handles the secrets gate, branching, committing, pushing, and PR
creation.

One PR per batch:
  asva_sast_239f8ach_1.json   -> fix/asva_sast_239f8ach_1   -> PR #1
  asva_sca_239f8ach.json      -> fix/asva_sca_239f8ach      -> PR #2
  asva_container_239f8ach.json-> fix/asva_container_239f8ach -> PR #3

Usage:
    python agent_loop.py --batch-dir ../fix_batches
    python agent_loop.py --batch-dir ../fix_batches --batch asva_sast_239f8ach_1.json
    python agent_loop.py --batch-dir ../fix_batches --dry-run
    python agent_loop.py --batch-dir ../fix_batches --dry-run --no-repo-context      # ITP1 baseline
    python agent_loop.py --batch-dir ../fix_batches --dry-run --no-rag               # without the RAG (3.3)
    python agent_loop.py --batch-dir ../fix_batches --dry-run --passes 2 --files-per-prompt 10

Passes (ITP2 task 3.6, "local and integration passes"):
    --passes 1 (default)  one pass; repo-aware context (3.1) is included unless --no-repo-context
    --passes 2            pass 1 (local): remediate with NO additional context
                          pass 2 (integration): remediate the pass-1 result again WITH the
                          additional context (RAG, repo context, memory)
    --files-per-prompt N  the MOST code_change files that go into one prompt (1, 10, 20, ...),
                          to study attention dilution as the amount of vulnerable code grows;
                          a batch with fewer files simply sends fewer
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

# Add project root to path so imports work when run from agent/ folder
sys.path.append(str(Path(__file__).resolve().parent.parent))

from llm.llm_client import call_llm, context_window, LLMUnavailableError
from llm import llm_client as _llm
from gitops.git_gh_ops import submit_scan_cycle
from gitops import config
from agent import regression_gate
from agent import npm_remediation
from agent import base_image
from agent import repo_context
from agent import import_map
from agent import rag_client
from agent import safe_upgrades
from agent import test_first
from agent.fix_context import FixContext, render_context

from dataclasses import replace
from datetime import datetime, timezone

from memory.memory_context import build_memory_context, previous_errors
from memory.memory_store import init_db, load_memory, make_fingerprint, save_fix
from memory.decisions_loader import load_decisions_file, make_finding_key, find_decision, apply_decision

# One id per pipeline run (batch ids repeat across runs on the same commit).
RUN_ID = os.environ.get("GITHUB_RUN_ID") or f"local-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}"


# ===========================================================================
# SECTION 1: CONSTANTS
# ===========================================================================

# Fix types whose prompt gets repo-aware context (3.1). Dependency and config fixes don't:
# the import graph says nothing useful about package.json or docker-compose.yml.
REPO_CONTEXT_FIX_TYPES = frozenset({"code_change", "logic_change"})

# Added to a prompt in the integration pass (3.6, pass 2) only.
SECOND_PASS_NOTE = (
    "This is the second (integration) pass. The current content below already includes a "
    "first-pass fix that was made WITHOUT the additional context. Use the additional context "
    "to correct or complete that fix where needed, and keep it compatible with the related "
    "files. If the first-pass fix is already correct and complete, return the content "
    "unchanged. Line numbers in the findings refer to the original file.\n\n"
)

# How each target-app language is named in prompts. "node" keeps the ITP1 wording exactly.
APP_LANGUAGE_LABELS = {"node": "Node.js", "python": "Python/Django"}

# Extra rules for Python targets (the same rules as the single-file Python prompt)
PYTHON_PROMPT_RULES = (
    "- Preserve intended functionality and lab routes.\n"
    "- Do not remove authentication, CSRF protection, tests or application features to "
    "silence findings.\n"
)


def app_language() -> str:
    """The target app's language: "node" or "python".

    ASVA_APP_LANGUAGE wins when set (CI sets it for PyGoat). Otherwise it is detected from
    the app folder ASVA_FIX_PATH_PREFIX points at (target-apps/NodeGoat -> node,
    target-apps/PyGoat -> python), so a local run against either app needs no extra setting.
    With no prefix the default is "node", the ITP1 behaviour."""
    explicit = os.environ.get("ASVA_APP_LANGUAGE", "").strip().lower()
    if explicit:
        return "node" if explicit in ("node", "nodejs", "javascript", "js") else explicit
    root = _app_root()
    if root is not None:
        return repo_context.detect_app_language(root) or "node"
    return "node"


def _app_root() -> Path | None:
    if not config.FIX_PATH_PREFIX:
        return None
    root = Path(config.FIX_PATH_PREFIX)
    return root if root.is_absolute() else Path(__file__).resolve().parent.parent / root


def app_label() -> str:
    """How the app is named in prompts: "Node.js", or "Python/<framework>" (Django for
    PyGoat, Flask for vulnbank); plain "Python/Django" when the app folder isn't known, as
    in the team's original PyGoat prompt."""
    lang = app_language()
    if lang == "python":
        root = _app_root()
        # Only name a framework when the app folder really is a Python app (not when
        # ASVA_APP_LANGUAGE forces python while the prefix points elsewhere)
        if root is not None and repo_context.detect_app_language(root) == "python":
            framework = repo_context.detect_python_framework(root)
            return f"Python/{framework}" if framework else "Python"
    return APP_LANGUAGE_LABELS.get(lang, lang.capitalize())


# ===========================================================================
# SECTION 2: LLM FIX PROMPTS
# Different prompt per fix_type — same LLM call pattern.
# ===========================================================================

def _image_ref(location: dict) -> str:
    """ "mongo:4.4" from a container finding's location.image_name / image_tag; "" when
    the finding doesn't name its image (e.g. a batch written before those fields existed)."""
    name, tag = location.get("image_name"), location.get("image_tag")
    if not name:
        return ""
    return f"{name}:{tag}" if tag else name


def sca_upgrade_map(findings: list[dict]) -> dict[str, str]:
    """{direct dependency: target version} from a version_upgrade file's findings, keeping
    the highest upgrade_to per dependency. Covered findings are included since they may
    reference different packages."""
    upgrade_map: dict[str, str] = {}
    for f in findings:
        pkg_full  = f["location"].get("package") or ""
        upgrade   = f["remediation"].get("upgrade_to") or ""
        if not pkg_full or not upgrade:
            continue
        # upgrade_to is in format "pkgname@version" — extract direct dep name
        dep_name, _, dep_ver = upgrade.rpartition("@")
        if not dep_name:
            dep_name, dep_ver = upgrade, ""
        if dep_name not in upgrade_map:
            upgrade_map[dep_name] = dep_ver
        # keep highest version if multiple findings reference same dep
        else:
            try:
                from packaging.version import Version
                if dep_ver and Version(dep_ver) > Version(upgrade_map[dep_name]):
                    upgrade_map[dep_name] = dep_ver
            except Exception:
                # if version comparison fails, keep existing
                pass
    return upgrade_map


def _python_findings(findings: list[dict], fix_type: str) -> list[dict]:
    """The findings as shown in the Python prompt: the same compact summary the Node.js
    code_change prompt uses for scanner findings (line, title, description, CWE, rule).
    The full normalised finding (score, dedup key, code flow, remediation, ...) is several
    times larger: PyGoat's introduction/views.py has 69 findings, ~87,000 characters as full
    JSON, which overflowed a 32k-token context window. Dependency/container findings are kept
    whole, since the upgrade target lives in them."""
    if fix_type != "code_change" or any(f.get("finding_type") not in (None, "sast") for f in findings):
        return findings
    return [{
        "line":        (f.get("location") or {}).get("line"),
        "title":       f.get("title"),
        "description": f.get("description"),
        "cwe":         (f.get("identifiers") or {}).get("cwe"),
        "rule_id":     (f.get("identifiers") or {}).get("rule_id"),
    } for f in findings]


def build_fix_prompt(
    file_path: str,
    current_content: str,
    findings: list[dict],
    fix_type: str,
    *,
    context: FixContext | None = None,
    second_pass: bool = False,
) -> str:
    """Build the LLM prompt for a given file and its findings.

    `context` (RAG guidance, memory, repo usage) is rendered as one read-only block between
    the findings and the file content. The caller decides which fields to fill; an empty or
    missing context leaves the prompt exactly as it was before ITP2. `second_pass` marks the
    integration pass of 3.6, whose `current_content` is the pass-1 result."""

    ctx_block = (SECOND_PASS_NOTE if second_pass else "") + render_context(context)

    # Python source fixes use the framework-aware prompt; dependency, container and config
    # fixes for Python apps use the type-specific prompts below (pip requirements, Dockerfile).
    if app_language() == "python" and fix_type == "code_change":
        return f"""You are fixing a {app_label()} application. File: {file_path}
Fix only the reported vulnerabilities and preserve intended functionality and lab routes.
For requirements.txt, use exactly the versions listed in the findings and no other new major version; preserve unrelated pins.
For Dockerfile.asva, change the vulnerable base image or package instructions, preserving startup.
Do not remove authentication, CSRF protection, tests or application features to silence findings.
Findings: {json.dumps(_python_findings(findings, fix_type), indent=2)}
{ctx_block}Current file:
{current_content}
Return ONLY the complete fixed file content, without markdown or explanation.
"""

    if fix_type == "code_change":
        # SAST — edit application source code
        findings_summary = json.dumps([{
            "line":        f["location"]["line"],
            "title":       f["title"],
            "description": f["description"],
            "cwe":         f["identifiers"].get("cwe"),
            "rule_id":     f["identifiers"].get("rule_id"),
        } for f in findings], indent=2)

        language = "Python" if Path(file_path).suffix.lower() == ".py" else "Node.js"
        return f"""You are a senior security engineer fixing vulnerabilities in a {language} application.

File: {file_path}

Vulnerabilities to fix:
{findings_summary}

{ctx_block}Current file content:
{current_content}

Instructions:
- Fix ALL vulnerabilities listed above in the file content provided.
- Do NOT change any logic unrelated to the vulnerabilities.
- Do NOT add comments explaining the fix.
- Return ONLY the complete fixed file content. No explanation, no markdown, no code blocks.
"""

    elif fix_type == "version_upgrade":
        # SCA — bump package versions in the application's dependency manifest.
        packages_summary = json.dumps([{
            "package":    f["location"].get("package"),
            "upgrade_to": f["remediation"].get("upgrade_to"),
            "cve":        f["identifiers"].get("cve"),
            "title":      f["title"],
        } for f in findings if f["finding_type"] == "sca"], indent=2)

        container_summary = json.dumps([{
            "package":    f["location"].get("package"),
            "upgrade_to": f["remediation"].get("upgrade_to"),
            "cve":        f["identifiers"].get("cve"),
            "title":      f["title"],
        } for f in findings if f["finding_type"] == "container"], indent=2)

        if any(f["finding_type"] == "sca" for f in findings):
            upgrade_map = sca_upgrade_map(findings)

            upgrades_summary = json.dumps([
                {"package": pkg, "upgrade_to_version": ver}
                for pkg, ver in upgrade_map.items()
            ], indent=2)

            if Path(file_path).name.lower() == "requirements.txt":
                return f"""You are a senior security engineer fixing vulnerable Python dependencies in a requirements.txt file.

File: {file_path}

Required package upgrades:
{upgrades_summary}

{ctx_block}Current file content:
{current_content}

Instructions:
- Update only the listed packages already present in this requirements file to exactly the specified upgrade versions.
- Change no other package, and never move a package to a new major version unless that version is listed above.
- If the current version is already equal to or higher than the specified version, leave it unchanged.
- Preserve unrelated dependencies, comments, extras, environment markers and requirements-file syntax.
- Do NOT convert this file to JSON or add invented dependency entries.
- Return ONLY the complete fixed file content. No explanation, no markdown, no code blocks.
"""

            return f"""You are a senior security engineer fixing vulnerable npm dependencies.

File: {file_path}

Direct dependencies to upgrade (update these exact package names to the specified versions):
{upgrades_summary}

{ctx_block}Current file content:
{current_content}

Instructions:
- Update ONLY the packages listed above in the dependencies or devDependencies sections.
- Set each package to EXACTLY the version specified in upgrade_to_version.
- If the current version is already equal to or higher than the specified version, leave it unchanged.
- Do NOT add, remove, or rename any other packages, and never move a package to a new major version unless that version is listed above.
- Preserve all formatting, indentation, and JSON structure exactly.
- Return ONLY the complete fixed file content. No explanation, no markdown, no code blocks.
"""
        else:
            # container — update the image version in the file that defines it (a Compose
            # file for NodeGoat, a Dockerfile for other apps; triage picks the file).
            # unique scanned images from the findings (e.g. "mongo:4.4", "redis:6.0")
            images = sorted({_image_ref(f["location"]) for f in findings} - {""})
            return f"""You are a senior security engineer fixing vulnerable container images in the file that defines them.

File: {file_path}

Vulnerable container images identified in the scan:
{json.dumps(images, indent=2)}

Vulnerable OS packages found inside those images:
{container_summary}

{ctx_block}Current file content:
{current_content}

Instructions:
- Find where {file_path} uses the vulnerable image(s) listed above (e.g. an `image:` entry in a Compose file, or a `FROM` line in a Dockerfile).
- Update each image to a tag that resolves the listed OS package vulnerabilities, and keep its current major version: a 4.4 tag may become another 4.x tag, never 5.x or later. Never use the `latest` tag.
- If the additional context names a compatible tag, use exactly that tag. If it says there is none, or no tag within the major version resolves the vulnerabilities, return the file unchanged.
- If a listed image is built from this file rather than referenced in it, update the base image in its `FROM` line instead.
- Do NOT change anything else in the file.
- Preserve all formatting, indentation, and structure exactly.
- Return ONLY the complete fixed file content. No explanation, no markdown, no code blocks.
"""

    elif fix_type == "logic_change":
        # A business-logic bug proven by a failing misuse-case test, not a
        # scanner rule -- no CWE/line/rule_id, only the expected behaviour and why it
        # currently fails. Logic batches normally go through build_multi_file_prompt (all
        # files in one prompt); this per-file branch only exists so a single logic_change
        # file processed on its own still gets a sane prompt.
        detail = findings[0]["description"] if findings else "(no description)"
        return f"""You are a senior security engineer fixing a business-logic vulnerability
in a {app_label()} application, proven by a failing security test rather than a static scanner.

File: {file_path}

Vulnerability (confirmed by test, not by a scanner rule):
{detail}

{ctx_block}Current file content:
{current_content}

Instructions:
- Fix the vulnerability described above.
- Do NOT change any logic unrelated to it.
- Do NOT add comments explaining the fix.
- Return ONLY the complete fixed file content. No explanation, no markdown, no code blocks.
"""

    else:
        # config_change — generic fallback
        findings_summary = json.dumps([{
            "title":       f["title"],
            "description": f["description"],
        } for f in findings], indent=2)

        return f"""You are a senior security engineer fixing a configuration vulnerability.

File: {file_path}

Findings:
{findings_summary}

{ctx_block}Current file content:
{current_content}

Instructions:
- Fix the configuration issues listed above.
- Do NOT change anything unrelated.
- Return ONLY the complete fixed file content. No explanation, no markdown, no code blocks.
"""


_LOGIC_FILE_START = "===FILE: {path}==="
_LOGIC_FILE_END = "===END FILE==="


def build_logic_change_prompt(file_contents: dict[str, str], detail: str,
                              contexts: dict[str, FixContext | None] | None = None) -> str:
    """Prompt covering ALL of a logic-change batch's files in one call -- a business-logic
    fix (e.g. an IDOR route + the DAO it calls + wherever the route is registered) can need
    coordinated changes across files. This is the ITP1 prompt, still used verbatim for a
    logic batch's first pass when there is no additional context."""
    contexts = contexts or {}
    files_block = "\n\n".join(
        f"{render_context(contexts.get(path))}{_LOGIC_FILE_START.format(path=path)}\n{content}\n{_LOGIC_FILE_END}"
        for path, content in file_contents.items()
    )
    file_list = ", ".join(file_contents)
    return f"""You are a senior security engineer fixing a business-logic vulnerability in
a {app_label()} application, proven by a failing security test rather than a static scanner rule.

Vulnerability (confirmed by test, not a scanner rule):
{detail}

Files that may need coordinated changes: {file_list}

Current content of each file:
{files_block}

Instructions:
- Fix the vulnerability described above. You may need to change more than one file for a
  consistent fix (e.g. a route parameter removed from one file must also be removed
  wherever that route is registered).
- Do NOT change any logic unrelated to the vulnerability.
- Do NOT add comments explaining the fix.
- Return EVERY file listed above, even if a file needs no change (return it unchanged).
- Return your answer using EXACTLY this format for each file, nothing else:

===FILE: <path>===
<complete fixed file content>
===END FILE===
"""


def parse_logic_change_response(response: str, expected_paths: list[str]) -> dict[str, str]:
    """Parse the "===FILE: path===" / "===END FILE===" delimited response back into
    {path: content}. A file the LLM didn't return is simply absent from the result --
    the caller treats that the same as any other file an LLM call didn't produce."""
    pattern = re.compile(r"===FILE:\s*(.+?)\s*===\s*\n(.*?)\n===END FILE===", re.DOTALL)
    found: dict[str, str] = {}
    for match in pattern.finditer(response):
        path = match.group(1).strip()
        if path not in expected_paths:
            continue
        content = match.group(2).strip()
        # LLM sometimes wraps an individual file in a markdown fence despite instructions
        if content.startswith("```"):
            lines = content.split("\n")
            content = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
        found[path] = content.strip()
    return found


def get_llm_logic_fix(file_contents: dict[str, str], detail: str,
                      contexts: dict[str, FixContext | None] | None = None) -> dict[str, str]:
    """One LLM call for an entire logic_change batch. Returns {path: fixed_content} for
    whichever files the LLM actually returned."""
    prompt = build_logic_change_prompt(file_contents, detail, contexts)
    print(f"    Querying LLM for a coordinated fix across {len(file_contents)} file(s)...")
    response = call_llm(prompt)
    return parse_logic_change_response(response, list(file_contents))


def _findings_summary(findings: list[dict], fix_type: str) -> str:
    """Per-file findings for a multi-file prompt, in the same shape the single-file prompt
    uses: JSON for scanner findings, the plain description for logic findings."""
    if not findings:
        return "None for this file. Return it unchanged."
    if fix_type == "logic_change":
        return findings[0].get("description") or "(no description)"
    return json.dumps([{
        "line":        (f.get("location") or {}).get("line"),
        "title":       f.get("title"),
        "description": f.get("description"),
        "cwe":         (f.get("identifiers") or {}).get("cwe"),
        "rule_id":     (f.get("identifiers") or {}).get("rule_id"),
    } for f in findings], indent=2)


def build_multi_file_prompt(
    files: list[dict],
    *,
    contexts: dict[str, FixContext | None] | None = None,
    second_pass: bool = False,
) -> str:
    """One prompt covering several files (3.6 batch-size experiments: 10 or 20 files with
    their findings in a single prompt). `files` = [{"path", "content", "findings",
    "fix_type"}]. Output uses the ===FILE:=== format read by parse_logic_change_response.

    A logic batch in the first pass with no context gets exactly the ITP1 logic prompt
    (build_logic_change_prompt), so the ITP1 baseline is reproduced byte for byte."""
    contexts = contexts or {}
    if (not second_pass and not any(contexts.values())
            and files and all(f["fix_type"] == "logic_change" for f in files)):
        detail = next((f["findings"][0].get("description") for f in files if f["findings"]),
                      None) or "(no description)"
        return build_logic_change_prompt({f["path"]: f["content"] for f in files}, detail)

    blocks = []
    for i, f in enumerate(files, start=1):
        ctx_block = render_context(contexts.get(f["path"]))
        blocks.append(
            f"### File {i} of {len(files)}: {f['path']}\n"
            f"Vulnerabilities to fix in this file:\n{_findings_summary(f['findings'], f['fix_type'])}\n\n"
            f"{ctx_block}Current content:\n"
            f"{_LOGIC_FILE_START.format(path=f['path'])}\n{f['content']}\n{_LOGIC_FILE_END}"
        )
    note = SECOND_PASS_NOTE if second_pass else ""
    files_block = "\n\n".join(blocks)
    extra_rules = PYTHON_PROMPT_RULES if app_language() == "python" else ""
    return f"""You are a senior security engineer fixing vulnerabilities in a {app_label()} application.

You are given {len(files)} file(s). Each file lists its own vulnerabilities.

{note}{files_block}

Instructions:
- Fix ALL vulnerabilities listed for each file in that file's content.
- Do NOT change any logic unrelated to the vulnerabilities.
{extra_rules}- Do NOT add comments explaining the fix.
- Return EVERY file listed above, even if a file needs no change (return it unchanged).
- Return your answer using EXACTLY this format for each file, nothing else:

===FILE: <path>===
<complete fixed file content>
===END FILE===
"""


def _strip_markdown_fences(result: str) -> str:
    """Strip markdown code blocks if the LLM wraps its response in them."""
    result = result.strip()
    if result.startswith("```"):
        lines = result.split("\n")
        # remove first and last ``` lines
        result = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
    return result.strip()


def get_llm_fix(
    file_path: str,
    current_content: str,
    findings: list[dict],
    fix_type: str,
    *,
    context: FixContext | None = None,
    second_pass: bool = False,
) -> str:
    """Ask the LLM to fix a file. Returns the fixed content as a string."""
    prompt = build_fix_prompt(
        file_path, current_content, findings, fix_type, context=context, second_pass=second_pass
    )
    print(f"    Querying LLM for fix... ({fix_type})")
    return _strip_markdown_fences(call_llm(prompt))


def build_refix_prompt(
    file_path: str,
    current_content: str,
    findings: list[dict],
    fix_type: str,
    failed_content: str,
    attempt: int,
    *,
    context: FixContext | None = None,
    reason: str | None = None,
) -> str:
    """Build the retry prompt: the normal fix prompt plus the rejected previous attempt,
    so the LLM knows what not to repeat. Without this context a retry is just a re-roll
    of the same prompt, likely to produce the same rejected output. The same FixContext
    as the first attempt is passed through, so a retry is never thinner than the original.
    `reason`: the app failed its tests with this attempt (agent/test_first.py); the failure may
    come from another file of the same batch, so an innocent attempt can come back unchanged."""
    base = build_fix_prompt(file_path, current_content, findings, fix_type, context=context)
    if reason:
        return base + f"""
IMPORTANT: the app was built and tested with a previous automated fix for this file (attempt
{attempt}, shown below) and fixes for other files, and it failed:

{reason}

Keep the vulnerability fixed and keep the app working: legitimate behaviour such as the failure
above expects must still work. If this attempt is not what caused the failure, return it unchanged.

Previous attempt {attempt}:
{failed_content}

Return ONLY the complete corrected file content. No explanation, no markdown, no code blocks.
"""
    return base + f"""
IMPORTANT: a previous automated fix for this file (attempt {attempt}, shown below) was
rejected before commit because it failed a syntax/validity check. Produce a corrected fix
that is different from it.

Rejected attempt {attempt}:
{failed_content}

Return ONLY the complete corrected file content. It must be syntactically valid. No
explanation, no markdown, no code blocks.
"""


def get_llm_refix(
    file_path: str,
    current_content: str,
    findings: list[dict],
    fix_type: str,
    failed_content: str,
    attempt: int,
    *,
    context: FixContext | None = None,
    reason: str | None = None,
) -> str:
    """Ask the LLM for a revised fix after a previous attempt failed the validity gate or the app's tests."""
    prompt = build_refix_prompt(
        file_path, current_content, findings, fix_type, failed_content, attempt,
        context=context, reason=reason,
    )
    print(f"    Querying LLM for a revised fix... (attempt {attempt + 1} for {file_path})")
    return _strip_markdown_fences(call_llm(prompt))


def llm_generation(batch, files, outcomes):
    generated = len(files)
    status = "generated" if generated == len(outcomes) else "partial" if generated else "error"
    return {"batch": batch, "files": files, "generation": {
        "method": "llm", "status": status, "files": outcomes,
        "message": f"Generated {generated}/{len(outcomes)} requested files",
    }}


# ===========================================================================
# SECTION 3: CONTEXT HELPERS (3.1 repo-aware context, D3 upgrade review notes)
# ===========================================================================

def repo_context_enabled(flag: bool | None = None) -> bool:
    """Repo-aware context is on unless --no-repo-context (flag=False) or ASVA_REPO_CONTEXT=0.
    The switch exists for the with/without A/B comparison and as a cheap escape hatch."""
    if flag is False:
        return False
    return os.environ.get("ASVA_REPO_CONTEXT", "1").strip() != "0"


def load_repo_index(repo_dir: str) -> "repo_context.ImportIndex | None":
    """Build the target app's import index. Context is best-effort: any failure here is
    logged and the fix run carries on without it rather than aborting."""
    try:
        index = repo_context.build_import_index(
            repo_context.app_root_for(repo_dir, config.FIX_PATH_PREFIX)
        )
    except Exception as e:  # noqa: BLE001 -- never let context break a fix run
        print(f"    [WARN] Could not build repo import index ({e}) — continuing without it")
        return None
    print(f"    Repo index: {len(index.files)} file(s) indexed")
    return index


def write_batch_import_map(
    index: "repo_context.ImportIndex",
    batch: dict,
    import_map_dir: str | Path,
) -> Path | None:
    """Write the interactive import map of the index this batch is fixed against, with the
    batch's files ringed (agent/import_map.py). Best-effort, like the index itself: a failure
    is logged and the fix run carries on."""
    out_path = Path(import_map_dir) / f"import_map_{batch.get('batch_id') or 'batch'}.html"
    try:
        out = import_map.write_import_map(index, out_path, batch)
    except Exception as e:  # noqa: BLE001 -- never let the map break a fix run
        print(f"    [WARN] Could not write import map ({e}) — continuing without it")
        return None
    print(f"    Import map: {out}")
    return out


def file_fix_context(
    file_path: str,
    fix_type: str,
    index: "repo_context.ImportIndex | None",
    findings: list[dict] | None = None,
) -> FixContext | None:
    """FixContext for one file. Only repo context (3.1) is filled here: the files that
    import / are imported by this one, plus the SAST scanner's data flow for its findings
    and the code of other files on that flow. RAG (3.3) and memory (3.5) fill their own
    fields of the same FixContext when they land."""
    if index is None or fix_type not in REPO_CONTEXT_FIX_TYPES:
        return None
    parts = [
        repo_context.render_code_flow(file_path, findings or [], index),
        repo_context.gather_repo_context(file_path, index, findings=findings),
    ]
    text = "\n\n".join(p for p in parts if p)
    if not text:
        return None
    print(f"    Repo context: {len(text)} chars")
    return FixContext(repo=text)


def misuse_fix_contexts(paths: list[str], repo_dir: str, use_repo_context: bool | None) -> dict[str, FixContext | None]:
    """Repo context (3.1) for the files of a misuse fix (agent/test_first.py). No memory (3.5) or RAG
    (3.3): both look up scanner findings, and these holes come from a test. Best-effort, like the index."""
    if not repo_context_enabled(use_repo_context):
        return {}
    try:
        index = load_repo_index(repo_dir)
        return {path: file_fix_context(path, "logic_change", index) for path in paths}
    except Exception as e:  # noqa: BLE001 -- never let context break a fix run
        print(f"    [WARN] Could not build repo context ({e}) — continuing without it")
        return {}


def with_memory(context: FixContext | None, memory_text: str) -> FixContext | None:
    """Add the memory section (3.5) to a file's FixContext (repo context, if any, is kept)."""
    if not memory_text:
        return context
    return replace(context, memory=memory_text) if context else FixContext(memory=memory_text)


def with_rag(context: FixContext | None, path: str, findings: list[dict], fix_type: str) -> FixContext | None:
    """Add the RAG section (3.3) to a file's FixContext. Off when ASVA_RAG_URL is empty; a RAG
    failure is logged and leaves the context as it was."""
    rag_text = rag_client.prompt_context(path, findings, fix_type)
    if not rag_text:
        return context
    return replace(context, rag=rag_text) if context else FixContext(rag=rag_text)


def held_back_generation(batch: dict, held: dict[str, str]) -> dict:
    """Every file in the batch has nothing safe to change: no PR, and no failure either. The
    reviewer gets the reason and the options in an issue (gitops/post_fix_failure_issue.py)."""
    answers = [rag_client.response(fe["findings"], fe["fix_type"]) for fe in batch.get("files_to_fix", [])]
    print(f"    [HELD BACK] {len(held)} file(s) with nothing safe to change — no LLM call")
    return {"batch": batch, "files": [], "passes": {}, "generation": {
        "method": "rag", "status": "no_candidate",
        "files": [{"path": path, "status": reason} for path, reason in held.items()],
        "message": "Nothing safe to change without a major version change",
        "rag_text": rag_client.pr_text(*answers),
    }}


def apply_reviewer_memory(entries: list[dict], decisions_data: dict) -> tuple[list[dict], dict]:
    """Memory (3.5) for each file: apply the dashboard's reviewer decisions per finding, then
    attach the fix history of the findings that remain.

    Returns (entries without reviewer-excluded findings, {path: memory context}). A file whose
    findings were all excluded is dropped. The memory context keeps the findings sent to the
    LLM and the memory text, for retries and for saving the outcome after submission."""
    kept, memory_context = [], {}
    for e in entries:
        path = e["path"]
        actionable, hints = [], []
        for finding in e["findings"]:
            finding_key = make_finding_key(finding)
            decision = find_decision(decisions_data, finding_key)
            if not decision:
                actionable.append(finding)
                continue
            print(f"    [MEMORY] {path}: reviewer decision for {finding_key}")
            action = apply_decision(decision, finding)
            if action in ("skip", "skip_pr"):
                continue  # accepted risk / false positive / needs manual fix: not for the LLM
            if action == "fix_with_hint":
                hints.append(finding.get("retry_hint", ""))
            actionable.append(finding)

        if not actionable:
            print(f"    [SKIP] No actionable findings remain for {path}")
            continue

        # Retrieve history for every actionable finding.
        history, seen_fingerprints = [], set()
        for finding in actionable:
            fingerprint = make_fingerprint(finding)
            if fingerprint in seen_fingerprints:
                continue
            seen_fingerprints.add(fingerprint)
            history.extend(load_memory(fingerprint))

        hint = "\n".join(h for h in hints if h) or None
        log = ""
        if history:
            runs = sorted({str(h["run_id"]) for h in history if h.get("outcome") == "committed"})
            last_run, errors = previous_errors(history)
            log = (f"    [MEMORY] {path}: injecting {len(runs)} previous run(s) of fix history "
                   f"({', '.join(runs) or 'none'}) and {len(errors)} error(s) from the previous pass"
                   f"{f' (run {last_run})' if errors else ''}")

        kept.append({**e, "findings": actionable})
        memory_context[path] = {
            "findings": actionable,
            "fix_type": e["fix_type"],
            "memory":   build_memory_context({"history": history}, hint),
            "log":      log,  # printed when the file's prompt goes to the LLM (not for a fix set in code)
        }
    return kept, memory_context


_VERSION_RE = re.compile(r"(\d+)(?:\.(\d+))?")


def _major_minor(spec: str) -> tuple[int, int] | None:
    """(major, minor) from a version or npm range like "^2.1.18" / "~0.3" / "2.2.4"."""
    m = _VERSION_RE.search(spec or "")
    if not m:
        return None
    return int(m.group(1)), int(m.group(2) or 0)


def is_breaking_upgrade(current_spec: str, target_version: str) -> bool:
    """Semver-breaking bump: a higher major, or a higher minor while still on 0.x."""
    cur, new = _major_minor(current_spec), _major_minor(target_version)
    if cur is None or new is None:
        return False
    if cur[0] >= 1900 or new[0] >= 1900:
        return False   # calendar versioning (certifi 2022.12.7 -> 2023.7.22) is not semver
    if new[0] != cur[0]:
        return new[0] > cur[0]
    return cur[0] == 0 and new[1] > cur[1]


_REQ_LINE_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*((?:===|==|~=|>=|<=|!=|>|<)\s*[^\s;#,]+)?")


def is_dependency_manifest(path: str) -> bool:
    """Manifests whose dependency upgrades get breaking-change review notes (D3)."""
    name = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name == "package.json" or bool(re.fullmatch(r"requirements[\w.-]*\.txt", name))


def pinned_requirements_fix(group: list[dict]) -> dict[str, str] | None:
    """{path: fixed content} when the versions can simply be set in a requirements file, where the
    LLM could only get them wrong: one such file, and every upgrade pinned there with `==`. Anything
    else (`Django>=4.0`, a package the file doesn't list) returns None and stays with the LLM."""
    if len(group) != 1 or group[0]["fix_type"] != "version_upgrade":
        return None
    entry = group[0]
    name = entry["path"].replace("\\", "/").rsplit("/", 1)[-1].lower()
    upgrades = sca_upgrade_map(entry["findings"]) if re.fullmatch(r"requirements[\w.-]*\.txt", name) else {}
    if not upgrades or any(not version or not test_first.pinned_version(entry["content"], package)
                           for package, version in upgrades.items()):
        return None
    content = entry["content"]
    for package, version in upgrades.items():
        content = test_first.set_version(content, package, version)
    print(f"    {entry['path']}: {len(upgrades)} version(s) set in code, no LLM needed")
    return {entry["path"]: content}


def _norm_dist(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def declared_dependencies(manifest_text: str, manifest: str = "package.json") -> dict[str, str]:
    """{package: declared version spec} from package.json, or from a pip requirements file
    (names PEP 503-normalised, e.g. "Django==2.2.13" -> {"django": "==2.2.13"})."""
    if manifest.replace("\\", "/").rsplit("/", 1)[-1].lower() == "package.json":
        try:
            data = json.loads(manifest_text)
        except ValueError:
            return {}
        declared: dict[str, str] = {}
        for section in ("dependencies", "devDependencies"):
            declared.update(data.get(section) or {})
        return declared
    declared = {}
    for line in manifest_text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        m = _REQ_LINE_RE.match(line)
        if m:
            declared[_norm_dist(m.group(1))] = (m.group(2) or "").replace(" ", "")
    return declared


def upgrade_review_notes(
    manifest_text: str,
    upgrade_map: dict[str, str],
    index: "repo_context.ImportIndex | None",
    manifest: str = "package.json",
) -> list[str]:
    """Reviewer notes for breaking dependency upgrades, naming where the app uses each
    package. The version_upgrade prompt only edits the manifest (package.json or
    requirements.txt), so code that relies on the old API (e.g. the ITP1 MongoDB driver
    mismatch) can only be caught by a human -- this points them at it. Deterministic, no
    LLM involved."""
    declared = declared_dependencies(manifest_text, manifest)
    if not declared:
        return []
    is_pip = not manifest.replace("\\", "/").lower().endswith("package.json")

    notes = []
    for pkg, target in sorted(upgrade_map.items()):
        current = declared.get(_norm_dist(pkg) if is_pip else pkg)
        if not current or not target or not is_breaking_upgrade(current, target):
            continue
        if is_pip:
            sites = [s for name in repo_context.python_import_names(pkg)
                     for s in repo_context.package_usage_sites(index, name)]
            current_display = current.lstrip("=~<>!") or current
        else:
            sites = repo_context.package_usage_sites(index, pkg)
            current_display = current
        where = (
            "Check the code that uses it: " + ", ".join(f"`{s}`" for s in sites[:10])
            + (f" (+{len(sites) - 10} more)" if len(sites) > 10 else "")
            if sites else "No direct imports were found in the app; check indirect use."
        )
        notes.append(
            f"`{pkg}` {current_display} -> {target} is a breaking (major) upgrade and may change its "
            f"API. {where}"
        )
    return notes


# ===========================================================================
# SECTION 4: BATCH PROCESSING
# ===========================================================================

def make_prompt_groups(entries: list[dict], batch_type: str, files_per_prompt: int) -> list[list[dict]]:
    """Split a batch's files into the groups that share one prompt.

    - logic batches: all files in ONE prompt (a coordinated business-logic fix, as in ITP1)
    - code_change files: chunks of at most `files_per_prompt` (1 = one prompt per file, as
      in ITP1). It is a limit, not a target: 9 files at a limit of 20 is one prompt of 9.
    - anything else (dependency, container, config): one prompt per file
    """
    if batch_type == "logic":
        groups = [entries] if entries else []
    else:
        groups, chunk = [], []
        for e in entries:
            if e["fix_type"] == "code_change":
                chunk.append(e)
                if len(chunk) >= max(1, files_per_prompt):
                    groups.append(chunk)
                    chunk = []
            else:
                groups.append([e])
        if chunk:
            groups.append(chunk)
    return groups


def _is_multi(group: list[dict]) -> bool:
    return len(group) > 1 or group[0]["fix_type"] == "logic_change"


def build_pass_prompt(
    group: list[dict],
    contexts: dict[str, FixContext | None] | None,
    second_pass: bool,
) -> str:
    """The prompt for one group in one pass (used by run_pass and the preview script)."""
    if _is_multi(group):
        return build_multi_file_prompt(group, contexts=contexts, second_pass=second_pass)
    e = group[0]
    return build_fix_prompt(
        e["path"], e["content"], e["findings"], e["fix_type"],
        context=(contexts or {}).get(e["path"]), second_pass=second_pass,
    )


# Ollama's usual default context window when neither the server nor OLLAMA_NUM_CTX sets one.
_DEFAULT_CONTEXT_TOKENS = 4096


def _warn_if_prompt_may_be_truncated(prompt: str, reply_chars: int = 0) -> None:
    """Rough check (about 4 characters per token). The prompt AND the reply (the rewritten
    files, about as long as the files sent) share the model's context window; Ollama silently
    cuts whatever does not fit, which would invalidate a batch-size comparison."""
    est = len(prompt) // 4
    reply = reply_chars // 4
    cap = os.environ.get("ASVA_LLM_NUM_PREDICT", "").strip()
    if cap.isdigit() and reply > 0.9 * int(cap):
        # The reply itself is capped at ASVA_LLM_NUM_PREDICT tokens (sent as max_tokens)
        print(f"    [WARN] reply may need ~{reply} tokens, close to or over the reply cap "
              f"ASVA_LLM_NUM_PREDICT={cap}; the rewritten file(s) may be cut off")
    window = context_window()
    if est + reply <= 0.9 * (window or _DEFAULT_CONTEXT_TOKENS):
        return
    if window:
        print(f"    [WARN] prompt is ~{est} tokens plus a ~{reply}-token reply, close to or over "
              f"OLLAMA_NUM_CTX={window}; the model may not see or finish all of it")
    else:
        print(f"    [WARN] prompt is ~{est} tokens plus a ~{reply}-token reply and "
              f"OLLAMA_NUM_CTX is not set; Ollama's default window (often "
              f"{_DEFAULT_CONTEXT_TOKENS} tokens) may cut it off")


def run_pass(
    group: list[dict],
    contexts: dict[str, FixContext | None] | None,
    second_pass: bool,
) -> dict[str, str]:
    """One LLM call for one group. Returns {path: content} for the files the LLM returned
    with non-empty content. LLMUnavailableError propagates to the caller."""
    prompt = build_pass_prompt(group, contexts, second_pass)
    _warn_if_prompt_may_be_truncated(prompt, sum(len(e["content"]) for e in group))
    label = "integration" if second_pass else "local"
    _llm.last_call.clear()
    if _is_multi(group):
        print(f"    Querying LLM ({label} pass) for {len(group)} file(s) in one prompt...")
        found = parse_logic_change_response(call_llm(prompt), [e["path"] for e in group])
    else:
        print(f"    Querying LLM ({label} pass) for {group[0]['path']}... ({group[0]['fix_type']})")
        found = {group[0]["path"]: _strip_markdown_fences(call_llm(prompt))}
    if _llm.last_call.get("finish_reason") == "length":
        # The model hit its output/context limit: the reply (and any file in it) is incomplete
        lc = _llm.last_call
        print(f"    [WARN] reply was cut off before the end (finish_reason=length; "
              f"prompt_tokens={lc.get('prompt_tokens')}, "
              f"completion_tokens={lc.get('completion_tokens')}, "
              f"reasoning_chars={lc.get('reasoning_chars')}, answer_chars={lc.get('answer_chars')})")
        if lc.get("reasoning_chars") and not lc.get("answer_chars"):
            print("    [WARN] the model spent the whole reply on hidden reasoning and wrote no code; "
                  "raise ASVA_LLM_NUM_PREDICT or reduce reasoning (ASVA_LLM_REASONING_EFFORT / "
                  "ASVA_LLM_EXTRA_BODY)")
        if not _is_multi(group):
            # A single-file reply that stopped early is a truncated file, not a fix. (Multi-file
            # replies only keep files closed by ===END FILE===, so they are already safe.)
            found = {}
    return {p: c for p, c in found.items() if c.strip()}


def process_batch(
    batch_path: Path,
    repo_dir: str = ".",
    *,
    use_repo_context: bool | None = None,
    passes: int = 1,
    files_per_prompt: int = 1,
    import_map_dir: str | Path | None = None,
) -> dict:
    """
    Load one batch file, generate LLM fixes for its files.
    Returns a cycle entry: {"batch": ..., "files": [{"path", "content"}, ...],
                            "passes": {"after_pass1": {...}, "after_pass2": {...}}}

    passes=1: one pass; additional context (3.1 repo context) is included unless switched off.
    passes=2 (3.6): pass 1 (local) remediates with NO additional context; pass 2
      (integration) remediates the pass-1 result again WITH the additional context. A file
      pass 2 omits, or a pass-2 LLM outage, keeps the pass-1 result; a group with no
      additional context at all skips pass 2 (it would only be a re-roll of pass 1).
      An LLM outage in pass 1 aborts the run (existing contract).
    files_per_prompt: the most code_change files per prompt (3.6 batch-size experiments).
    import_map_dir: when set and the import index is built, write an interactive HTML map
      of it there (import_map_<batch_id>.html).

    "passes" records the state after each pass, so each pass can be evaluated separately.
    The import index is built once per batch. Breaking dependency upgrades are recorded on
    batch["review_notes"] ({path: [note, ...]}) for the PR description.
    """
    decisions_data = load_decisions_file()

    print(f"\n  Loading batch: {batch_path.name}")
    batch = json.loads(batch_path.read_text(encoding="utf-8"))

    if batch.get("remediation_method") == base_image.METHOD:
        return base_image.generate(batch)

    safe_upgrades.apply(batch)

    if npm_remediation.enabled(batch):
        result = npm_remediation.generate(batch, repo_dir)
        files = {f["path"]: f["content"] for f in result["files"]}
        if "package.json" in files and "package-lock.json" in files:
            safe_upgrades.add_pr_text(result["batch"], [
                rag_client.npm_response(fe["findings"], fe.get("fix_type"), files["package.json"], files["package-lock.json"])
                for fe in result["batch"].get("files_to_fix", []) if fe.get("findings")])
        return result

    batch_type = batch.get("batch_type", "unknown")
    print(f"  Type: {batch_type} | "
          f"Files: {batch['total_files']} | "
          f"Findings: {batch['total_findings']}")

    from gitops.git_gh_ops import repo_path

    raw_entries = batch.get("files_to_fix", [])
    # Nothing safe to change in these files: no LLM call, and the reason goes to the reviewer.
    held = {fe["file"]: reason for fe in raw_entries if (reason := safe_upgrades.nothing_to_edit(fe))}
    if held and len(held) == len(raw_entries):
        return held_back_generation(batch, held)
    raw_entries = [fe for fe in raw_entries if fe["file"] not in held]
    context_on = repo_context_enabled(use_repo_context)
    needs_prompt_ctx = context_on and (
        batch_type == "logic" or any(fe.get("fix_type") in REPO_CONTEXT_FIX_TYPES for fe in raw_entries)
    )
    needs_usage = context_on and any(
        fe.get("fix_type") == "version_upgrade" and is_dependency_manifest(fe["file"])
        for fe in raw_entries
    )
    # One switch covers every 3.1 feature (prompt context and upgrade review notes), so
    # --no-repo-context reproduces the pre-ITP2 behaviour exactly for A/B comparisons.
    index = load_repo_index(repo_dir) if (needs_prompt_ctx or needs_usage) else None
    if index is not None and import_map_dir:
        write_batch_import_map(index, batch, import_map_dir)

    entries: list[dict] = []
    for fe in raw_entries:
        path = fe["file"]
        fix_type = "logic_change" if batch_type == "logic" else fe["fix_type"]
        disk_path = Path(repo_dir) / repo_path(path)
        if not disk_path.exists():
            print(f"    [WARN] File not found on disk: {disk_path} — skipping")
            continue
        content = disk_path.read_text(encoding="utf-8")
        entries.append({"path": path, "content": content,
                        "findings": fe.get("findings", []), "fix_type": fix_type})
        if needs_usage and fix_type == "version_upgrade" and is_dependency_manifest(path):
            notes = upgrade_review_notes(content, sca_upgrade_map(fe.get("findings", [])), index,
                                         manifest=path)
            if notes:
                batch.setdefault("review_notes", {})[path] = notes
                print(f"    Review notes: {len(notes)} breaking upgrade(s) flagged for the PR")

    if not entries:
        print("    [WARN] No files on disk for this batch — nothing to fix")
        return {**llm_generation(batch, [], [{"path": fe["file"], "status": "missing_source"}
                                             for fe in raw_entries]), "passes": {}}

    # Memory (3.5): reviewer decisions and fix history. Logic batches have no per-finding keys.
    memory_context: dict[str, dict] = {}
    on_disk = {e["path"] for e in entries}
    if batch_type != "logic":
        entries, memory_context = apply_reviewer_memory(entries, decisions_data)
        if not entries:
            print("    [SKIP] Reviewer decisions excluded every finding in this batch")
            return {**llm_generation(batch, [], []), "passes": {}, "memory_context": {}}
    excluded = on_disk - {e["path"] for e in entries}  # every finding excluded by a reviewer

    contexts = {e["path"]: with_memory(file_fix_context(e["path"], e["fix_type"], index, e["findings"]),
                                       memory_context.get(e["path"], {}).get("memory", ""))
                for e in entries}
    if batch_type != "logic":  # logic batches come from a failing test: no scanner finding to look up
        contexts = {e["path"]: with_rag(contexts[e["path"]], e["path"], e["findings"], e["fix_type"]) for e in entries}
        safe_upgrades.add_pr_text(batch, [
            rag_client.manifest_response(e["path"], e["content"], e["findings"], e["fix_type"])
            if is_dependency_manifest(e["path"]) else rag_client.response(e["findings"], e["fix_type"])
            for e in entries], held)
    groups = make_prompt_groups(entries, batch_type, files_per_prompt)
    print(f"  Passes: {passes} | Prompts per pass: {len(groups)} "
          f"(files per prompt: {'all' if batch_type == 'logic' else files_per_prompt})")

    after_pass1: dict[str, str] = {}
    after_pass2: dict[str, str] = {}
    used_code: dict[str, str] = {}
    for group in groups:
        # Pass 1: with passes=2 this is the local pass, so NO additional context
        pass1_contexts = contexts if passes == 1 else None
        in_code = pinned_requirements_fix(group)
        if in_code is not None:
            used_code.update(in_code)
            after_pass1.update(in_code)
            after_pass2.update(in_code)
            continue
        for e in group:
            if memory_context.get(e["path"], {}).get("log"):
                print(memory_context[e["path"]]["log"])
        try:
            result = run_pass(group, pass1_contexts, second_pass=False)
        except LLMUnavailableError:
            print(f"    [FATAL] LLM did not respond for batch {batch.get('batch_id')} — aborting "
                  f"the whole run instead of working through the remaining files.")
            raise
        after_pass1.update(result)

        if passes >= 2:
            group_ctx = {e["path"]: contexts.get(e["path"]) for e in group}
            if not any(group_ctx.values()):
                print("    Integration pass skipped: no additional context for these file(s)")
                after_pass2.update(result)
                continue
            # Pass 2 starts from the pass-1 result (the original where pass 1 returned nothing)
            current = [{**e, "content": result.get(e["path"], e["content"])} for e in group]
            try:
                second = run_pass(current, group_ctx, second_pass=True)
            except LLMUnavailableError as e:
                print(f"    [WARN] Integration pass unavailable ({e}) — keeping the pass-1 result")
                second = {}
            merged = dict(result)
            merged.update(second)
            after_pass2.update(merged)

    final = after_pass2 if passes >= 2 else after_pass1
    files = []
    for e in entries:
        content = final.get(e["path"])
        if content is None:
            print(f"    [WARN] LLM did not return a fix for {e['path']} — skipping")
            continue
        if e["path"] not in used_code:
            print(f"    LLM fix received for {e['path']} ({len(content)} chars)")
        files.append({"path": e["path"], "content": content})

    recorded = {"after_pass1": after_pass1}
    if passes >= 2:
        recorded["after_pass2"] = after_pass2
    generated = {f["path"] for f in files}
    outcomes = [{"path": fe["file"], "status": "generated" if fe["file"] in generated else
                 "missing_source" if fe["file"] not in on_disk else "empty_or_truncated"}
                for fe in raw_entries if fe["file"] not in excluded]
    entry = {**llm_generation(batch, files, outcomes), "passes": recorded, "memory_context": memory_context}
    if used_code and len(used_code) == len(files):
        entry["generation"]["method"] = "code"  # no LLM wrote any of these
    return entry


def make_refix_fn(cycle: list[dict], repo_dir: str, *, use_repo_context: bool | None = None):
    """Build the refix_fn callback submit_fix_batch retries with when a fix fails the
    validity gate: revert happened already, so re-read the original file from disk and
    ask the LLM again — this time showing it the rejected attempt so it doesn't repeat it.
    Retries get the same repo context as the first attempt (index built lazily, once).

    Returns None (give up on the file, it lands in the PR body / failure issue) for:
    logic batches (their fixes are coordinated across files and can't be regenerated per
    file without desyncing the others), paths not in this cycle, files missing on disk, and
    an LLM outage mid-retry (fail the one file, not the whole submission — unlike the
    initial fix pass, where an outage aborts the run before anything is attempted).
    """
    from gitops.git_gh_ops import repo_path

    fix_types: dict[str, str] = {}
    last_attempt: dict[str, str] = {}
    contexts: dict[str, dict] = {}
    for entry in cycle:
        if entry.get("generation", {}).get("method") == "npm":
            continue  # Dependency pairs are regenerated together, never re-fixed per file.
        batch_is_logic = entry["batch"].get("batch_type") == "logic"
        for fe in entry["batch"].get("files_to_fix", []):
            fix_types[fe["file"]] = "logic_change" if batch_is_logic else fe.get("fix_type", "code_change")
        for f in entry["files"]:
            last_attempt[f["path"]] = f["content"]
        contexts.update(entry.get("memory_context", {}))

    context_on = repo_context_enabled(use_repo_context)
    index_cache: dict[str, "repo_context.ImportIndex | None"] = {}

    def refix(path: str, findings: list[dict], attempt: int, reason: str | None = None) -> str | None:
        fix_type = fix_types.get(path)
        if fix_type is None or fix_type == "logic_change":
            return None
        disk_path = Path(repo_dir) / repo_path(path)
        if not disk_path.exists():
            return None
        original = disk_path.read_text(encoding="utf-8")
        # git_gh_ops passes every finding in the batch file; keep reviewer-excluded ones out.
        ctx = contexts.get(path, {})
        findings = ctx.get("findings", findings)
        context = None
        if context_on and fix_type in REPO_CONTEXT_FIX_TYPES:
            if "index" not in index_cache:
                index_cache["index"] = load_repo_index(repo_dir)
            context = file_fix_context(path, fix_type, index_cache["index"], findings)
        context = with_rag(with_memory(context, ctx.get("memory", "")), path, findings, fix_type)
        try:
            new_content = get_llm_refix(
                path, original, findings, fix_type,
                failed_content=last_attempt.get(path, ""), attempt=attempt,
                context=context, reason=reason,
            )
        except LLMUnavailableError:
            print(f"    [WARN] LLM unavailable during re-fix of {path} — giving up on this file.")
            return None
        last_attempt[path] = new_content
        return new_content

    # Exposed so the final (possibly re-fixed) content is what gets saved to memory.
    refix.last_attempt = last_attempt
    return refix


REVIEWER_SKIPS = ("false_positive", "accepted_risk", "needs_manual_fix")


def reviewer_skipped(batch: dict) -> list[dict]:
    """The findings a reviewer's decision kept out of this PR (apply_reviewer_memory), so the PR
    check shows them as skipped rather than as fixes that did not work."""
    return [{"rule_id": (f.get("identifiers") or {}).get("rule_id"),
             "file": (f.get("location") or {}).get("file") or fe.get("file"),
             "line": (f.get("location") or {}).get("line"),
             "decision": f["memory_applied"]["decision"],
             "note": f["memory_applied"].get("note", "")}
            for fe in batch.get("files_to_fix", []) for f in fe.get("findings", [])
            if (f.get("memory_applied") or {}).get("decision") in REVIEWER_SKIPS]


def save_for_pr_check(batch_path: Path, entry: dict) -> None:
    """Add what the scan before the PR left, the misuse fixes that were dropped, and the findings a
    reviewer skipped to the batch file, for the PR's later check to read. Only those: the rest of
    the file is what validation compares the PR with."""
    batch = entry.get("batch") or {}
    notes = {key: batch[key] for key in ("new_before_pr", "misuse_dropped") if batch.get(key)}
    if skipped := reviewer_skipped(batch):
        notes["reviewer_skipped"] = skipped
    if notes:
        saved = json.loads(batch_path.read_text(encoding="utf-8"))
        saved.update(notes)
        batch_path.write_text(json.dumps(saved, indent=2), encoding="utf-8")


def save_cycle_to_memory(cycle: list[dict], prs: list[dict], final_content: dict[str, str]) -> None:
    """Record one fix_history row per finding the LLM was asked to fix, with the file's
    submission outcome: committed (in an open PR), rejected (secrets gate / tests / no-op,
    with the reason) or error (the whole batch failed to submit).

    The row's error is what this pass broke, for the next pass ("errors from pass N-1"): the
    pre-PR check or scan that still failed (agent/test_first.py), or the gate that rejected it."""
    results = {pr.get("batch_id"): pr for pr in prs}
    for entry in cycle:
        batch_id = entry["batch"].get("batch_id")
        pr = results.get(batch_id, {})
        reasons = {r["path"]: r.get("reason", "") for r in pr.get("blocked", []) + pr.get("failed", [])}
        check_failures = entry.get("check_failures", {})

        for f in entry["files"]:
            path = f["path"]
            ctx = entry.get("memory_context", {}).get(path)
            if not ctx:
                continue  # logic batches don't use per-finding memory

            if path in pr.get("committed", []):
                outcome, summary = "committed", f"{ctx['fix_type']} fix committed in {pr.get('pr_url')}"
            elif path in reasons:
                outcome, summary = "rejected", f"{ctx['fix_type']} fix rejected: {reasons[path]}"
            elif pr.get("status") == "dry_run":
                outcome, summary = "dry_run", f"{ctx['fix_type']} fix generated in a dry run"
            else:
                outcome, summary = "error", f"{ctx['fix_type']} fix not submitted: {pr.get('message', 'unknown')}"
            error = check_failures.get(path) or (reasons[path] if outcome == "rejected" else "")

            for finding in ctx["findings"]:
                save_fix(
                    fingerprint   = make_fingerprint(finding),
                    file          = path,
                    finding_type  = finding.get("finding_type", "unknown"),
                    rule_id       = finding.get("identifiers", {}).get("rule_id", "unknown"),
                    run_id        = RUN_ID,
                    outcome       = outcome,
                    fix_summary   = summary,
                    fixed_content = final_content.get(path, f["content"]),
                    error         = error,
                )
    print(f"[memory] Saved fix history for run {RUN_ID}")


# ===========================================================================
# SECTION 5: MAIN
# ===========================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="ASVA Fix Agent (Stage B) — fix candidates and GitHub PRs."
    )
    parser.add_argument(
        "--batch-dir",
        default="../fix_batches",
        metavar="DIR",
        help="Directory containing batch JSON files. Default: ../fix_batches"
    )
    parser.add_argument(
        "--batch",
        action="append",
        default=[],
        metavar="FILE",
        help="Specific batch file(s) to process. Repeatable. Default: all in --batch-dir"
    )
    parser.add_argument(
        "--repo-dir",
        default=".",
        metavar="DIR",
        help="Path to the repo working tree. Default: ."
    )
    parser.add_argument(
        "--base-branch",
        default=None,
        metavar="BRANCH",
        help=f"Base branch for PRs. Default: {config.GITHUB_BASE_BRANCH}"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Generate candidates without creating branches, commits, or PRs."
    )
    parser.add_argument(
        "--output-dir",
        default="../dry_run_output",
        metavar="DIR",
        help="Folder for candidate files during dry run. Default: ../dry_run_output"
    )
    parser.add_argument(
        "--no-secrets-gate",
        action="store_true",
        help="Skip the gitleaks secrets gate (for local testing only)."
    )
    parser.add_argument(
        "--no-regression-gate",
        action="store_true",
        help="Skip the pre-commit regression gate (test_fn) — commits fixes unverified. For local testing only."
    )
    parser.add_argument(
        "--no-repo-context",
        action="store_true",
        help="Turn off all repo-aware features (importers/call sites in fix prompts, "
             "breaking-upgrade review notes). Same as ASVA_REPO_CONTEXT=0. "
             "For with/without comparisons."
    )
    parser.add_argument(
        "--no-rag",
        action="store_true",
        help="Do not ask the RAG (3.3), even when ASVA_RAG_URL is set. For with/without comparisons."
    )
    parser.add_argument(
        "--passes",
        type=int,
        choices=(1, 2),
        default=1,
        help="1 (default): one pass, with additional context unless --no-repo-context. "
             "2: local pass with NO additional context, then an integration pass on its "
             "result WITH the additional context (3.6)."
    )
    parser.add_argument(
        "--files-per-prompt",
        type=int,
        default=1,
        metavar="N",
        help="Most code_change files sent together in one prompt (default 1, as in ITP1). "
             "A limit, not a target: a batch with fewer files sends fewer. "
             "Use 10 or 20 for the 3.6 attention-dilution experiments."
    )
    parser.add_argument(
        "--output-json",
        default=None,
        metavar="PATH",
        help="Write the PRs opened this run as JSON ([{batch_id, branch, pr_url, status}, "
             "...]) to PATH, for CI to hand off to a downstream pre-merge check job."
    )

    parser.add_argument(
        "--import-map-dir",
        default=None,
        metavar="DIR",
        help="Write an interactive HTML import map of the target app to DIR for each batch "
             "that builds the repo-context index. Default: $ASVA_IMPORT_MAP_DIR, or "
             "<output-dir>/import_maps on a dry run; otherwise off."
    )

    parser.add_argument(
        "--findings-json",
        default=None,
        metavar="FILE",
        help="ranked_unified_findings.json, for trying a newer base image (ASVA_BASE_IMAGE_FIX=1)."
    )
    parser.add_argument(
        "--container-file",
        default=None,
        metavar="FILE",
        help="The app's container file, for trying a newer base image (ASVA_BASE_IMAGE_FIX=1)."
    )
    args      = parser.parse_args()
    batch_dir = Path(args.batch_dir)
    repo_dir  = args.repo_dir
    base      = args.base_branch or config.GITHUB_BASE_BRANCH

    print("=" * 60)
    print("ASVA Fix Agent (Stage B)")
    print("=" * 60)
    print(f"  batch dir   : {batch_dir}")
    print(f"  repo dir    : {repo_dir}")
    print(f"  base branch : {base}")
    print(f"  dry run     : {args.dry_run}")
    print(f"  secrets gate: {'OFF' if args.no_secrets_gate else 'ON'}")
    print(f"  regression gate: {'OFF' if args.no_regression_gate else 'ON'}")
    print(f"  SCA mode    : {os.environ.get('ASVA_SCA_FIX_MODE', 'llm')}")
    use_repo_context = repo_context_enabled(not args.no_repo_context)
    print(f"  repo context: {'ON' if use_repo_context else 'OFF'}")
    if args.no_rag:
        os.environ.pop("ASVA_RAG_URL", None)
    print(f"  RAG         : {'ON' if rag_client.enabled() else 'OFF'}")
    print(f"  test first  : {'ON' if test_first.enabled() else 'OFF'}")
    print(f"  misuse fix  : {'ON' if test_first.enabled() and test_first.misuse_fix_enabled() else 'OFF'}")
    print(f"  passes      : {args.passes}"
          + (" (local without context, then integration with context)" if args.passes == 2 else ""))
    print(f"  files/prompt: {args.files_per_prompt} (logic batches: all files in one prompt)")
    import_map_dir = (args.import_map_dir or os.environ.get("ASVA_IMPORT_MAP_DIR", "").strip()
                      or (str(Path(args.output_dir) / "import_maps") if args.dry_run else None))
    if not use_repo_context:
        import_map_dir = None   # the map is drawn from the repo-context index
    print(f"  import map  : {import_map_dir or 'OFF'}")

    # A newer OS release may fix what triage left out: its batch goes in with the others.
    if test_first.enabled():
        base_image.prepare(batch_dir, repo_dir, args.findings_json, args.container_file)

    # Collect batch files
    if args.batch:
        batch_paths = [Path(p) for p in args.batch]
    else:
        batch_paths = sorted(batch_dir.glob("*.json"))

    if not batch_paths:
        print(f"\n[ERROR] No batch files found in {batch_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"\n  Found {len(batch_paths)} batch file(s):")
    for p in batch_paths:
        print(f"    {p.name}")

    # Fail fast if the LLM backend isn't reachable, before spending any time on batches
    # (an outage or exhausted quota fails every call the same way, so there's no point
    # discovering that one file at a time).
    print("\n" + "=" * 60)
    print("Checking LLM connectivity")
    print("=" * 60)
    try:
        call_llm("Reply with the single word: ok")
    except LLMUnavailableError as e:
        print(f"\n[FATAL] {e}", file=sys.stderr)
        print("[FATAL] Aborting before processing any batches — no fixes attempted, "
              "nothing to submit.", file=sys.stderr)
        sys.exit(2)
    print("  OK")

    init_db()

    # Generate candidates using each batch's configured method.
    print("\n" + "=" * 60)
    print("Generating fix candidates")
    print("=" * 60)

    cycle = []
    try:
        for batch_path in batch_paths:
            entry = process_batch(
                batch_path, repo_dir,
                use_repo_context=use_repo_context,
                passes=args.passes,
                files_per_prompt=args.files_per_prompt,
                import_map_dir=import_map_dir,
            )
            entry = test_first.run(
                entry, repo_dir, sca_upgrade_map,
                make_refix=lambda e: make_refix_fn([e], repo_dir, use_repo_context=use_repo_context),
                notes=lambda path, original, upgrades: upgrade_review_notes(
                    original, upgrades, load_repo_index(repo_dir), manifest=path) if use_repo_context else [],
                logic_fix=lambda files, detail: get_llm_logic_fix(
                    files, detail, misuse_fix_contexts(list(files), repo_dir, use_repo_context)),
                findings_path=args.findings_json,
            )
            save_for_pr_check(batch_path, entry)
            same_major = entry.pop("same_major", None)
            if entry["files"] or entry.get("generation"):
                cycle.append(entry)
            else:
                print(f"  [SKIP] {batch_path.name} — no files to fix")
            if same_major:  # its own batch, as the pipeline's later stages read one per PR
                (batch_dir / f"{same_major['batch']['batch_id']}.json").write_text(
                    json.dumps(same_major["batch"], indent=2), encoding="utf-8")
                cycle.append(same_major)
    except LLMUnavailableError as e:
        print(f"\n[FATAL] {e}", file=sys.stderr)
        print("[FATAL] Aborting — no batches were submitted.", file=sys.stderr)
        sys.exit(2)

    if not cycle:
        print("\n[INFO] No fixes generated. Nothing to submit.")
        sys.exit(0)

    if args.dry_run:
        output_dir = Path(args.output_dir)
        print(f"\n[DRY RUN] Fixes generated — writing to {output_dir}")
        for entry in cycle:
            batch_id = entry["batch"]["batch_id"]
            print(f"\n  Batch: {batch_id}")
            for f in entry["files"]:
                # mirror the original folder structure under output_dir/batch_id/
                out_path = output_dir / batch_id / f["path"]
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(f["content"], encoding="utf-8")
                print(f"    wrote: {out_path}  ({len(f['content'])} chars)")
            # The state after each pass, in the same layout, so every pass can be evaluated
            # on its own: output_dir/after_pass1/<batch_id>/..., output_dir/after_pass2/...
            for pass_name, contents in (entry.get("passes") or {}).items():
                for path, content in contents.items():
                    pass_path = output_dir / pass_name / batch_id / path
                    pass_path.parent.mkdir(parents=True, exist_ok=True)
                    pass_path.write_text(content, encoding="utf-8")
                print(f"    {pass_name}: {len(contents)} file(s) -> {output_dir / pass_name / batch_id}")
            if entry["batch"].get("rag_pr_text"):
                rag_path = output_dir / batch_id / "_pr_text_from_rag.md"
                rag_path.parent.mkdir(parents=True, exist_ok=True)
                rag_path.write_text(entry["batch"]["rag_pr_text"], encoding="utf-8")
                print(f"    wrote: {rag_path}")
            # What the PR description's "Check before merging" section would say
            for path, notes in (entry["batch"].get("review_notes") or {}).items():
                for note in notes:
                    print(f"    review note ({path}): {note}")
        save_cycle_to_memory(
            cycle, [{"batch_id": e["batch"]["batch_id"], "status": "dry_run"} for e in cycle], {}
        )
        print(f"\n[DRY RUN] No git operations performed.")
        print(f"[DRY RUN] Inspect fixes in: {output_dir.resolve()}")
        sys.exit(0)

    # Submit to GitHub — git_gh_ops handles branch, commit, push, PR
    print("\n" + "=" * 60)
    print("Submitting to GitHub")
    print("=" * 60)

    # test_fn only receives the fix's repo-relative path, but the gate needs repo_dir to
    # find the file on disk — close over it here, at the wiring point.
    # refix_fn only makes sense alongside a gate that can reject a fix, so both share the
    # flag; without it, git_gh_ops gives a rejected fix exactly one attempt.
    test_fn = None
    refix_fn = None
    if not args.no_regression_gate:
        test_fn = lambda path: regression_gate.check(path, repo_dir=repo_dir)
        refix_fn = make_refix_fn(cycle, repo_dir, use_repo_context=use_repo_context)

    result = submit_scan_cycle(
        cycle,
        base_branch=base,
        repo_dir=repo_dir,
        run_secret_scan=not args.no_secrets_gate,
        test_fn=test_fn,
        refix_fn=refix_fn,
        max_attempts=int(os.environ.get("ASVA_FIX_MAX_ATTEMPTS", "3")),
    )
    final_content = refix_fn.last_attempt if refix_fn else {}
    save_cycle_to_memory(cycle, result.get("prs", []), final_content)

    if args.output_json:
        output_json_path = Path(args.output_json)
        output_json_path.parent.mkdir(parents=True, exist_ok=True)
        output_json_path.write_text(json.dumps([
            {
                "batch_id": pr.get("batch_id"),
                "branch": pr.get("branch"),
                "pr_url": pr.get("pr_url"),
                "status": pr.get("status"),
                "failed": pr.get("failed", []),
                "blocked": pr.get("blocked", []),
                "secrets_already_there": pr.get("secrets_already_there", {}),
                "message": pr.get("message", ""),
                **({"generation": pr["generation"]} if "generation" in pr else {}),
            }
            for pr in result.get("prs", [])
        ], indent=2), encoding="utf-8")
        print(f"\n[OUTPUT] PR list written to {output_json_path}")

    # Print results
    print(f"\n{result['message']}")
    print()
    for pr in result.get("prs", []):
        status = pr["status"]
        bid    = pr["batch_id"]
        url    = pr.get("pr_url", "")
        print(f"    {pr['message']}")
        print(f"  [{bid}] {status}" + (f" -> {url}" if url else ""))

        for b in pr.get("blocked", []):
            print(f"      blocked  : {b['path']} ({b['reason']})")
        for path, where in pr.get("secrets_already_there", {}).items():
            print(f"      already there: {path}: {where}")
        for f in pr.get("failed", []):
            print(f"      failed   : {f['path']} ({f['reason']})")

    print()
    incomplete = any(c.get("generation", {}).get("status") in ("partial", "error") for c in cycle)
    sys.exit(0 if result["status"] == "prs_opened" and not incomplete else 1)


if __name__ == "__main__":
    main()
