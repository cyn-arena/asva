"""Unit tests for agent/agent_loop.py — call_llm mocked via the fake_llm fixture,
never a real Ollama endpoint."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent.agent_loop import (
    build_fix_prompt,
    build_logic_change_prompt,
    build_refix_prompt,
    get_llm_fix,
    get_llm_logic_fix,
    is_breaking_upgrade,
    make_prompt_groups,
    make_refix_fn,
    parse_logic_change_response,
    process_batch,
    upgrade_review_notes,
)
from agent import rag_client
from agent.fix_context import FixContext
from gitops import config
from llm.llm_client import LLMUnavailableError

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _node_app_by_default(monkeypatch):
    """Prompts depend on the target app's language. Pin the default (no app prefix, no
    ASVA_APP_LANGUAGE -> Node.js, the ITP1 prompts) so a developer's .env pointing at
    another app doesn't change these tests; Python tests opt in explicitly."""
    monkeypatch.delenv("ASVA_APP_LANGUAGE", raising=False)
    monkeypatch.delenv("ASVA_RAG_URL", raising=False)
    monkeypatch.setattr(config, "FIX_PATH_PREFIX", "")


# --------------------------------------------------------------------------------------
# build_fix_prompt
# --------------------------------------------------------------------------------------

def test_build_fix_prompt_code_change_includes_findings_and_content():
    findings = [{
        "location": {"line": 32}, "title": "Code Injection",
        "description": "Unsanitized input flows into eval().",
        "identifiers": {"cwe": "CWE-94", "rule_id": "javascript/CodeInjection"},
    }]
    content = "const x = eval(req.body.expr);"
    prompt = build_fix_prompt("app/routes/contributions.js", content, findings, "code_change")
    assert "app/routes/contributions.js" in prompt
    assert content in prompt
    assert "CWE-94" in prompt
    assert "Code Injection" in prompt


def test_build_fix_prompt_version_upgrade_sca_includes_package_and_target_version():
    findings = [{
        "finding_type": "sca",
        "location": {"package": "marked@0.3.5"},
        "remediation": {"upgrade_to": "marked@0.3.6"},
        "identifiers": {"cve": "CVE-2016-10531"},
        "title": "XSS in marked",
    }]
    content = '{"dependencies": {"marked": "0.3.5"}}'
    prompt = build_fix_prompt("package.json", content, findings, "version_upgrade")
    assert "marked" in prompt
    assert "0.3.6" in prompt
    assert content in prompt


def test_python_source_prompt_uses_python_context():
    findings = [{
        "location": {"line": 10}, "title": "Code Injection",
        "description": "Untrusted input reaches eval.",
        "identifiers": {"cwe": "CWE-94", "rule_id": "python/CodeInjection"},
    }]
    prompt = build_fix_prompt("introduction/views.py", "eval(value)", findings, "code_change")
    assert "Python application" in prompt
    assert "Node.js application" not in prompt
    assert "python/CodeInjection" in prompt


def test_python_dependency_prompt_preserves_requirements_format():
    findings = [{
        "finding_type": "sca",
        "location": {"package": "Django@4.2"},
        "remediation": {"upgrade_to": "Django@4.2.25"},
        "identifiers": {"cve": "CVE-example"},
        "title": "Django vulnerability",
    }]
    content = "# Application dependencies\nDjango==4.2\nrequests==2.28.2\n"
    prompt = build_fix_prompt("requirements.txt", content, findings, "version_upgrade")
    assert "Python dependencies" in prompt
    assert "4.2.25" in prompt
    assert content in prompt
    assert "environment markers" in prompt
    assert "npm dependencies" not in prompt


def _container_finding(file: str, image_name: str | None, image_tag: str | None) -> dict:
    return {
        "finding_type": "container",
        "location": {"file": file, "package": "glibc@2.23",
                     "image_name": image_name, "image_tag": image_tag},
        "remediation": {"upgrade_to": "glibc@2.24"},
        "identifiers": {"cve": "CVE-2022-23219"},
        "title": "Buffer overflow in glibc",
    }


def test_build_fix_prompt_version_upgrade_container_includes_image_name():
    # triage sets location.file to the file to edit, so the image must come from its own fields
    findings = [_container_finding("docker-compose.yml", "mongo", "4.4")]
    content = "services:\n  mongo:\n    image: mongo:4.4\n"
    prompt = build_fix_prompt("docker-compose.yml", content, findings, "version_upgrade")
    assert 'identified in the scan:\n[\n  "mongo:4.4"\n]' in prompt
    assert content in prompt


def test_container_prompt_keeps_the_major_version_and_never_asks_for_latest():
    prompt = build_fix_prompt("docker-compose.yml", "image: mongo:4.4\n",
                              [_container_finding("docker-compose.yml", "mongo", "4.4")], "version_upgrade")
    assert "latest stable version" not in prompt
    assert "keep its current major version" in prompt
    assert "Never use the `latest` tag" in prompt
    assert "return the file unchanged" in prompt  # no tag within the major: no change, not a jump


@pytest.mark.parametrize("file_path", ["requirements.txt", "package.json"])
def test_dependency_prompts_forbid_unlisted_major_versions(file_path):
    findings = [{
        "finding_type": "sca", "title": "t", "identifiers": {"cve": "CVE-1"},
        "location": {"package": "pkg@1.0.0"}, "remediation": {"upgrade_to": "pkg@1.0.1"},
    }]
    prompt = build_fix_prompt(file_path, "content", findings, "version_upgrade")
    assert "never move a package to a new major version unless that version is listed" in prompt


def test_build_fix_prompt_version_upgrade_container_works_for_a_dockerfile():
    findings = [_container_finding("Dockerfile", "asva-pygoat", "scan")]
    content = "FROM python:3.9-slim\nCOPY . /app\n"
    prompt = build_fix_prompt("Dockerfile", content, findings, "version_upgrade")
    assert "File: Dockerfile" in prompt
    assert '"asva-pygoat:scan"' in prompt
    assert "docker-compose.yml" not in prompt
    assert content in prompt


def test_build_fix_prompt_version_upgrade_container_lists_each_image_once():
    findings = [
        _container_finding("docker-compose.yml", "redis", None),
        _container_finding("docker-compose.yml", "mongo", "4.4"),
        _container_finding("docker-compose.yml", "mongo", "4.4"),
        _container_finding("docker-compose.yml", None, None),   # batch without image fields
    ]
    prompt = build_fix_prompt("docker-compose.yml", "services: {}", findings, "version_upgrade")
    assert 'identified in the scan:\n[\n  "mongo:4.4",\n  "redis"\n]' in prompt


def test_build_fix_prompt_config_change_fallback_includes_findings_and_content():
    findings = [{"title": "Insecure config", "description": "cookie.secure is disabled"}]
    content = "app.use(session({cookie: {secure: false}}))"
    prompt = build_fix_prompt("server.js", content, findings, "config_change")
    assert "Insecure config" in prompt
    assert content in prompt


def test_build_fix_prompt_logic_change_single_file_fallback_includes_detail():
    findings = [{"description": "user1 can see user2's data"}]
    content = "const { userId } = req.params;"
    prompt = build_fix_prompt("app/routes/allocations.js", content, findings, "logic_change")
    assert "user1 can see user2's data" in prompt
    assert content in prompt


# --------------------------------------------------------------------------------------
# get_llm_fix — markdown fence stripping
# --------------------------------------------------------------------------------------

def test_get_llm_fix_strips_markdown_fences(fake_llm):
    fake_llm.response = "```js\nconst x = 1;\n```"
    result = get_llm_fix("app/x.js", "old content", [], "code_change")
    assert result == "const x = 1;"


def test_get_llm_fix_passthrough_without_fences(fake_llm):
    fake_llm.response = "const x = 1;"
    result = get_llm_fix("app/x.js", "old content", [], "code_change")
    assert result == "const x = 1;"


# --------------------------------------------------------------------------------------
# process_batch
# --------------------------------------------------------------------------------------

def _write_batch(tmp_path: Path, file_path: str, fix_type: str = "code_change") -> Path:
    batch = {
        "batch_id": "asva_sast_test_1",
        "batch_type": "sast",
        "repo_name": "asva",
        "commit_sha": "deadbeef",
        "scan_run_id": "run1",
        "total_files": 1,
        "total_findings": 1,
        "files_to_fix": [{
            "file": file_path,
            "fix_type": fix_type,
            "finding_type": "sast",
            "finding_count": 1,
            "findings": [{
                "location": {"line": 1}, "title": "t", "description": "d",
                "identifiers": {"cwe": "CWE-1", "rule_id": "r1"},
            }],
        }],
    }
    batch_path = tmp_path / "batch.json"
    batch_path.write_text(json.dumps(batch), encoding="utf-8")
    return batch_path


@pytest.fixture
def repo_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "FIX_PATH_PREFIX", "")
    d = tmp_path / "repo" / "app"
    d.mkdir(parents=True)
    (d / "x.js").write_text("old content", encoding="utf-8")
    return tmp_path / "repo"


def test_process_batch_valid_fix_produces_cycle_entry(tmp_path, repo_dir, fake_llm):
    fake_llm.response = "fixed content"
    batch_path = _write_batch(tmp_path, "app/x.js")

    entry = process_batch(batch_path, repo_dir=str(repo_dir))

    assert entry["files"] == [{"path": "app/x.js", "content": "fixed content"}]
    assert entry["batch"]["batch_id"] == "asva_sast_test_1"


def test_process_batch_empty_llm_output_skips_file(tmp_path, repo_dir, fake_llm):
    fake_llm.response = "   "
    batch_path = _write_batch(tmp_path, "app/x.js")

    entry = process_batch(batch_path, repo_dir=str(repo_dir))

    assert entry["files"] == []
    assert entry["generation"]["status"] == "error"
    assert entry["generation"]["files"] == [{"path": "app/x.js", "status": "empty_or_truncated"}]


def test_process_batch_llm_unavailable_aborts_instead_of_skipping(tmp_path, repo_dir, fake_llm):
    """An LLM outage/quota failure is fatal for the whole run, not a per-file skip --
    a backend that can't respond will fail every subsequent call the same way, so there's
    no point working through the remaining files first."""
    fake_llm.side_effect = LLMUnavailableError("Ollama call failed: 429 rate limited")
    batch_path = _write_batch(tmp_path, "app/x.js")

    with pytest.raises(LLMUnavailableError):
        process_batch(batch_path, repo_dir=str(repo_dir))


def test_process_batch_missing_file_on_disk_is_skipped(tmp_path, repo_dir, fake_llm):
    fake_llm.response = "fixed content"
    batch_path = _write_batch(tmp_path, "app/does_not_exist.js")

    entry = process_batch(batch_path, repo_dir=str(repo_dir))

    assert entry["files"] == []
    assert fake_llm.calls == []  # never even asked the LLM for a file that isn't on disk
    assert entry["generation"]["files"] == [{"path": "app/does_not_exist.js", "status": "missing_source"}]


def test_partial_llm_batch_reports_each_requested_file(tmp_path, repo_dir, fake_llm):
    batch_path = _write_batch(tmp_path, "app/x.js")
    batch = json.loads(batch_path.read_text())
    missing = {**batch["files_to_fix"][0], "file": "app/missing.js"}
    batch["files_to_fix"].append(missing)
    batch["total_files"] = 2
    batch_path.write_text(json.dumps(batch))
    fake_llm.response = "fixed"
    entry = process_batch(batch_path, repo_dir=str(repo_dir))
    assert entry["generation"]["status"] == "partial"
    assert entry["generation"]["message"] == "Generated 1/2 requested files"
    assert entry["generation"]["files"] == [
        {"path": "app/x.js", "status": "generated"}, {"path": "app/missing.js", "status": "missing_source"}]


# --------------------------------------------------------------------------------------
# logic_change -- multi-file prompt / response parsing
# --------------------------------------------------------------------------------------

def test_build_logic_change_prompt_includes_all_files_and_detail():
    file_contents = {
        "app/routes/allocations.js": "route content",
        "app/data/allocations-dao.js": "dao content",
    }
    prompt = build_logic_change_prompt(file_contents, "user1 can see user2's data")
    assert "user1 can see user2's data" in prompt
    assert "route content" in prompt
    assert "dao content" in prompt
    assert "===FILE: app/routes/allocations.js===" in prompt
    assert "===FILE: app/data/allocations-dao.js===" in prompt


def test_parse_logic_change_response_extracts_each_file():
    response = (
        "===FILE: app/routes/allocations.js===\n"
        "fixed route content\n"
        "===END FILE===\n"
        "===FILE: app/data/allocations-dao.js===\n"
        "fixed dao content\n"
        "===END FILE===\n"
    )
    result = parse_logic_change_response(
        response, ["app/routes/allocations.js", "app/data/allocations-dao.js"]
    )
    assert result == {
        "app/routes/allocations.js": "fixed route content",
        "app/data/allocations-dao.js": "fixed dao content",
    }


def test_parse_logic_change_response_ignores_unexpected_paths():
    response = "===FILE: not/expected.js===\ncontent\n===END FILE===\n"
    result = parse_logic_change_response(response, ["app/routes/allocations.js"])
    assert result == {}


def test_parse_logic_change_response_strips_markdown_fence_per_file():
    response = "===FILE: app/x.js===\n```js\nconst x = 1;\n```\n===END FILE===\n"
    result = parse_logic_change_response(response, ["app/x.js"])
    assert result == {"app/x.js": "const x = 1;"}


def test_a_misuse_prompt_shows_each_files_repo_context_and_is_unchanged_without_any():
    files = {"app/x.js": "old x", "app/y.js": "old y"}
    plain = agent_loop.build_logic_change_prompt(files, "detail")
    assert agent_loop.build_logic_change_prompt(files, "detail", {"app/x.js": None}) == plain
    with_context = agent_loop.build_logic_change_prompt(files, "detail", {"app/x.js": FixContext(repo="session.js calls this")})
    assert "session.js calls this" in with_context and "session.js calls this" not in plain
    assert with_context.index("session.js calls this") < with_context.index("old x") < with_context.index("old y")


def test_misuse_fix_contexts_use_the_repo_index(monkeypatch):
    monkeypatch.setattr(agent_loop, "load_repo_index", lambda repo_dir: "index")
    monkeypatch.setattr(agent_loop, "file_fix_context", lambda path, fix_type, index: FixContext(repo=f"{path} {fix_type} {index}"))
    assert agent_loop.misuse_fix_contexts(["a.js"], ".", None) == {"a.js": FixContext(repo="a.js logic_change index")}


def test_misuse_fix_contexts_respect_the_off_switch(monkeypatch):
    monkeypatch.setattr(agent_loop, "load_repo_index", lambda repo_dir: pytest.fail("built the index"))
    assert agent_loop.misuse_fix_contexts(["a.js"], ".", False) == {}


def test_a_problem_with_repo_context_does_not_stop_a_misuse_fix(monkeypatch):
    def broken(repo_dir):
        raise RuntimeError("boom")
    monkeypatch.setattr(agent_loop, "load_repo_index", broken)
    assert agent_loop.misuse_fix_contexts(["a.js"], ".", None) == {}


def test_get_llm_logic_fix_calls_llm_once_and_parses_all_files(fake_llm):
    fake_llm.response = (
        "===FILE: app/x.js===\nfixed x\n===END FILE===\n"
        "===FILE: app/y.js===\nfixed y\n===END FILE===\n"
    )
    result = get_llm_logic_fix({"app/x.js": "old x", "app/y.js": "old y"}, "detail")
    assert result == {"app/x.js": "fixed x", "app/y.js": "fixed y"}
    assert len(fake_llm.calls) == 1


# --------------------------------------------------------------------------------------
# refix_fn -- the retry callback for fixes that fail the validity gate
# --------------------------------------------------------------------------------------

def _cycle_entry(
    file_path: str = "app/x.js",
    fix_type: str = "code_change",
    batch_type: str = "sast",
    content: str = "first fix",
) -> dict:
    return {
        "batch": {
            "batch_id": "b1",
            "batch_type": batch_type,
            "files_to_fix": [{
                "file": file_path,
                "fix_type": fix_type,
                "findings": [{
                    "location": {"line": 1}, "title": "t", "description": "d",
                    "identifiers": {"cwe": "CWE-1", "rule_id": "r1"},
                }],
            }],
        },
        "files": [{"path": file_path, "content": content}],
    }


def test_build_refix_prompt_includes_base_prompt_and_rejected_attempt():
    findings = [{
        "location": {"line": 1}, "title": "Code Injection", "description": "d",
        "identifiers": {"cwe": "CWE-94", "rule_id": "r1"},
    }]
    prompt = build_refix_prompt(
        "app/x.js", "original content", findings, "code_change",
        failed_content="broken fix", attempt=1,
    )
    assert "original content" in prompt   # the base fix prompt is still all there
    assert "Code Injection" in prompt
    assert "broken fix" in prompt         # ...plus the rejected attempt
    assert "rejected" in prompt.lower()
    assert "syntactically valid" in prompt


def test_a_retry_after_failed_tests_says_what_failed_and_lets_an_innocent_file_come_back_unchanged():
    findings = [{"location": {"line": 1}, "title": "Open Redirect", "description": "d",
                 "identifiers": {"cwe": "CWE-601", "rule_id": "r1"}}]
    prompt = build_refix_prompt("app/x.js", "original", findings, "code_change", failed_content="my fix", attempt=1,
                                reason="the app's tests failed: FAILED test_link expected khanacademy")
    assert "FAILED test_link expected khanacademy" in prompt and "my fix" in prompt
    assert "If this attempt is not what caused the failure, return it unchanged" in prompt
    assert "syntax/validity" not in prompt


def test_make_refix_fn_passes_the_reason_to_the_prompt(repo_dir, fake_llm):
    fake_llm.response = "second fix"
    refix = make_refix_fn([_cycle_entry()], str(repo_dir))
    assert refix("app/x.js", [], 1, reason="the app did not start: boom") == "second fix"
    assert "the app did not start: boom" in fake_llm.calls[0]


def test_make_refix_fn_reasks_llm_with_original_and_failed_content(repo_dir, fake_llm):
    fake_llm.response = "second fix"
    refix = make_refix_fn([_cycle_entry()], str(repo_dir))

    out = refix("app/x.js", [], 1)

    assert out == "second fix"
    # the retry prompt is built from the on-disk original (post-revert) and shows the
    # first rejected fix so the LLM doesn't repeat it
    assert "old content" in fake_llm.calls[0]
    assert "first fix" in fake_llm.calls[0]


def test_make_refix_fn_second_retry_shows_latest_rejected_attempt(repo_dir, fake_llm):
    responses = iter(["second fix", "third fix"])
    fake_llm.side_effect = lambda prompt: next(responses)
    refix = make_refix_fn([_cycle_entry()], str(repo_dir))

    refix("app/x.js", [], 1)
    out = refix("app/x.js", [], 2)

    assert out == "third fix"
    assert "second fix" in fake_llm.calls[1]  # attempt 2's prompt shows attempt 1's reject


def test_make_refix_fn_strips_markdown_fences(repo_dir, fake_llm):
    fake_llm.response = "```js\nsecond fix\n```"
    refix = make_refix_fn([_cycle_entry()], str(repo_dir))
    assert refix("app/x.js", [], 1) == "second fix"


def test_make_refix_fn_gives_up_on_logic_batches(repo_dir, fake_llm):
    """A logic batch's fixes are coordinated across files in one LLM call -- regenerating
    one file in isolation could desync it from the others, so refix declines."""
    refix = make_refix_fn(
        [_cycle_entry(batch_type="logic", fix_type="logic_change")], str(repo_dir)
    )
    assert refix("app/x.js", [], 1) is None
    assert fake_llm.calls == []


def test_make_refix_fn_gives_up_on_unknown_path(repo_dir, fake_llm):
    refix = make_refix_fn([_cycle_entry()], str(repo_dir))
    assert refix("app/not_in_cycle.js", [], 1) is None
    assert fake_llm.calls == []


def test_make_refix_fn_gives_up_on_missing_file(repo_dir, fake_llm):
    refix = make_refix_fn([_cycle_entry(file_path="app/gone.js")], str(repo_dir))
    assert refix("app/gone.js", [], 1) is None
    assert fake_llm.calls == []


def test_make_refix_fn_llm_outage_gives_up_instead_of_raising(repo_dir, fake_llm):
    """Unlike the initial fix pass (where an outage aborts the run before anything is
    attempted), an outage mid-retry fails only that file -- other files' committed fixes
    and the PR must still go out."""
    fake_llm.side_effect = LLMUnavailableError("Ollama call failed: 429 rate limited")
    refix = make_refix_fn([_cycle_entry()], str(repo_dir))
    assert refix("app/x.js", [], 1) is None


# --------------------------------------------------------------------------------------
# process_batch -- logic batches: all files in one prompt, ITP1 prompt in pass 1
# --------------------------------------------------------------------------------------

def _write_logic_batch(tmp_path: Path, files: list[str]) -> Path:
    batch = {
        "batch_id": "asva_logic_test_case",
        "batch_type": "logic",
        "repo_name": "asva",
        "commit_sha": "deadbeef",
        "total_files": len(files),
        "total_findings": len(files),
        "files_to_fix": [
            {
                "file": f,
                "fix_type": "logic_change",
                "finding_type": "logic",
                "finding_count": 1,
                "findings": [{"description": "shared detail"}],
            }
            for f in files
        ],
    }
    batch_path = tmp_path / "logic_batch.json"
    batch_path.write_text(json.dumps(batch), encoding="utf-8")
    return batch_path


def test_logic_batch_baseline_sends_exactly_the_itp1_prompt(tmp_path, repo_dir, fake_llm):
    (repo_dir / "app" / "y.js").write_text("old y", encoding="utf-8")
    fake_llm.response = "===FILE: app/x.js===\nfixed x\n===END FILE===\n"
    batch_path = _write_logic_batch(tmp_path, ["app/x.js", "app/y.js"])

    process_batch(batch_path, repo_dir=str(repo_dir), use_repo_context=False)

    assert fake_llm.calls == [build_logic_change_prompt(
        {"app/x.js": "old content", "app/y.js": "old y"}, "shared detail"
    )]


def test_logic_batch_makes_one_llm_call_for_all_files(tmp_path, repo_dir, fake_llm):
    (repo_dir / "app" / "y.js").write_text("old y", encoding="utf-8")
    fake_llm.response = (
        "===FILE: app/x.js===\nfixed x\n===END FILE===\n"
        "===FILE: app/y.js===\nfixed y\n===END FILE===\n"
    )
    batch_path = _write_logic_batch(tmp_path, ["app/x.js", "app/y.js"])

    entry = process_batch(batch_path, repo_dir=str(repo_dir))

    assert len(fake_llm.calls) == 1
    assert {"path": "app/x.js", "content": "fixed x"} in entry["files"]
    assert {"path": "app/y.js", "content": "fixed y"} in entry["files"]


def test_logic_batch_skips_files_llm_didnt_return(tmp_path, repo_dir, fake_llm):
    (repo_dir / "app" / "y.js").write_text("old y", encoding="utf-8")
    fake_llm.response = "===FILE: app/x.js===\nfixed x\n===END FILE===\n"
    batch_path = _write_logic_batch(tmp_path, ["app/x.js", "app/y.js"])

    entry = process_batch(batch_path, repo_dir=str(repo_dir))

    assert entry["files"] == [{"path": "app/x.js", "content": "fixed x"}]


def test_process_batch_logic_type_llm_unavailable_aborts_instead_of_skipping(tmp_path, repo_dir, fake_llm):
    fake_llm.side_effect = LLMUnavailableError("Ollama call failed: 429 rate limited")
    batch_path = _write_logic_batch(tmp_path, ["app/x.js"])

    with pytest.raises(LLMUnavailableError):
        process_batch(batch_path, repo_dir=str(repo_dir))


def test_process_batch_logic_type_no_files_on_disk_yields_no_files(tmp_path, repo_dir, fake_llm):
    fake_llm.response = "===FILE: app/missing.js===\nfixed\n===END FILE===\n"
    batch_path = _write_logic_batch(tmp_path, ["app/missing.js"])

    entry = process_batch(batch_path, repo_dir=str(repo_dir))

    assert entry["files"] == []
    assert fake_llm.calls == []  # never asked the LLM when nothing was on disk


# --------------------------------------------------------------------------------------
# 3.6 local and integration passes (--passes 2)
# --------------------------------------------------------------------------------------

_SECOND_PASS_MARKER = "second (integration) pass"


@pytest.fixture
def linked(repo_dir):
    """app/y.js imports and calls app/x.js, so x.js has repo context; app/z.js stands alone."""
    (repo_dir / "app" / "y.js").write_text(
        'const X = require("./x");\nX.run(req.body);\n', encoding="utf-8"
    )
    (repo_dir / "app" / "z.js").write_text("old z", encoding="utf-8")
    return repo_dir


def _per_pass_llm(pass1="pass1 fix", pass2="pass2 fix"):
    """Reply by pass; a value may be an exception instance to raise instead."""
    def reply(prompt: str) -> str:
        value = pass2 if _SECOND_PASS_MARKER in prompt else pass1
        if isinstance(value, Exception):
            raise value
        return value
    return reply


def test_two_passes_local_without_context_then_integration_with_context(tmp_path, linked, fake_llm):
    fake_llm.side_effect = _per_pass_llm()
    batch_path = _write_batch(tmp_path, "app/x.js")

    entry = process_batch(batch_path, repo_dir=str(linked), passes=2)

    assert len(fake_llm.calls) == 2
    local, integration = fake_llm.calls
    # pass 1: the plain ITP1 prompt -- no additional context at all
    findings = json.loads(batch_path.read_text())["files_to_fix"][0]["findings"]
    assert local == build_fix_prompt("app/x.js", "old content", findings, "code_change")
    # pass 2: works on the pass-1 result, with the repo context
    assert _SECOND_PASS_MARKER in integration
    assert "Related code in the app" in integration
    assert "pass1 fix" in integration and "old content" not in integration
    assert entry["files"] == [{"path": "app/x.js", "content": "pass2 fix"}]
    assert entry["passes"] == {
        "after_pass1": {"app/x.js": "pass1 fix"},
        "after_pass2": {"app/x.js": "pass2 fix"},
    }


def test_integration_pass_skipped_when_there_is_no_additional_context(tmp_path, linked, fake_llm):
    fake_llm.side_effect = _per_pass_llm()
    entry = process_batch(_write_batch(tmp_path, "app/z.js"), repo_dir=str(linked), passes=2)

    assert len(fake_llm.calls) == 1   # z.js has no importers: pass 2 would only re-roll pass 1
    assert entry["passes"]["after_pass2"] == {"app/z.js": "pass1 fix"}


def test_integration_pass_skipped_when_repo_context_switched_off(tmp_path, linked, fake_llm):
    fake_llm.side_effect = _per_pass_llm()
    process_batch(_write_batch(tmp_path, "app/x.js"), repo_dir=str(linked),
                  passes=2, use_repo_context=False)
    assert len(fake_llm.calls) == 1


@pytest.mark.parametrize("pass2_reply", [
    LLMUnavailableError("Ollama call failed: 429"),   # outage in pass 2 does not abort
    "   ",                                            # empty pass-2 reply
])
def test_failed_integration_pass_keeps_the_pass1_result(tmp_path, linked, fake_llm, pass2_reply):
    fake_llm.side_effect = _per_pass_llm(pass2=pass2_reply)
    entry = process_batch(_write_batch(tmp_path, "app/x.js"), repo_dir=str(linked), passes=2)
    assert entry["files"] == [{"path": "app/x.js", "content": "pass1 fix"}]


def test_local_pass_outage_still_aborts_the_run(tmp_path, linked, fake_llm):
    fake_llm.side_effect = LLMUnavailableError("Ollama call failed: 429 rate limited")
    with pytest.raises(LLMUnavailableError):
        process_batch(_write_batch(tmp_path, "app/x.js"), repo_dir=str(linked), passes=2)


def test_empty_local_pass_lets_integration_start_from_the_original(tmp_path, linked, fake_llm):
    fake_llm.side_effect = _per_pass_llm(pass1="  ")
    entry = process_batch(_write_batch(tmp_path, "app/x.js"), repo_dir=str(linked), passes=2)

    assert "old content" in fake_llm.calls[1]
    assert entry["files"] == [{"path": "app/x.js", "content": "pass2 fix"}]
    assert entry["passes"]["after_pass1"] == {}


def test_one_pass_keeps_context_in_the_only_pass(tmp_path, linked, fake_llm):
    """Default (--passes 1): 3.1 context goes into the single pass, no second-pass note."""
    fake_llm.response = "fixed"
    entry = process_batch(_write_batch(tmp_path, "app/x.js"), repo_dir=str(linked))

    assert len(fake_llm.calls) == 1
    assert "Related code in the app" in fake_llm.calls[0]
    assert _SECOND_PASS_MARKER not in fake_llm.calls[0]
    assert set(entry["passes"]) == {"after_pass1"}


# --------------------------------------------------------------------------------------
# 3.6 batch size: --files-per-prompt
# --------------------------------------------------------------------------------------

def _write_code_batch(tmp_path: Path, files: list[str]) -> Path:
    entries = [{
        "file": path, "fix_type": "code_change", "finding_type": "sast", "finding_count": 1,
        "findings": [{
            "location": {"line": 1}, "title": f"t-{path}", "description": "d",
            "identifiers": {"cwe": "CWE-1", "rule_id": "r1"},
        }],
    } for path in files]
    batch = {"batch_id": "asva_exp_test", "batch_type": "sast", "total_files": len(entries),
             "total_findings": len(entries), "files_to_fix": entries}
    path = tmp_path / "exp.json"
    path.write_text(json.dumps(batch), encoding="utf-8")
    return path


def _file_blocks(*names: str, prefix: str = "fixed") -> str:
    return "".join(f"===FILE: app/{n}.js===\n{prefix} {n}\n===END FILE===\n" for n in names)


def test_files_per_prompt_1_is_one_prompt_per_file(tmp_path, linked, fake_llm):
    fake_llm.response = "fixed"
    batch = _write_code_batch(tmp_path, ["app/x.js", "app/y.js", "app/z.js"])
    process_batch(batch, repo_dir=str(linked))
    assert len(fake_llm.calls) == 3


def test_files_per_prompt_3_sends_every_file_and_finding_in_one_prompt(tmp_path, linked, fake_llm):
    fake_llm.response = _file_blocks("x", "y", "z")
    batch = _write_code_batch(tmp_path, ["app/x.js", "app/y.js", "app/z.js"])

    entry = process_batch(batch, repo_dir=str(linked), files_per_prompt=3)

    assert len(fake_llm.calls) == 1
    prompt = fake_llm.calls[0]
    assert "You are given 3 file(s)" in prompt
    for name in ("x", "y", "z"):
        assert f"t-app/{name}.js" in prompt                  # each file's own findings
        assert f"===FILE: app/{name}.js===" in prompt
    assert [f["content"] for f in entry["files"]] == ["fixed x", "fixed y", "fixed z"]


def test_files_per_prompt_2_chunks_three_files_into_two_prompts(tmp_path, linked, fake_llm):
    fake_llm.side_effect = lambda p: _file_blocks("x", "y") if "You are given 2" in p else "fixed z"
    batch = _write_code_batch(tmp_path, ["app/x.js", "app/y.js", "app/z.js"])

    entry = process_batch(batch, repo_dir=str(linked), files_per_prompt=2)

    assert len(fake_llm.calls) == 2
    assert [f["content"] for f in entry["files"]] == ["fixed x", "fixed y", "fixed z"]


def test_multi_file_two_passes_integration_sees_pass1_results_and_keeps_omitted_files(
    tmp_path, linked, fake_llm
):
    def reply(prompt: str) -> str:
        if _SECOND_PASS_MARKER in prompt:
            return _file_blocks("x", prefix="pass2")         # only x revised in pass 2
        return _file_blocks("x", "y", "z", prefix="pass1")
    fake_llm.side_effect = reply
    batch = _write_code_batch(tmp_path, ["app/x.js", "app/y.js", "app/z.js"])

    entry = process_batch(batch, repo_dir=str(linked), files_per_prompt=3, passes=2)

    assert len(fake_llm.calls) == 2
    assert "Additional context" not in fake_llm.calls[0]
    assert "===FILE: app/z.js===\npass1 z\n===END FILE===" in fake_llm.calls[1]
    assert "Related code in the app" in fake_llm.calls[1]
    assert [f["content"] for f in entry["files"]] == ["pass2 x", "pass1 y", "pass1 z"]


def test_files_per_prompt_is_a_limit_not_a_target(tmp_path, linked, fake_llm):
    """A batch with fewer files than the limit just sends fewer: no filler files are added."""
    fake_llm.response = _file_blocks("x", "y", "z")
    batch = _write_code_batch(tmp_path, ["app/x.js", "app/y.js", "app/z.js"])

    entry = process_batch(batch, repo_dir=str(linked), files_per_prompt=20)

    assert len(fake_llm.calls) == 1
    assert "You are given 3 file(s)" in fake_llm.calls[0]
    assert fake_llm.calls[0].count("### File ") == 3
    assert [f["path"] for f in entry["files"]] == ["app/x.js", "app/y.js", "app/z.js"]


def test_make_prompt_groups_keeps_logic_together_and_other_fix_types_single():
    def e(path, fix_type="code_change"):
        return {"path": path, "fix_type": fix_type, "content": "", "findings": [{}]}

    logic = [e("a", "logic_change"), e("b", "logic_change"), e("c", "logic_change")]
    assert make_prompt_groups(logic, "logic", files_per_prompt=1) == [logic]

    mixed = [e("a"), e("b"), e("pkg", "version_upgrade"), e("c")]
    groups = make_prompt_groups(mixed, "sast", files_per_prompt=10)
    assert [[x["path"] for x in g] for g in groups] == [["pkg"], ["a", "b", "c"]]


# --------------------------------------------------------------------------------------
# Repo-aware context (3.1)
# --------------------------------------------------------------------------------------

_CODE_FINDINGS = [{
    "location": {"line": 1}, "title": "Code Injection", "description": "d",
    "identifiers": {"cwe": "CWE-94", "rule_id": "r1"},
}]


@pytest.fixture
def imported_x(repo_dir):
    """app/y.js imports app/x.js and calls it -- so x.js has an importer to report."""
    (repo_dir / "app" / "y.js").write_text(
        'const X = require("./x");\nX.run(req.body);\n', encoding="utf-8"
    )
    return repo_dir


@pytest.mark.parametrize("fix_type", ["code_change", "logic_change", "version_upgrade", "config_change"])
def test_empty_context_leaves_prompt_unchanged(fix_type):
    findings = [{
        "finding_type": "sca", "location": {"line": 1, "package": "a@1", "file": "f"},
        "remediation": {"upgrade_to": "a@2"}, "identifiers": {"cwe": None, "rule_id": None, "cve": None},
        "title": "t", "description": "d",
    }]
    base = build_fix_prompt("app/x.js", "content", findings, fix_type)
    assert build_fix_prompt("app/x.js", "content", findings, fix_type, context=FixContext()) == base
    assert build_fix_prompt("app/x.js", "content", findings, fix_type, context=None) == base


def test_context_section_sits_between_findings_and_file_content():
    prompt = build_fix_prompt(
        "app/x.js", "FILE BODY", _CODE_FINDINGS, "code_change",
        context=FixContext(repo="Imported by: app/y.js"),
    )
    assert "Related code in the app" in prompt
    assert "read-only reference" in prompt
    assert prompt.index("Code Injection") < prompt.index("Imported by: app/y.js") < prompt.index("FILE BODY")


def test_context_sections_render_in_rag_memory_repo_order():
    prompt = build_fix_prompt(
        "app/x.js", "c", _CODE_FINDINGS, "code_change",
        context=FixContext(rag="RAG TEXT", memory="MEMORY TEXT", repo="REPO TEXT"),
    )
    assert prompt.index("RAG TEXT") < prompt.index("MEMORY TEXT") < prompt.index("REPO TEXT")


def _fake_rag(monkeypatch, text="RAG GUIDANCE"):
    """The RAG's answer for every file, recording who was asked for."""
    asked = []

    def prompt_context(file_path, findings, fix_type):
        asked.append((file_path, fix_type))
        return text

    monkeypatch.setattr(rag_client, "prompt_context", prompt_context)
    return asked


def test_process_batch_puts_the_rag_text_in_the_prompt_before_the_file(tmp_path, repo_dir, fake_llm, monkeypatch):
    fake_llm.response = "fixed"
    asked = _fake_rag(monkeypatch)
    process_batch(_write_batch(tmp_path, "app/x.js"), repo_dir=str(repo_dir))
    assert asked == [("app/x.js", "code_change")]
    prompt = fake_llm.calls[0]
    assert "Security guidance for these findings" in prompt
    assert prompt.index("RAG GUIDANCE") < prompt.index("old content")


def test_process_batch_keeps_repo_context_next_to_the_rag_text(tmp_path, imported_x, fake_llm, monkeypatch):
    fake_llm.response = "fixed"
    _fake_rag(monkeypatch)
    process_batch(_write_batch(tmp_path, "app/x.js"), repo_dir=str(imported_x))
    assert "RAG GUIDANCE" in fake_llm.calls[0] and "app/y.js" in fake_llm.calls[0]


def test_dependency_and_container_fixes_also_get_the_rag_text(tmp_path, repo_dir, fake_llm, monkeypatch):
    fake_llm.response = "fixed"
    asked = _fake_rag(monkeypatch)
    batch_path = _write_batch(tmp_path, "app/x.js", fix_type="version_upgrade")
    batch = json.loads(batch_path.read_text())
    batch["files_to_fix"][0]["findings"][0].update({
        "finding_type": "container", "location": {"file": "app/x.js", "package": "glibc@2.23"},
        "remediation": {"upgrade_to": "glibc@2.24"},
    })
    batch_path.write_text(json.dumps(batch), encoding="utf-8")
    process_batch(batch_path, repo_dir=str(repo_dir))
    assert asked == [("app/x.js", "version_upgrade")]
    assert "RAG GUIDANCE" in fake_llm.calls[0]


def test_without_a_rag_answer_the_prompt_is_the_baseline_prompt(tmp_path, repo_dir, fake_llm, monkeypatch):
    fake_llm.response = "fixed"
    batch_path = _write_batch(tmp_path, "app/x.js")
    process_batch(batch_path, repo_dir=str(repo_dir), use_repo_context=False)
    _fake_rag(monkeypatch, text="")  # RAG off, or down: rag_client answers ""
    process_batch(batch_path, repo_dir=str(repo_dir), use_repo_context=False)
    assert fake_llm.calls[0] == fake_llm.calls[1]
    assert "Additional context" not in fake_llm.calls[1]


def test_logic_batches_do_not_ask_the_rag(tmp_path, repo_dir, fake_llm, monkeypatch):
    fake_llm.response = "===FILE: app/x.js===\nfixed x\n===END FILE===\n"
    asked = _fake_rag(monkeypatch)
    process_batch(_write_logic_batch(tmp_path, ["app/x.js"]), repo_dir=str(repo_dir))
    assert asked == []


def test_a_retry_keeps_the_rag_text(repo_dir, fake_llm, monkeypatch):
    fake_llm.response = "second fix"
    _fake_rag(monkeypatch)
    refix = make_refix_fn([_cycle_entry()], str(repo_dir))
    assert refix("app/x.js", [{"location": {"line": 1}, "title": "t", "description": "d",
                               "identifiers": {"cwe": "CWE-1", "rule_id": "r1"}}], 1) == "second fix"
    assert "RAG GUIDANCE" in fake_llm.calls[0]


def test_process_batch_code_change_prompt_shows_importer_and_require_line(
    tmp_path, imported_x, fake_llm
):
    fake_llm.response = "fixed"
    process_batch(_write_batch(tmp_path, "app/x.js"), repo_dir=str(imported_x))

    assert "app/y.js" in fake_llm.calls[0]
    assert 'L1: const X = require("./x");' in fake_llm.calls[0]
    assert "L2: X.run(req.body);" in fake_llm.calls[0]


def test_process_batch_version_upgrade_gets_no_repo_context(tmp_path, imported_x, fake_llm):
    """Even when the file has importers, dependency fixes get no import-graph context."""
    fake_llm.response = "fixed"
    batch_path = _write_batch(tmp_path, "app/x.js", fix_type="version_upgrade")
    batch = json.loads(batch_path.read_text())
    batch["files_to_fix"][0]["findings"][0].update({
        "finding_type": "container",
        "location": {"file": "mongo_4.0", "package": "glibc@2.23"},
        "remediation": {"upgrade_to": "glibc@2.24"},
    })
    batch_path.write_text(json.dumps(batch), encoding="utf-8")

    process_batch(batch_path, repo_dir=str(imported_x))

    assert "Additional context" not in fake_llm.calls[0]


def test_no_repo_context_switch_matches_baseline_prompt(tmp_path, imported_x, fake_llm, monkeypatch):
    fake_llm.response = "fixed"
    batch_path = _write_batch(tmp_path, "app/x.js")
    baseline = build_fix_prompt("app/x.js", "old content", json.loads(
        batch_path.read_text())["files_to_fix"][0]["findings"], "code_change")

    process_batch(batch_path, repo_dir=str(imported_x), use_repo_context=False)
    monkeypatch.setenv("ASVA_REPO_CONTEXT", "0")
    process_batch(batch_path, repo_dir=str(imported_x))

    assert fake_llm.calls == [baseline, baseline]


def test_refix_prompt_keeps_repo_context(imported_x, fake_llm):
    fake_llm.response = "second fix"
    refix = make_refix_fn([_cycle_entry()], str(imported_x))
    refix("app/x.js", _CODE_FINDINGS, 1)
    assert "Related code in the app" in fake_llm.calls[0]
    assert "first fix" in fake_llm.calls[0]


# --------------------------------------------------------------------------------------
# Breaking dependency upgrades -> PR review notes (3.1, D3)
# --------------------------------------------------------------------------------------

@pytest.mark.parametrize("current,target,breaking", [
    ("^2.1.18", "3.1.13", True),    # major bump
    ("0.3.5", "0.3.18", False),     # patch on 0.x
    ("~0.3.5", "0.4.0", True),      # minor bump on 0.x is breaking under semver
    ("^1.15.1", "1.20.3", False),   # minor bump on 1.x
    ("2.0.0", "2.0.0", False),
    ("latest", "3.0.0", False),     # unparseable current spec: don't guess
    ("==2022.12.7", "2023.7.22", False),   # calendar versioning is not semver
])
def test_is_breaking_upgrade(current, target, breaking):
    assert is_breaking_upgrade(current, target) is breaking


def test_upgrade_review_notes_names_usage_sites_for_major_bumps(tmp_path):
    from agent.repo_context import build_import_index
    (tmp_path / "server.js").write_text(
        'const MongoClient = require("mongodb").MongoClient;\n', encoding="utf-8"
    )
    index = build_import_index(tmp_path)
    manifest = json.dumps({"dependencies": {"mongodb": "^2.1.18", "marked": "0.3.5"}})

    notes = upgrade_review_notes(manifest, {"mongodb": "3.1.13", "marked": "0.3.18"}, index)

    assert len(notes) == 1
    assert "`mongodb` ^2.1.18 -> 3.1.13" in notes[0]
    assert "`server.js:1`" in notes[0]


def test_process_batch_records_review_notes_for_package_json(tmp_path, repo_dir, fake_llm, monkeypatch):
    # A major upgrade that is applied (safe_upgrades holds these back today; option A will apply tested ones)
    monkeypatch.setattr(agent_loop.safe_upgrades, "apply", lambda batch: None)
    (repo_dir / "package.json").write_text(
        json.dumps({"dependencies": {"mongodb": "^2.1.18"}}), encoding="utf-8"
    )
    (repo_dir / "server.js").write_text('const m = require("mongodb");\n', encoding="utf-8")
    batch = {
        "batch_id": "asva_sca_test", "batch_type": "sca", "total_files": 1, "total_findings": 1,
        "files_to_fix": [{
            "file": "package.json", "fix_type": "version_upgrade", "finding_type": "sca",
            "findings": [{
                "finding_type": "sca", "title": "t",
                "location": {"package": "mongodb@2.1.18"},
                "remediation": {"upgrade_to": "mongodb@3.1.13"},
                "identifiers": {"cve": "CVE-X"},
            }],
        }],
    }
    batch_path = tmp_path / "sca.json"
    batch_path.write_text(json.dumps(batch), encoding="utf-8")
    fake_llm.response = "{}"

    entry = process_batch(batch_path, repo_dir=str(repo_dir))

    notes = entry["batch"]["review_notes"]["package.json"]
    assert "mongodb" in notes[0] and "`server.js:1`" in notes[0]

    # --no-repo-context turns off every 3.1 feature, review notes included
    entry = process_batch(batch_path, repo_dir=str(repo_dir), use_repo_context=False)
    assert "review_notes" not in entry["batch"]


def test_long_prompt_warns_about_context_truncation(tmp_path, repo_dir, fake_llm, monkeypatch, capsys):
    monkeypatch.delenv("OLLAMA_NUM_CTX", raising=False)
    (repo_dir / "app" / "x.js").write_text("x" * 20000, encoding="utf-8")   # ~5,000 tokens
    fake_llm.response = "fixed"
    process_batch(_write_batch(tmp_path, "app/x.js"), repo_dir=str(repo_dir))
    assert "OLLAMA_NUM_CTX is not set" in capsys.readouterr().out

    monkeypatch.setenv("OLLAMA_NUM_CTX", "32768")
    process_batch(_write_batch(tmp_path, "app/x.js"), repo_dir=str(repo_dir))
    assert "[WARN] prompt is" not in capsys.readouterr().out


def test_scanner_code_flow_reaches_the_prompt_and_is_off_without_repo_context(
    tmp_path, linked, fake_llm
):
    batch_path = _write_batch(tmp_path, "app/x.js")
    batch = json.loads(batch_path.read_text())
    batch["files_to_fix"][0]["findings"][0]["code_flow"] = [
        {"file": "app/y.js", "line": 2}, {"file": "app/x.js", "line": 1},
    ]
    batch_path.write_text(json.dumps(batch), encoding="utf-8")
    fake_llm.response = "fixed"

    process_batch(batch_path, repo_dir=str(linked))
    process_batch(batch_path, repo_dir=str(linked), use_repo_context=False)

    with_ctx, without = fake_llm.calls
    assert "Data flow reported by the SAST scanner" in with_ctx
    assert "app/y.js L2 -> L1" in with_ctx
    assert "Data flow reported by the SAST scanner" not in without


def test_cut_off_reply_is_reported(tmp_path, repo_dir, fake_llm, capsys):
    from llm import llm_client

    def reply(prompt):
        llm_client.last_call.update({"finish_reason": "length", "prompt_tokens": 9000,
                                     "completion_tokens": 7000})
        return "partial fix"
    fake_llm.side_effect = reply

    process_batch(_write_batch(tmp_path, "app/x.js"), repo_dir=str(repo_dir))

    assert "[WARN] reply was cut off before the end (finish_reason=length" in capsys.readouterr().out
    llm_client.last_call.clear()



# --------------------------------------------------------------------------------------
# Other target apps: Python/Django (PyGoat)
# --------------------------------------------------------------------------------------

from agent import agent_loop  # noqa: E402

_PY_FINDINGS = [{
    "location": {"line": 3}, "title": "Deserialization of Untrusted Data",
    "description": "Unsanitized input flows into pickle.loads.",
    "identifiers": {"cwe": "CWE-502", "rule_id": "python/Deserialization"},
}]


@pytest.fixture
def py_repo(tmp_path, monkeypatch):
    """A tiny Django app: shop/urls.py routes to shop/views.py:buy."""
    monkeypatch.setattr(config, "FIX_PATH_PREFIX", "")
    monkeypatch.setenv("ASVA_APP_LANGUAGE", "python")
    root = tmp_path / "repo"
    files = {
        "manage.py": "",
        "shop/__init__.py": "",
        "shop/views.py": "import pickle\n\ndef buy(request):\n    return pickle.loads(request.body)\n",
        "shop/urls.py": "from . import views\nurlpatterns = [path('buy', views.buy)]\n",
    }
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")
    return root


def _py_batch(tmp_path, files):
    entries = [{"file": f, "fix_type": "code_change", "finding_type": "sast", "finding_count": 1,
                "findings": _PY_FINDINGS} for f in files]
    batch = {"batch_id": "asva_sast_py_1", "batch_type": "sast", "total_files": len(entries),
             "total_findings": len(entries), "files_to_fix": entries}
    path = tmp_path / "py_batch.json"
    path.write_text(json.dumps(batch), encoding="utf-8")
    return path


def test_app_language_is_detected_from_the_app_folder(tmp_path, monkeypatch):
    (tmp_path / "PyGoat").mkdir()
    (tmp_path / "PyGoat" / "manage.py").write_text("", encoding="utf-8")
    (tmp_path / "NodeGoat").mkdir()
    (tmp_path / "NodeGoat" / "package.json").write_text("{}", encoding="utf-8")

    monkeypatch.setattr(config, "FIX_PATH_PREFIX", str(tmp_path / "PyGoat"))
    assert agent_loop.app_language() == "python"
    monkeypatch.setattr(config, "FIX_PATH_PREFIX", str(tmp_path / "NodeGoat"))
    assert agent_loop.app_language() == "node"
    monkeypatch.setenv("ASVA_APP_LANGUAGE", "python")        # explicit setting wins
    assert agent_loop.app_language() == "python"
    monkeypatch.delenv("ASVA_APP_LANGUAGE")
    monkeypatch.setattr(config, "FIX_PATH_PREFIX", "")
    assert agent_loop.app_language() == "node"                # ITP1 default


def test_python_prompt_without_context_is_unchanged_and_gains_the_block_with_it(monkeypatch):
    monkeypatch.setenv("ASVA_APP_LANGUAGE", "python")
    base = build_fix_prompt("shop/views.py", "CONTENT", _PY_FINDINGS, "code_change")
    assert base.startswith("You are fixing a Python/Django application.")
    assert "Additional context" not in base

    ctx = build_fix_prompt("shop/views.py", "CONTENT", _PY_FINDINGS, "code_change",
                           context=FixContext(repo="shop/urls.py uses views.buy"))
    assert ctx.index("Related code in the app") < ctx.index("Current file:") < ctx.index("CONTENT")
    assert ctx.replace(
        ctx[ctx.index("Additional context"):ctx.index("Current file:")], "") == base


def test_python_multi_file_prompt_names_the_language_and_rules(monkeypatch):
    files = [{"path": f"shop/{n}.py", "content": n, "findings": _PY_FINDINGS,
              "fix_type": "code_change"} for n in ("a", "b")]
    node_prompt = agent_loop.build_multi_file_prompt(files)
    assert "a Node.js application" in node_prompt and "lab routes" not in node_prompt
    monkeypatch.setenv("ASVA_APP_LANGUAGE", "python")
    py_prompt = agent_loop.build_multi_file_prompt(files)
    assert "a Python/Django application" in py_prompt
    assert "Do not remove authentication, CSRF protection" in py_prompt


def test_python_two_passes_add_django_route_context_in_pass_2(tmp_path, py_repo, fake_llm):
    fake_llm.side_effect = _per_pass_llm()
    entry = process_batch(_py_batch(tmp_path, ["shop/views.py"]), repo_dir=str(py_repo), passes=2)

    local, integration = fake_llm.calls
    assert "Related code in the app" not in local
    assert "shop/urls.py" in integration
    assert "path('buy', views.buy)" in integration
    assert "lines using buy" in integration
    assert entry["passes"]["after_pass2"] == {"shop/views.py": "pass2 fix"}


def test_python_files_per_prompt_groups_and_parses(tmp_path, py_repo, fake_llm):
    (py_repo / "shop" / "models.py").write_text("x = 1\n", encoding="utf-8")
    fake_llm.response = ("===FILE: shop/views.py===\nfixed v\n===END FILE===\n"
                         "===FILE: shop/models.py===\nfixed m\n===END FILE===\n")
    entry = process_batch(_py_batch(tmp_path, ["shop/views.py", "shop/models.py"]),
                          repo_dir=str(py_repo), files_per_prompt=10)
    assert len(fake_llm.calls) == 1
    assert "a Python/Django application" in fake_llm.calls[0]
    assert {f["path"]: f["content"] for f in entry["files"]} == {
        "shop/views.py": "fixed v", "shop/models.py": "fixed m"}


def test_upgrade_review_notes_for_requirements_txt(tmp_path):
    from agent.repo_context import build_import_index
    (tmp_path / "views.py").write_text("import yaml\nfrom django.db import models\n", encoding="utf-8")
    index = build_import_index(tmp_path)
    reqs = "Django==2.2.13  # web\nPyYAML==5.3\nrequests==2.25.0\n-r other.txt\n"

    notes = upgrade_review_notes(reqs, {"django": "3.2.25", "PyYAML": "6.0.1", "requests": "2.31.0"},
                                 index, manifest="requirements.txt")

    assert len(notes) == 2                          # requests 2.x -> 2.x is not breaking
    yaml_note, django = sorted(notes)
    assert "`django` 2.2.13 -> 3.2.25" in django and "`views.py:2`" in django
    assert "`PyYAML` 5.3 -> 6.0.1" in yaml_note and "`views.py:1`" in yaml_note


def test_process_batch_records_review_notes_for_requirements_txt(tmp_path, py_repo, fake_llm, monkeypatch):
    monkeypatch.setattr(agent_loop.safe_upgrades, "apply", lambda batch: None)  # as above
    (py_repo / "requirements.txt").write_text("PyYAML==5.3\n", encoding="utf-8")
    (py_repo / "shop" / "loader.py").write_text("import yaml\n", encoding="utf-8")
    batch = {
        "batch_id": "asva_sca_py", "batch_type": "sca", "total_files": 1, "total_findings": 1,
        "files_to_fix": [{
            "file": "requirements.txt", "fix_type": "version_upgrade", "finding_type": "sca",
            "findings": [{"finding_type": "sca", "title": "t", "location": {"package": "pyyaml@5.3"},
                          "remediation": {"upgrade_to": "pyyaml@6.0.1"}, "identifiers": {}}],
        }],
    }
    path = tmp_path / "sca_py.json"
    path.write_text(json.dumps(batch), encoding="utf-8")
    fake_llm.response = "PyYAML==6.0.1\n"
    entry = process_batch(path, repo_dir=str(py_repo))
    assert "`shop/loader.py:1`" in entry["batch"]["review_notes"]["requirements.txt"][0]


def test_is_dependency_manifest():
    assert agent_loop.is_dependency_manifest("package.json")
    assert agent_loop.is_dependency_manifest("requirements.txt")
    assert agent_loop.is_dependency_manifest("deploy/requirements-prod.txt")
    assert not agent_loop.is_dependency_manifest("docker-compose.yml")
    assert not agent_loop.is_dependency_manifest("package-lock.json")


def test_reply_longer_than_the_reply_cap_is_warned(tmp_path, repo_dir, fake_llm, monkeypatch, capsys):
    (repo_dir / "app" / "x.js").write_text("x" * 40000, encoding="utf-8")   # ~10,000-token reply
    fake_llm.response = "fixed"
    monkeypatch.setenv("OLLAMA_NUM_CTX", "131072")
    monkeypatch.setenv("ASVA_LLM_NUM_PREDICT", "8192")
    process_batch(_write_batch(tmp_path, "app/x.js"), repo_dir=str(repo_dir))
    assert "ASVA_LLM_NUM_PREDICT=8192" in capsys.readouterr().out

    monkeypatch.setenv("ASVA_LLM_NUM_PREDICT", "16384")
    process_batch(_write_batch(tmp_path, "app/x.js"), repo_dir=str(repo_dir))
    assert "reply cap" not in capsys.readouterr().out


def test_python_prompt_names_the_framework(tmp_path, monkeypatch):
    flask = tmp_path / "vulnbank"
    flask.mkdir()
    (flask / "requirements.txt").write_text("Flask==2.0.1\nrequests\n", encoding="utf-8")
    django = tmp_path / "PyGoat"
    django.mkdir()
    (django / "manage.py").write_text("", encoding="utf-8")

    monkeypatch.setattr(config, "FIX_PATH_PREFIX", str(flask))
    assert agent_loop.app_language() == "python"
    assert build_fix_prompt("app.py", "C", _PY_FINDINGS, "code_change").startswith(
        "You are fixing a Python/Flask application.")
    monkeypatch.setattr(config, "FIX_PATH_PREFIX", str(django))
    assert build_fix_prompt("v.py", "C", _PY_FINDINGS, "code_change").startswith(
        "You are fixing a Python/Django application.")


def test_forced_python_with_a_non_python_app_folder_keeps_the_django_wording(tmp_path, monkeypatch):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(config, "FIX_PATH_PREFIX", str(tmp_path))
    monkeypatch.setenv("ASVA_APP_LANGUAGE", "python")
    assert "Python/Django" in build_fix_prompt("views.py", "pass", [], "code_change")


def test_cut_off_single_file_reply_is_not_used_as_a_fix(tmp_path, repo_dir, fake_llm, monkeypatch, capsys):
    from llm import llm_client

    def reply(prompt):
        llm_client.last_call.update({"finish_reason": "length", "reasoning_chars": 9000,
                                     "answer_chars": 0})
        return ""
    fake_llm.side_effect = reply
    entry = process_batch(_write_batch(tmp_path, "app/x.js"), repo_dir=str(repo_dir))
    out = capsys.readouterr().out
    assert entry["files"] == []
    assert "spent the whole reply on hidden reasoning" in out

    def truncated(prompt):
        llm_client.last_call.update({"finish_reason": "length", "reasoning_chars": 0,
                                     "answer_chars": 10})
        return "const x = "
    fake_llm.side_effect = truncated
    assert process_batch(_write_batch(tmp_path, "app/x.js"), repo_dir=str(repo_dir))["files"] == []


def test_python_prompt_shows_compact_scanner_findings(monkeypatch):
    monkeypatch.setenv("ASVA_APP_LANGUAGE", "python")
    findings = [{**_PY_FINDINGS[0], "finding_type": "sast", "score": 9.1, "dedup_key": "k" * 200,
                 "code_flow": [{"file": "a.py", "line": 1}] * 50}]
    prompt = build_fix_prompt("shop/views.py", "C", findings, "code_change")
    assert '"rule_id": "python/Deserialization"' in prompt and '"line": 3' in prompt
    assert "dedup_key" not in prompt and "code_flow" not in prompt
    sca = [{"finding_type": "sca", "title": "t", "location": {"package": "pyyaml@5.3"},
            "remediation": {"upgrade_to": "pyyaml@6.0.1"}, "identifiers": {}}]
    # Dependency findings keep their upgrade target (pip requirements prompt)
    sca_prompt = build_fix_prompt("requirements.txt", "C", sca, "version_upgrade")
    assert '"package": "pyyaml"' in sca_prompt and '"upgrade_to_version": "6.0.1"' in sca_prompt
