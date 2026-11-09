"""Pinned requirements files: the versions are set in code. The LLM stays for what code can't do."""

from __future__ import annotations

import json

import pytest

from agent import agent_loop
from gitops import config

pytestmark = pytest.mark.unit

REQUIREMENTS = "# deps\nDjango==4.2\nPyYAML==5.1  # yaml\nargon2-cffi-bindings==21.2.0\nrequests>=2\nzope.interface==5.0\n"


def finding(package, target):
    return {"finding_id": target, "finding_type": "sca", "severity": "high", "title": target, "identifiers": {"cve": target},
            "location": {"file": "requirements.txt", "package": package}, "remediation": {"upgrade_to": target, "fixable": True}}


def entry(findings, content=REQUIREMENTS, path="requirements.txt", fix_type="version_upgrade"):
    return {"path": path, "content": content, "findings": findings, "fix_type": fix_type}


def test_versions_are_set_and_every_other_line_stays_exactly_as_it_was():
    fixed = agent_loop.pinned_requirements_fix([entry([finding("django@4.2", "django@4.2.28"), finding("pyyaml@5.1", "pyyaml@5.4")])])
    assert fixed["requirements.txt"] == "# deps\nDjango==4.2.28\nPyYAML==5.4  # yaml\nargon2-cffi-bindings==21.2.0\nrequests>=2\nzope.interface==5.0\n"


def test_names_are_compared_as_pip_does():
    fixed = agent_loop.pinned_requirements_fix([entry([finding("zope-interface@5.0", "zope-interface@5.1"), finding("argon2_cffi_bindings@21.2.0", "argon2_cffi_bindings@25.1.0")])])
    assert "zope.interface==5.1" in fixed["requirements.txt"] and "argon2-cffi-bindings==25.1.0" in fixed["requirements.txt"]


@pytest.mark.parametrize("case", [
    entry([finding("requests@2", "requests@2.30.0")]),                     # a range, not a pin
    entry([finding("django@4.2", "django@4.2.28"), finding("x@1", "x@2")]),  # one the file doesn't list
    entry([finding("django@4.2", "django@4.2.28")], path="pyproject.toml"),
    entry([finding("django@4.2", "django@4.2.28")], fix_type="code_change"),
    entry([]),
], ids=["range", "not listed", "other file", "other fix type", "nothing to upgrade"])
def test_anything_else_stays_with_the_llm(case):
    assert agent_loop.pinned_requirements_fix([case]) is None


def test_more_than_one_file_stays_with_the_llm():
    one = entry([finding("django@4.2", "django@4.2.28")])
    assert agent_loop.pinned_requirements_fix([one, one]) is None


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "FIX_PATH_PREFIX", "")
    (tmp_path / "requirements.txt").write_text(REQUIREMENTS, encoding="utf-8")
    monkeypatch.setenv("ASVA_DECISIONS_PATH", str(tmp_path / "none.json"))
    return tmp_path


def _batch(tmp_path, findings):
    path = tmp_path / "b.json"
    path.write_text(json.dumps({"batch_id": "b", "batch_type": "sca", "total_files": 1, "total_findings": len(findings),
                                "files_to_fix": [{"file": "requirements.txt", "fix_type": "version_upgrade", "finding_type": "sca", "findings": findings}]}), encoding="utf-8")
    return path


def test_process_batch_makes_no_llm_call_and_records_how_it_was_done(repo, monkeypatch):
    monkeypatch.setattr(agent_loop, "call_llm", lambda *_: pytest.fail("called the LLM"))
    result = agent_loop.process_batch(_batch(repo, [finding("django@4.2", "django@4.2.28")]), str(repo), use_repo_context=False)
    assert "Django==4.2.28" in result["files"][0]["content"]
    assert result["generation"]["method"] == "code" and result["generation"]["status"] == "generated"


def test_a_pin_the_file_does_not_have_still_goes_to_the_llm(repo, monkeypatch):
    asked = []

    def llm(prompt, *_):
        asked.append(prompt)
        return "Django==4.2.28\nx==2\n"

    monkeypatch.setattr(agent_loop, "call_llm", llm)
    result = agent_loop.process_batch(_batch(repo, [finding("django@4.2", "django@4.2.28"), finding("x@1.0", "x@1.1")]), str(repo), use_repo_context=False)
    assert asked and result["generation"]["method"] != "code"


def test_the_safe_versions_are_what_gets_set_not_the_scanners(repo, monkeypatch):
    monkeypatch.setattr(agent_loop, "call_llm", lambda *_: pytest.fail("called the LLM"))
    # The major jump is held back by the same-major rule, so only the safe one is set.
    result = agent_loop.process_batch(_batch(repo, [finding("django@4.2", "django@4.2.28"), finding("pyyaml@5.1", "pyyaml@6.0.3")]), str(repo), use_repo_context=False)
    assert "Django==4.2.28" in result["files"][0]["content"] and "PyYAML==5.1" in result["files"][0]["content"]


def test_a_file_set_in_code_does_not_say_memory_was_injected(repo, monkeypatch, capsys):
    from memory import memory_store
    django = finding("django@4.2", "django@4.2.28")
    memory_store.save_fix(memory_store.make_fingerprint(django), "requirements.txt", "sca", "", "run-1", "committed", "s", "old")
    monkeypatch.setattr(agent_loop, "call_llm", lambda *_: pytest.fail("called the LLM"))
    agent_loop.process_batch(_batch(repo, [django]), str(repo), use_repo_context=False)
    assert "[MEMORY]" not in capsys.readouterr().out  # no prompt, so nothing was injected


def test_a_finding_a_reviewer_excluded_is_not_upgraded(repo, monkeypatch):
    monkeypatch.setattr(agent_loop, "call_llm", lambda *_: pytest.fail("called the LLM"))
    monkeypatch.setattr(agent_loop, "apply_reviewer_memory", lambda entries, decisions: ([{**e, "findings": e["findings"][:1]} for e in entries], {}))
    result = agent_loop.process_batch(_batch(repo, [finding("django@4.2", "django@4.2.28"), finding("pyyaml@5.1", "pyyaml@5.4")]), str(repo), use_repo_context=False)
    assert "Django==4.2.28" in result["files"][0]["content"] and "PyYAML==5.1" in result["files"][0]["content"]
