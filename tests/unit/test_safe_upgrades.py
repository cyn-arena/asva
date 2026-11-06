"""Which versions a fix may use: the RAG's compatible version, the same-major rule without it, and
what happens when nothing safe is left. The RAG is faked; no network, LLM or GitHub calls."""

from __future__ import annotations

import copy
import json

import pytest

from agent import agent_loop, npm_remediation, rag_client, safe_upgrades
from gitops import config, git_gh_ops, post_fix_failure_issue
from security_context.integration import asva_rag_client as client

pytestmark = pytest.mark.unit


def sca(package, upgrade_to, cve="CVE-1", path=None):
    finding = {"finding_id": cve, "finding_type": "sca", "title": "t", "identifiers": {"cve": cve},
               "location": {"package": package}, "remediation": {"upgrade_to": upgrade_to}}
    if path:
        finding["dependency"] = {"path": path}
    return finding


def container(image="mongo", tag="4.4"):
    return {"finding_id": "CVE-2", "finding_type": "container", "title": "t", "identifiers": {"cve": "CVE-2"},
            "location": {"package": "perl@5", "image_name": image, "image_tag": tag},
            "remediation": {"upgrade_to": None}}


def batch_of(file, findings, batch_type="sca"):
    return {"batch_id": f"asva_{batch_type}_x", "batch_type": batch_type, "repo_name": "asva", "commit_sha": "abc",
            "total_files": 1, "total_findings": len(findings),
            "files_to_fix": [{"file": file, "fix_type": "version_upgrade", "finding_type": batch_type, "findings": findings}]}


def package(name, safe, scope="all", **extra):
    return {"kind": "package", "name": name, "current": "1.0.0", "target": "9.0.0", "compatible_target": safe,
            "compatible_scope": scope if safe else None, "status": "ok" if safe else "major_change",
            "major_change": not safe, "note": None if safe else "No compatible fix: needs a migration.", **extra}


def image(safe=None, status="newer_line_needed", note="No compatible fix: no 4.x line of mongo resolves these."):
    return {"kind": "image", "name": "mongo", "current": "4.4", "target": "7.0", "compatible_target": safe,
            "status": status, "major_change": True, "note": note}


@pytest.fixture
def rag(monkeypatch):
    """The RAG's answer, set by the test. None means the RAG is off or down."""
    state = {"answer": None, "asked": []}

    def response(findings, fix_type, **kwargs):
        state["asked"].append(kwargs)
        return state["answer"]

    monkeypatch.setattr(rag_client, "response", response)
    monkeypatch.setattr(rag_client, "manifest_response", lambda path, content, findings, fix_type:
                        response(findings, fix_type, manifest=(path, content)))
    return state


@pytest.mark.parametrize("current, target, same", [
    ("2.2.36", "2.3.0", True), ("2.2.36", "3.1.13", False), ("0.3.5", "0.3.18", True), ("0.3.1", "0.6.0", False),
    ("2022.12.7", "2023.7.22", False), (None, "1.0.0", False), ("1.0.0", None, False),
])
def test_same_major(current, target, same):
    assert safe_upgrades.same_major(current, target) is same


def test_the_rag_version_replaces_the_scanner_version_and_the_scanner_version_is_kept(rag):
    rag["answer"] = {"upgrades": [package("urllib3", "1.26.19", "partial"), package("pillow", None), package("django", "4.2.28")]}
    findings = [sca("urllib3@1.26.9", "urllib3@2.8.0"), sca("pillow@9.4.0", "pillow@12.3.0"), sca("django@4.2", "django@4.2.28")]
    batch = batch_of("requirements.txt", findings)

    safe_upgrades.apply(batch)

    assert [f["remediation"]["upgrade_to"] for f in findings] == ["urllib3@1.26.19", None, "django@4.2.28"]
    assert [f["remediation"]["scanner_upgrade_to"] for f in findings] == ["urllib3@2.8.0", "pillow@12.3.0", "django@4.2.28"]
    assert batch["upgrade_source"] == "rag"


def test_the_rag_is_always_asked_about_the_scanner_version():
    # The agent rewrites upgrade_to; the RAG must still see what the scanner said, so its answer does not change.
    finding = sca("mongodb@2.2.36", "mongodb@3.1.13")
    before = client.to_request_finding(finding)
    finding["remediation"].update(scanner_upgrade_to="mongodb@3.1.13", upgrade_to=None)
    assert client.to_request_finding(finding) == before


def test_without_the_rag_the_same_major_rule_applies(rag):
    findings = [sca("marked@0.3.5", "marked@0.3.18"), sca("mongodb@2.2.36", "mongodb@3.1.13"),
                sca("qs@6.5.2", "express@4.22.3", path=["app@1.0.0", "express@4.16.4", "qs@6.5.2"]),
                sca("qs@6.5.2", "express@5.3.0", path=["app@1.0.0", "express@4.16.4", "qs@6.5.2"])]
    batch = batch_of("package.json", findings)

    safe_upgrades.apply(batch)

    assert [f["remediation"]["upgrade_to"] for f in findings] == ["marked@0.3.18", None, "express@4.22.3", None]
    assert batch["upgrade_source"] == "rule"


def test_a_package_the_rag_has_no_answer_for_uses_the_rule(rag):
    rag["answer"] = {"upgrades": [package("marked", "0.3.18")]}
    findings = [sca("marked@0.3.5", "marked@0.3.18"), sca("mongodb@2.2.36", "mongodb@3.1.13")]
    batch = batch_of("package.json", findings)

    safe_upgrades.apply(batch)

    assert findings[1]["remediation"]["upgrade_to"] is None
    assert batch["upgrade_source"] == "mixed"


def test_a_finding_the_scanner_has_no_upgrade_for_is_left_alone(rag):
    finding = sca("x@1.0.0", None)
    batch = batch_of("package.json", [finding])
    safe_upgrades.apply(batch)
    assert "scanner_upgrade_to" not in finding["remediation"]
    assert "upgrade_source" not in batch


def test_other_batches_are_not_touched(rag):
    finding = {"finding_type": "sast", "location": {"line": 1}, "remediation": {"upgrade_to": None}}
    batch = batch_of("app/x.js", [copy.deepcopy(finding)], "sast")
    safe_upgrades.apply(batch)
    assert batch["files_to_fix"][0]["findings"] == [finding]


def test_the_npm_plan_only_holds_the_safe_versions(rag):
    # NodeGoat's case: mongodb 2 -> 3 is what stopped the app starting.
    rag["answer"] = {"upgrades": [package("marked", "0.3.18"), package("mongodb", None)]}
    batch = batch_of("package.json", [sca("marked@0.3.5", "marked@0.3.18"), sca("mongodb@2.2.36", "mongodb@3.1.13", "CVE-3")])
    safe_upgrades.apply(batch)
    manifest = {"dependencies": {"marked": "0.3.5", "mongodb": "^2.1.18"}}
    lock = {"packages": {"node_modules/marked": {"version": "0.3.5"}, "node_modules/mongodb": {"version": "2.2.36"}}}

    upgrades, unresolved = npm_remediation.upgrade_plan(batch, manifest, lock)

    assert list(upgrades) == ["marked"]
    assert [u["finding_id"] for u in unresolved] == ["CVE-3"]


# -- nothing safe left to change -------------------------------------------------------------------

def test_a_dependency_file_with_every_upgrade_held_back_has_nothing_to_edit(rag):
    rag["answer"] = {"upgrades": [package("pillow", None)]}
    batch = batch_of("requirements.txt", [sca("pillow@9.4.0", "pillow@12.3.0")])
    safe_upgrades.apply(batch)
    reason = safe_upgrades.nothing_to_edit(batch["files_to_fix"][0])
    assert "held back" in reason and "needs a migration" in reason


def test_a_dependency_file_with_one_safe_upgrade_goes_ahead(rag):
    rag["answer"] = {"upgrades": [package("pillow", None), package("django", "4.2.28")]}
    batch = batch_of("requirements.txt", [sca("pillow@9.4.0", "pillow@12.3.0"), sca("django@4.2", "django@4.2.28")])
    safe_upgrades.apply(batch)
    assert safe_upgrades.nothing_to_edit(batch["files_to_fix"][0]) == ""


@pytest.mark.parametrize("answer, held", [
    ({"upgrades": [image()]}, True),                                                    # no compatible line
    ({"upgrades": [image(status="rebuild_may_suffice", note="No tag change needed.")]}, True),  # same tag, rebuilt
    ({"upgrades": [image(safe="4.4.29")]}, False),                                      # a tag to use
    ({"upgrades": [image(status="unknown")]}, False),                                   # the RAG cannot tell
    ({"upgrades": []}, False),
    (None, False),                                                                      # RAG off: the prompt guard still applies
])
def test_a_container_file_is_held_back_only_when_the_rag_says_so(rag, answer, held):
    rag["answer"] = answer
    entry = batch_of("docker-compose.yml", [container()], "container")["files_to_fix"][0]
    assert bool(safe_upgrades.nothing_to_edit(entry)) is held


def _process(tmp_path, batch, file, content):
    (tmp_path / file).write_text(content, encoding="utf-8")
    path = tmp_path / "batch.json"
    path.write_text(json.dumps(batch), encoding="utf-8")
    return agent_loop.process_batch(path, repo_dir=str(tmp_path))


@pytest.fixture
def no_prefix(monkeypatch):
    monkeypatch.setattr(config, "FIX_PATH_PREFIX", "")
    monkeypatch.delenv("ASVA_APP_LANGUAGE", raising=False)


@pytest.fixture
def no_llm(monkeypatch):
    monkeypatch.setattr(agent_loop, "call_llm", lambda _: pytest.fail("nothing safe to change: must not call the LLM"))


def test_a_held_back_container_file_skips_the_llm_and_is_not_a_failure(tmp_path, rag, no_prefix, no_llm):
    rag["answer"] = {"upgrades": [image()], "items": [], "references": [], "trials": []}
    entry = _process(tmp_path, batch_of("docker-compose.yml", [container()], "container"), "docker-compose.yml", "image: mongo:4.4\n")

    assert entry["files"] == []
    assert entry["generation"]["method"] == "rag" and entry["generation"]["status"] == "no_candidate"
    assert "no 4.x line of mongo" in entry["generation"]["files"][0]["status"]
    assert "mongo:4.4" in entry["generation"]["rag_text"]


def test_a_held_back_dependency_file_skips_the_llm(tmp_path, rag, no_prefix, no_llm):
    rag["answer"] = {"upgrades": [package("pillow", None)], "items": [], "references": [], "trials": []}
    entry = _process(tmp_path, batch_of("requirements.txt", [sca("pillow@9.4.0", "pillow@12.3.0")]), "requirements.txt", "Pillow==9.4.0\n")
    assert entry["files"] == [] and entry["generation"]["status"] == "no_candidate"


def test_the_llm_is_only_given_the_safe_versions_and_the_pr_gets_the_rag_text(tmp_path, rag, no_prefix, monkeypatch):
    rag["answer"] = {"upgrades": [package("pillow", None), package("django", "4.2.28")], "items": [], "references": [],
                     "trials": [{"order": 1, "kind": "major_upgrade", "name": "pillow", "current": "9.4.0", "target": "12.3.0",
                                 "fixes": ["CVE-1"], "known_exploited": [], "also_needs": [], "dev_only": False, "note": "Try it."}]}
    prompts = []
    monkeypatch.setattr(agent_loop, "call_llm", lambda p: prompts.append(p) or "Django==4.2.28\n")
    batch = batch_of("requirements.txt", [sca("pillow@9.4.0", "pillow@12.3.0"), sca("django@4.2", "django@4.2.28")])

    # A range, not a pin, so this one still goes to the LLM (see test_pinned_requirements.py).
    entry = _process(tmp_path, batch, "requirements.txt", "Django>=4.2\nPillow==9.4.0\n")

    assert '"package": "django"' in prompts[0] and '"package": "pillow"' not in prompts[0]
    text = entry["batch"]["rag_pr_text"]
    assert "Upgrade summary" in text and "Upgrades to try next" in text and "`pillow` 9.4.0" in text
    assert "RAG unavailable" not in text
    assert rag["asked"][-1]["manifest"] == ("requirements.txt", "Django>=4.2\nPillow==9.4.0\n")  # for the trial plan


def test_the_pr_says_so_when_the_rag_was_unavailable(tmp_path, rag, no_prefix, monkeypatch):
    monkeypatch.setattr(agent_loop, "call_llm", lambda p: "Django==4.2.28\n")
    entry = _process(tmp_path, batch_of("requirements.txt", [sca("django@4.2", "django@4.2.28")]), "requirements.txt", "Django==4.2\n")
    assert "RAG unavailable" in entry["batch"]["rag_pr_text"]


def test_a_held_back_batch_opens_no_pr_and_reports_the_reason(monkeypatch):
    monkeypatch.setattr(git_gh_ops, "submit_fix_batch", lambda *a, **k: pytest.fail("no PR for a held-back batch"))
    batch = batch_of("docker-compose.yml", [container()], "container")
    generation = {"method": "rag", "status": "no_candidate", "message": "m", "rag_text": "TABLE",
                  "files": [{"path": "docker-compose.yml", "status": "held back, no compatible image: reason"}]}
    result = git_gh_ops.submit_scan_cycle([{"batch": batch, "files": [], "generation": generation}], "main")
    row = result["prs"][0]
    assert row["status"] == "no_commits"
    assert row["failed"] == [{"path": "docker-compose.yml", "reason": "held back, no compatible image: reason"}]

    body = post_fix_failure_issue.format_issue_body(batch, row)
    assert "held back, needs a person" in body and "No fix was attempted" in body and "TABLE" in body
    assert "attempted and rejected" not in body
    assert "no safe fix" in post_fix_failure_issue.format_issue_title("b", row)
    assert "automated fix failed" in post_fix_failure_issue.format_issue_title("b", {"generation": {"method": "llm"}})


# -- PR text ---------------------------------------------------------------------------------------

def test_the_pr_body_carries_the_rag_text_only_when_there_is_some():
    batch = batch_of("requirements.txt", [sca("django@4.2", "django@4.2.28")])
    committed = [{"path": "requirements.txt", "batch_type": "sca", "findings": batch["files_to_fix"][0]["findings"]}]
    assert "From the RAG" not in git_gh_ops.batch_pr_body(batch, committed, [], [])
    batch["rag_pr_text"] = "RAG TABLE"
    body = git_gh_ops.batch_pr_body(batch, committed, [], [])
    assert "From the RAG" in body and body.index("RAG TABLE") < body.index("_Pipeline:")


def test_the_pr_does_not_claim_the_findings_it_holds_back(rag):
    rag["answer"] = {"upgrades": [package("pillow", None), package("django", "4.2.28")]}
    findings = [sca("pillow@9.4.0", "pillow@12.3.0", "CVE-HELD"), sca("django@4.2", "django@4.2.28", "CVE-FIXED")]
    batch = batch_of("requirements.txt", findings)
    safe_upgrades.apply(batch)
    committed = [{"path": "requirements.txt", "batch_type": "sca", "findings": findings}]

    body = git_gh_ops.batch_pr_body(batch, committed, [], [])

    assert "1 finding(s)" in git_gh_ops.batch_pr_title(batch, committed)
    assert "CVE-FIXED" in body and "CVE-HELD" not in body and "1 held back" in body


def test_a_big_answer_cuts_the_references_but_keeps_the_upgrades(monkeypatch):
    monkeypatch.setattr(rag_client, "PR_TEXT_LIMIT", 900)
    references = [{"type": "cve", "id": f"CVE-{n}", "url": "https://nvd.test/x", "cvss": 9.0, "cwes": []} for n in range(200)]
    text = rag_client.pr_text({"upgrades": [package("django", "4.2.28")], "references": references, "trials": []})
    assert "Upgrade summary" in text and "references cut here" in text
    assert len(text) < 1000
