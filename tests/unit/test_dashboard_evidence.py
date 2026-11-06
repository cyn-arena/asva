"""Offline contract and failure-path checks; no GitHub, Azure, AI or Docker calls."""
import importlib.util
import json
from pathlib import Path
import subprocess

import pytest

spec = importlib.util.spec_from_file_location(
    "dashboard_evidence", Path(__file__).resolve().parents[2] / "scripts/dashboard_evidence.py")
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)
pytestmark = pytest.mark.unit

SHA, CANDIDATE = "a" * 40, "b" * 40
METADATA = {"id": 123, "head_sha": SHA, "head_branch": "feat/expand-app-support",
    "created_at": "2026-10-15T01:00:00Z", "run_started_at": "2026-10-15T01:01:00Z",
    "name": "Example pipeline", "html_url": "https://github.com/example/asva/actions/runs/123"}
OUTCOMES = {"scan": "success", "fix": "success", "validate": "success"}


def prepared(tmp_path, app):
    artifacts = tmp_path / "artifacts"
    for kind in ("sast", "sca", "container"):
        name = "image" if app == "nodegoat" and kind == "container" else kind
        evidence.write(artifacts / f"{app}-scan-results/{name}.sarif.json", {"runs": [{"results": []}]})
    fix = artifacts / f"{app}-fix-output"
    findings = [{"finding_id": "fixture", "location": {"file": "requirements.txt"}, "priority": 1}]
    evidence.write(fix / "findings/ranked_unified_findings.json", findings)
    evidence.write(fix / "findings/ranked_findings.json", findings)
    evidence.write(fix / "fix_batches/batch-1.json", {"batch_id": "batch-1", "files_to_fix": []})
    evidence.write(fix / "stage-status.json", {"normalise": "success", "triage": "success", "fix": "success"})
    evidence.write(fix / "fixes.json", [{"batch_id": "batch-1", "batch_type": "sca", "status": "pr_opened",
        "branch": "fix/batch-1", "pr_url": "https://github.com/example/asva/pull/1", "candidate_sha": CANDIDATE,
        "pr_number": 1, "title": "Fix", "body": "Details", "files": []}])
    report = {"batch_id": "batch-1", "pr_url": "https://github.com/example/asva/pull/1",
        "commit_sha": CANDIDATE, "checked_at": METADATA["created_at"], "app_started": True,
        "result": "passed", "checks": [evidence.check("login", True)]}
    evidence.write(artifacts / f"{app}-validation-batch-1/validation/batch-1.json", report)
    return artifacts


def assert_contract(manifest, folder):
    required = {"schema_version", "app", "run_id", "commit_sha", "branch", "workflow",
                "created_at", "workflow_url", "stages", "artifacts"}
    assert required <= manifest.keys()
    assert manifest["schema_version"] == "0.1"
    assert set(manifest["stages"].values()) <= {"completed", "failed", "not_available"}
    assert {"scan", "normalise", "triage", "fix", "validate"} <= manifest["stages"].keys()
    for value in manifest["artifacts"].values():
        paths = value.values() if isinstance(value, dict) else value if isinstance(value, list) else [value]
        for relative in paths:
            assert (folder / relative).is_file(), relative
    for path in (folder / "validation").glob("*.json"):
        report = evidence.read(path)
        assert {"batch_id", "pr_url", "commit_sha", "checked_at", "app_started", "result", "checks"} <= report.keys()
        assert isinstance(report["app_started"], bool)
        assert report["result"] in ("passed", "failed")
        assert all(evidence.valid_check(row) for row in report["checks"])


@pytest.mark.parametrize("app", ["nodegoat", "pygoat"])
def test_complete_package_matches_contract_and_preserves_findings(tmp_path, app):
    artifacts = prepared(tmp_path, app)
    output = tmp_path / "package"
    manifest = evidence.package(app, artifacts, output, METADATA, OUTCOMES)
    assert_contract(manifest, output)
    assert set(manifest["stages"].values()) == {"completed"}
    assert manifest["created_at"] == METADATA["run_started_at"]
    assert manifest["commit_sha"] == SHA[:8]
    assert evidence.read(output / manifest["artifacts"]["findings"]) == evidence.read(
        artifacts / f"{app}-fix-output/findings/ranked_unified_findings.json")
    assert manifest["artifacts"]["remediation"] == manifest["artifacts"]["fixes"]


def test_failed_candidate_stays_failed_in_successfully_packaged_run(tmp_path):
    artifacts = prepared(tmp_path, "nodegoat")
    report = artifacts / "nodegoat-validation-batch-1/validation/batch-1.json"
    data = evidence.read(report)
    data.update(result="failed", checks=[evidence.check("login", False, "regression")])
    evidence.write(report, data)
    out = tmp_path / "out"
    manifest = evidence.package("nodegoat", artifacts, out, METADATA, {**OUTCOMES, "validate": "failure"})
    assert manifest["stages"]["validate"] == "failed"
    assert evidence.read(out / "validation/batch-1.json")["result"] == "failed"
    assert_contract(manifest, out)


def test_initial_scan_policy_and_execution_logs_survive_packaging(tmp_path):
    artifacts = prepared(tmp_path, "nodegoat")
    scan = artifacts / "nodegoat-scan-results"
    status = {"scan_kind": "initial", "commit_sha": SHA,
              "scan_policy": {"sca_manifest": "package.json", "snyk_version": "1.1305.2"},
              "scans": {kind: {"status": "completed"} for kind in ("sast", "sca", "container")}}
    evidence.write(scan / "scan-status.json", status)
    (scan / "npm-version.log").write_text("8.19.4\n", encoding="utf-8")
    (scan / "snyk-version.log").write_text("1.1305.2\n", encoding="utf-8")
    out = tmp_path / "out"
    manifest = evidence.package("nodegoat", artifacts, out, METADATA, OUTCOMES)
    assert evidence.read(out / manifest["artifacts"]["scan_status"]) == status
    assert set(manifest["artifacts"]["scan_logs"]) == {"scan/npm-version.log", "scan/snyk-version.log"}
    assert (out / "scan/npm-version.log").read_text() == "8.19.4\n"
    assert_contract(manifest, out)


@pytest.mark.parametrize("failure", ["missing", "malformed", "wrong-sha", "invalid-result"])
def test_unusable_validation_is_never_reported_as_passed(tmp_path, failure):
    artifacts = prepared(tmp_path, "pygoat")
    report = artifacts / "pygoat-validation-batch-1/validation/batch-1.json"
    if failure == "missing":
        report.unlink()
    elif failure == "malformed":
        report.write_text("{", encoding="utf-8")
    else:
        data = evidence.read(report)
        data["commit_sha" if failure == "wrong-sha" else "result"] = "invalid"
        evidence.write(report, data)
    out = tmp_path / "out"
    manifest = evidence.package("pygoat", artifacts, out, METADATA, OUTCOMES)
    assert manifest["stages"]["validate"] == "failed"
    assert evidence.read(out / "validation/batch-1.json")["evidence_available"] is False
    assert_contract(manifest, out)


def test_early_failure_has_required_placeholder_and_explicit_unavailable_status(tmp_path):
    out = tmp_path / "out"
    manifest = evidence.package("pygoat", tmp_path / "no-artifacts", out, METADATA,
        {"baseline": "failure", "scan": "skipped", "fix": "skipped", "validate": "skipped"})
    assert_contract(manifest, out)
    assert evidence.read(out / manifest["artifacts"]["findings"]) == []
    assert manifest["artifact_status"]["findings"] == "not_available"
    assert set(manifest["stages"].values()) == {"not_available"}
    assert manifest["job_outcomes"]["baseline"] == "failure"
    assert manifest["evidence_errors"]
    assert "remediation" not in manifest["artifacts"]


@pytest.mark.parametrize("relative,failed_stage", [
    ("findings/ranked_unified_findings.json", "normalise"),
    ("findings/ranked_findings.json", "triage"), ("fixes.json", "fix")])
def test_malformed_processing_output_still_publishes_failure_evidence(tmp_path, relative, failed_stage):
    artifacts = prepared(tmp_path, "pygoat")
    (artifacts / "pygoat-fix-output" / relative).write_text("{", encoding="utf-8")
    out = tmp_path / "out"
    manifest = evidence.package("pygoat", artifacts, out, METADATA, OUTCOMES)
    assert manifest["stages"][failed_stage] == "failed"
    assert manifest["evidence_errors"]
    assert_contract(manifest, out)


def test_baseline_is_published_only_for_the_scanned_source(tmp_path):
    artifacts = prepared(tmp_path, "pygoat")
    report = {"commit_sha": SHA, "result": "failed", "app_started": True,
              "checks": [evidence.check("static assets", False, "HTTP 404")]}
    evidence.write(artifacts / "pygoat-baseline-123-1/pygoat-baseline.json", report)
    out = tmp_path / "out"
    manifest = evidence.package("pygoat", artifacts, out, METADATA, OUTCOMES)
    assert manifest["baseline_status"] == "failed"
    assert evidence.read(out / manifest["artifacts"]["baseline_validation"]) == report
    report["commit_sha"] = "stale"
    evidence.write(artifacts / "pygoat-baseline-123-1/pygoat-baseline.json", report)
    other = evidence.package("pygoat", artifacts, tmp_path / "other", METADATA, OUTCOMES)
    assert "baseline_validation" not in other["artifacts"]


def test_after_fix_link_and_initial_default(tmp_path):
    artifacts = prepared(tmp_path, "nodegoat")
    manifest = evidence.package("nodegoat", artifacts, tmp_path / "out", METADATA, OUTCOMES,
                                scan_kind="after_fix", after_fix_of="122")
    assert manifest["scan_kind"] == "after_fix"
    assert manifest["after_fix_of"] == "122"
    with pytest.raises(ValueError):
        evidence.package("nodegoat", artifacts, tmp_path / "bad", METADATA, OUTCOMES,
                         scan_kind="after_fix", after_fix_of="123")


def test_only_referenced_files_publish_and_manifest_is_last_even_with_legacy(tmp_path):
    artifacts = prepared(tmp_path, "nodegoat")
    out = tmp_path / "out"
    evidence.package("nodegoat", artifacts, out, METADATA, OUTCOMES)
    calls = []
    evidence.upload(out, "nodegoat", "123", legacy=True, run=lambda args, **kw: calls.append(args),
                    account="account", container="container")
    names = [args[args.index("--name") + 1] for args in calls]
    assert names[-1] == "nodegoat/123/manifest.json"
    assert "nodegoat/sast-nodegoat-123-aaaaaaa.json" in names
    assert "nodegoat/123/remediation/fixes.json" in names
    assert all("account" in args and "container" in args for args in calls)


def test_upload_reads_storage_from_env_and_refuses_without_it(tmp_path, monkeypatch):
    artifacts = prepared(tmp_path, "pygoat")
    out = tmp_path / "out"
    evidence.package("pygoat", artifacts, out, METADATA, OUTCOMES)
    monkeypatch.delenv("ASVA_AZURE_STORAGE_ACCOUNT", raising=False)
    monkeypatch.delenv("ASVA_AZURE_STORAGE_CONTAINER", raising=False)
    with pytest.raises(ValueError):
        evidence.upload(out, "pygoat", "123", run=lambda args, **kw: None)
    monkeypatch.setenv("ASVA_AZURE_STORAGE_ACCOUNT", "envaccount")
    monkeypatch.setenv("ASVA_AZURE_STORAGE_CONTAINER", "envcontainer")
    calls = []
    evidence.upload(out, "pygoat", "123", run=lambda args, **kw: calls.append(args))
    assert calls and all("envaccount" in args and "envcontainer" in args for args in calls)


def test_upload_failure_prevents_manifest_publication(tmp_path):
    artifacts = prepared(tmp_path, "pygoat")
    out = tmp_path / "out"
    evidence.package("pygoat", artifacts, out, METADATA, OUTCOMES)
    calls = []
    def fail(args, **kwargs):
        calls.append(args)
        raise subprocess.CalledProcessError(1, "az")
    with pytest.raises(subprocess.CalledProcessError):
        evidence.upload(out, "pygoat", "123", run=fail, account="account", container="container")
    assert not any(args[args.index("--name") + 1].endswith("manifest.json") for args in calls)


def test_fix_collection_keeps_failures_and_uses_app_relative_diffs(tmp_path):
    for bid in ("opened", "failed"):
        evidence.write(tmp_path / f"batches/{bid}.json", {"batch_id": bid, "batch_type": "sast"})
    evidence.write(tmp_path / "prs.json", [
        {"batch_id": "opened", "status": "pr_opened", "branch": "fix/opened", "pr_url": "https://github.com/example/asva/pull/1"},
        {"batch_id": "failed", "status": "no_commits", "failed": [{"path": "x.py", "reason": "syntax error"}]}])
    def run(args, cwd=None):
        if args[1] == "rev-parse": return CANDIDATE
        if "--numstat" in args: return "2\t1\ttarget-apps/PyGoat/introduction/views.py\0"
        return "@@ -1 +1 @@\n-old\n+new\n"
    rows, matrix, errors = evidence.collect_fixes(tmp_path / "batches", tmp_path / "prs.json", ".", SHA,
        "pygoat", "success", run=run, metadata=lambda url: {"number": 1, "title": "Fix", "body": "Details"})
    assert not errors
    failed, opened = rows
    assert failed["status"] == "no_commits" and failed["failed"]
    assert opened["files"][0]["path"] == "introduction/views.py"
    assert opened["files"][0]["patch"].startswith("@@")
    assert opened["pr_number"] == opened["number"] == 1
    assert matrix[0]["sha"] == CANDIDATE
    assert opened["validation_path"] == "validation/opened.json"


@pytest.mark.parametrize("status", ["pr_opened", "error"])
def test_npm_generation_diagnostics_survive_collection_and_packaging(tmp_path, status):
    artifacts = prepared(tmp_path, "nodegoat")
    fix = artifacts / "nodegoat-fix-output"
    generation = {"method": "npm", "status": "generated" if status == "pr_opened" else "error",
        "npm_version": "8.19.4", "duration_seconds": 1.5,
        "upgrades": {"mongodb": {"from": "^2.1.18", "to": "3.1.13", "section": "dependencies"}},
        "unresolved": [{"finding_id": "unsupported", "reason": "No supported upgrade"}]}
    raw = {"batch_id": "batch-1", "status": status, "generation": generation,
           "branch": "fix/batch-1", "pr_url": "https://github.com/example/asva/pull/1"}
    if status == "error":
        raw["pr_url"] = None
    evidence.write(fix / "fix_batches/batch-1.json", {"batch_id": "batch-1", "batch_type": "sca"})
    evidence.write(fix / "prs.json", [raw])
    rows, matrix, errors = evidence.collect_fixes(fix / "fix_batches", fix / "prs.json", ".", SHA,
        "nodegoat", "success", run=lambda args, cwd=None: CANDIDATE if "rev-parse" in args else "",
        metadata=lambda url: {"number": 1, "title": "Dependencies", "body": "npm"})
    assert not errors
    assert rows[0]["generation"] == generation
    assert bool(matrix) == (status == "pr_opened")
    evidence.write(fix / "fixes.json", rows)
    evidence.package("nodegoat", artifacts, tmp_path / "package", METADATA, OUTCOMES)
    assert evidence.read(tmp_path / "package/remediation/fixes.json")[0]["generation"] == generation


@pytest.mark.parametrize("started,build,smoke", [(False, "failure", "skipped"), (True, "success", "failure")])
def test_validation_fails_closed_for_startup_or_missing_smoke(tmp_path, started, build, smoke):
    result = evidence.validation(app="nodegoat", batch_id="batch", pr_url="pr", sha=CANDIDATE,
        started=started, build_result=build, smoke_result=smoke, smoke_xml=str(tmp_path / "missing.xml"))
    assert result["result"] == "failed"
    assert all(evidence.valid_check(c) for c in result["checks"])


def test_comment_authentication_failure_does_not_erase_candidate_results(tmp_path):
    xml = tmp_path / "smoke.xml"
    xml.write_text('<testsuite><testcase name="login"/></testsuite>', encoding="utf-8")
    result = evidence.validation(app="nodegoat", batch_id="batch", pr_url="pr", sha=CANDIDATE,
        started=True, build_result="success", smoke_result="success", smoke_xml=str(xml), comment_result="failure")
    assert result["result"] == "passed"
    assert result["reporting"]["pr_comment"] == "failure"


def test_partial_generation_remains_failed_evidence_even_if_a_pr_was_opened(tmp_path):
    evidence.write(tmp_path / "batches/partial.json", {"batch_id": "partial", "batch_type": "sast"})
    generation = {"method": "llm", "status": "partial", "message": "Generated 1/2 requested files",
                  "files": [{"path": "missing.py", "status": "empty_or_truncated"}]}
    evidence.write(tmp_path / "prs.json", [{"batch_id": "partial", "status": "pr_opened", "branch": "fix/partial",
        "pr_url": "https://example.test/pr/1", "generation": generation}])
    rows, matrix, errors = evidence.collect_fixes(tmp_path / "batches", tmp_path / "prs.json", ".", SHA,
        "pygoat", "failure", run=lambda args, cwd=None: CANDIDATE if "rev-parse" in args else "",
        metadata=lambda url: {"number": 1, "title": "Partial", "body": "Incomplete"})
    assert rows[0]["generation"] == generation and matrix[0]["sha"] == CANDIDATE
    assert errors == ["partial"]


def test_missing_expected_security_report_cannot_pass(tmp_path):
    xml = tmp_path / "smoke.xml"
    xml.write_text('<testsuite><testcase name="login"/></testsuite>', encoding="utf-8")
    matched = tmp_path / "matched.json"
    evidence.write(matched, {"matched_tests": [{"name": "security"}]})
    result = evidence.validation(app="nodegoat", batch_id="batch", pr_url="pr", sha=CANDIDATE,
        started=True, build_result="success", smoke_result="success", smoke_xml=str(xml),
        matched_json=str(matched), selection_required=True, misuse_xml=str(tmp_path / "missing.xml"))
    assert result["result"] == "failed"
    assert any(c["kind"] == "misuse" and c["status"] == "failed" for c in result["checks"])


def scoped_validation(tmp_path, cases, matched, misuse_result="failure"):
    smoke = tmp_path / "smoke.xml"
    smoke.write_text('<testsuite><testcase name="login"/></testsuite>', encoding="utf-8")
    misuse = tmp_path / "misuse.xml"
    misuse.write_text("<testsuite>" + "".join(
        f'<testcase name="{name}">' + ('<failure message="still works"/>' if failed else "") + "</testcase>"
        for name, failed in cases) + "</testsuite>", encoding="utf-8")
    evidence.write(tmp_path / "matched.json", {"matched_tests": matched})
    return evidence.validation(app="nodegoat", batch_id="batch", pr_url="pr", sha=CANDIDATE,
        started=True, build_result="success", smoke_result="success", smoke_xml=str(smoke),
        matched_json=str(tmp_path / "matched.json"), selection_required=True,
        misuse_xml=str(misuse), misuse_result=misuse_result)


def test_untargeted_security_case_is_reported_but_cannot_fail_candidate(tmp_path):
    result = scoped_validation(tmp_path, [("test_redirect", False), ("test_idor", True)],
        [{"test_name": "test_redirect", "attempted": True}, {"test_name": "test_idor", "attempted": False}])
    assert result["result"] == "passed"
    assert [c["name"] for c in result["checks"] if c["kind"] == "misuse"] == ["test_redirect"]
    assert result["out_of_scope_checks"] == [{"name": "test_idor", "kind": "misuse", "status": "failed",
        "detail": "still works", "scope": "not_targeted_by_batch"}]


@pytest.mark.parametrize("matched", [
    [{"test_name": "test_redirect", "attempted": True}],
    [{"test_name": "test_redirect"}],  # selection without the flag stays in scope
])
def test_targeted_security_failure_still_fails_candidate(tmp_path, matched):
    result = scoped_validation(tmp_path, [("test_redirect", True)], matched)
    assert result["result"] == "failed" and "out_of_scope_checks" not in result
    assert not any(c["name"] == "security test execution completes" for c in result["checks"])


def test_unexplained_security_step_failure_still_fails_candidate(tmp_path):
    result = scoped_validation(tmp_path, [("test_redirect", False)],
        [{"test_name": "test_redirect", "attempted": True}], misuse_result="failure")
    assert result["result"] == "failed"
    assert any(c["name"] == "security test execution completes" for c in result["checks"])


def test_scan_exit_one_is_successful_evidence_but_exit_two_is_not(tmp_path, monkeypatch):
    for kind in ("sast", "sca", "container"):
        evidence.write(tmp_path / f"{kind}.sarif.json", {"runs": [{"results": []}]})
        monkeypatch.setenv(kind.upper() + "_EXIT", "1")
    assert evidence.scan_status("pygoat", tmp_path)
    monkeypatch.setenv("SCA_EXIT", "2")
    assert not evidence.scan_status("pygoat", tmp_path)
    assert evidence.read(tmp_path / "scan-status.json")["scans"]["sca"]["status"] == "failed"


def test_identifiers_cannot_escape_destination():
    for value in ("../bad", "x/y", "..", "x\nother"):
        with pytest.raises(ValueError):
            evidence.identifier(value)
