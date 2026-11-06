"""Regression coverage for comparable scans and consistent dashboard/PR evidence."""
import json
from pathlib import Path
import subprocess
import sys

import pytest
from jsonschema import ValidationError

from normaliser.normaliser import dependency_severity, parse_help_upgrade, process_sarif_file
from gitops.post_pr_check_comment import format_validation_comment
from tests.unit.test_run_evidence import load, write, ROOT

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("text,package,current,expected", [
    ("# Remediation\nUpgrade `PyYAML` to version 5.3.1 or higher.\n# References\nother", "pyyaml", "5.3", "pyyaml@5.3.1"),
    ("# Remediation\nUpgrade Django to version 3.2.25, 4.2.11, 5.0.3 or higher.", "Django", "4.2.0", "Django@4.2.11"),
    ("# Remediation\nThere is no fixed version.\n# References\nUpgrade PyYAML to version 5.3.1", "PyYAML", "5.3", None),
    ("# Overview\nUpgrade PyYAML to version 5.3.1", "PyYAML", "5.3", None),
    ("# Remediation\nUpgrade other to version 5.3.1", "PyYAML", "5.3", None),
    ("# Remediation\nUpgrade PyYAML to version 5.3.1", "PyYAML", "6.0", None),
])
def test_remediation_help_fallback(text, package, current, expected):
    assert parse_help_upgrade(text, package, current) == (expected is not None, expected)


def test_dependency_rating_preserved_and_score_fallback_available():
    assert dependency_severity({"shortDescription": {"text": "Low severity - example"}}, {}, "error", 9.8) == "low"
    assert dependency_severity({"properties": {"severity": "critical"}}, {}, "note", 2.0) == "critical"
    assert dependency_severity({}, {}, "warning", 9.8) == "critical"


def test_pip_rule_without_result_fixes_produces_fixable_upgrade(tmp_path):
    data = json.loads((ROOT / "tests/fixtures/sarif/sca_sample.sarif.json").read_text(encoding="utf-8"))
    run = data["runs"][0]
    run["results"] = [run["results"][0]]
    result = run["results"][0]
    result.pop("fixes", None)
    result["locations"][0]["logicalLocations"][0]["fullyQualifiedName"] = "PyYAML@5.3"
    rule = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == result["ruleId"])
    rule["help"] = {"markdown": "# Remediation\nUpgrade `PyYAML` to version 5.3.1 or higher."}
    path = tmp_path / "pip.sarif.json"
    write(path, data)
    assert process_sarif_file(path)[0]["remediation"] == {"type": "version_upgrade", "fixable": True, "upgrade_to": "PyYAML@5.3.1"}


def test_batch_limit_covers_types_and_preserves_fallback_batch_type(tmp_path, monkeypatch):
    runner = load("run-fix-stage")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GITHUB_REF_NAME", "feat/app-types")
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    batches = []
    for name, kind in (("sast1", "sast"), ("sast2", "sast"), ("sca", "sca"), ("container", "container")):
        path = tmp_path / "batches" / (name + ".json")
        write(path, {"batch_id": name, "batch_type": kind})
        batches.append(path)
    assert [p.stem for p in runner.select_batches(batches, 3)] == ["sast1", "sca", "container"]
    monkeypatch.setattr(sys, "argv", ["runner", "--app", "nodegoat", "--batch-dir", str(tmp_path / "batches"), "--max-batches", "3"])
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 2))
    assert runner.main() == 2
    rows = json.loads(Path("asva-results/remediation/fixes.json").read_text())
    assert {r["batch_type"] for r in rows if r["status"] == "failed"} == {"sast", "sca", "container"}
    assert next(r for r in rows if r["status"] == "not_attempted")["batch_type"] == "sast"


def test_skipped_tests_and_pr_comment_use_identical_checks(tmp_path):
    junit = load("junit-validation")
    path = tmp_path / "smoke.xml"
    path.write_text('<testsuite><testcase name="login"/><testcase name="optional"><skipped message="not applicable"/></testcase><testcase name="broken"><failure message="bad"/></testcase></testsuite>')
    report = junit.convert([("smoke", path)], "nodegoat", "b" * 40, app_started=True)
    assert report["checks"][2]["status"] == "skipped"
    assert report["checks"][1]["detail"] is None
    report["checks"].append({"name": "targeted scanner findings", "kind": "security_scan", "status": "failed", "detail": "still present"})
    comment = format_validation_comment(report)
    assert "5 checks: 2 passed, 2 failed, 1 skipped" in comment
    assert all(c["name"] in comment for c in report["checks"])


def test_candidate_timestamp_not_parent_and_early_failure_type(tmp_path, monkeypatch):
    manifest = load("build-run-manifest")
    monkeypatch.setenv("RUN_CREATED_AT", "2026-10-11T03:19:13Z")
    parent = manifest.make_manifest(tmp_path / "parent", "nodegoat", "123", "a" * 40, {})
    child = manifest.make_manifest(tmp_path / "child", "nodegoat", "123-after-fix-test", "b" * 40, {}, scan_kind="after_fix", after_fix_of="123", created_at="2026-10-11T03:25:00Z")
    assert parent["created_at"] < child["created_at"]
    root = tmp_path / "failed"
    write(root / "remediation/fix_batches/test.json", {"batch_id": "test", "batch_type": "sca", "scan_run_id": "123", "commit_sha": "aaaaaaaa", "files_to_fix": []})
    # Avoid the unrelated batch contract: inspect fallback generation before its validation.
    with pytest.raises(ValidationError):
        manifest.make_manifest(root, "nodegoat", "123", "a" * 40, {"fix": "failure"})
    assert json.loads((root / "remediation/fixes.json").read_text())[0]["batch_type"] == "sca"


@pytest.mark.parametrize("installed", [True, False])
def test_nodegoat_installs_before_sast_and_fails_closed(tmp_path, monkeypatch, installed):
    candidate = load("check-fix-candidate")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    monkeypatch.setattr(sys, "argv", ["candidate", "--app", "nodegoat", "--batch-id", "test", "--sha", "b" * 40])
    write(tmp_path / "asva-results/remediation/fix_batches/test.json", {"files_to_fix": []})
    write(tmp_path / "asva-results/validation/test.json", {"app_started": True, "checks": [{"name": "login", "kind": "smoke", "status": "passed"}]})
    def output(args, **kwargs):
        return "b" * 40 if args[0] == "git" else json.dumps({"services": {"mongo": {"image": "mongo:4.4"}}})
    monkeypatch.setattr(candidate.subprocess, "check_output", output)
    commands = []
    def command(args, cwd=None):
        commands.append(args)
        if args[0] == "npm":
            return 0 if installed else 1
        if args[0] == "snyk":
            kind = "sast" if args[1] == "code" else "container" if args[1] == "container" else "sca"
            # Retain the complete source fixture, including node_modules findings.
            write(tmp_path / f"asva-results/candidates/test/scan/{kind}.sarif.json", json.loads((ROOT / f"tests/fixtures/sarif/{kind}_sample.sarif.json").read_text(encoding="utf-8")))
        if args[0] == sys.executable:
            write(tmp_path / "asva-results/candidates/test/findings/ranked_unified_findings.json", [])
        return 0
    monkeypatch.setattr(candidate, "command", command)
    assert candidate.main() == (0 if installed else 1)
    assert commands[0] == ["npm", "install", "--ignore-scripts"]
    if installed:
        assert commands[1][:3] == ["snyk", "code", "test"]
        findings = process_sarif_file(tmp_path / "asva-results/candidates/test/scan/sast.sarif.json")
        assert any(f["is_node_modules"] for f in findings)
    else:
        assert not any(c[:3] == ["snyk", "code", "test"] for c in commands)
        assert not any(c[0] == sys.executable for c in commands)


def test_collector_retains_only_canonical_baseline(tmp_path, monkeypatch):
    collector = load("collect-run-evidence")
    artifact = {"name": "pygoat-validation-123-1", "id": 1, "created_at": "now", "expired": False}
    monkeypatch.setattr(collector, "gh_json", lambda *a: [{"artifacts": [artifact]}])
    def download(args, **kwargs):
        directory = Path(args[-1])
        write(directory / "pygoat-validation.json", {"result": "passed"})
    monkeypatch.setattr(collector.subprocess, "run", download)
    collector.collect("pygoat", "example/asva", "123", tmp_path / "evidence")
    assert (tmp_path / "evidence/validation/baseline.json").exists()
    assert not (tmp_path / "evidence/validation/pygoat-validation.json").exists()


@pytest.mark.parametrize("timeout", [False, True])
def test_container_diagnostics_preserve_tracebacks_and_collection_errors(tmp_path, monkeypatch, timeout):
    candidate = load("check-fix-candidate")
    commands = []
    compose = ["docker", "compose", "-f", "compose.asva.yml"]
    def run(args, **kwargs):
        commands.append(args)
        assert kwargs["stderr"] == subprocess.STDOUT
        kwargs["stdout"].write("exited container\n" if "ps" in args else "Traceback: missing log_function_checker\n")
        if timeout and "logs" in args:
            raise subprocess.TimeoutExpired(args, 30)
        return subprocess.CompletedProcess(args, 0 if "ps" in args else 1)
    monkeypatch.setattr(candidate.subprocess, "run", run)
    candidate.capture_compose_diagnostics(compose, tmp_path / "validation")
    assert commands == [[*compose, "ps", "--all"], [*compose, "logs", "--no-color", "--tail", "200"]]
    log = (tmp_path / "validation/pygoat-container.log").read_text()
    assert "missing log_function_checker" in log
    assert ("Could not complete diagnostics" if timeout else "Diagnostic command exit code: 1") in log
    assert "exited container" in (tmp_path / "validation/pygoat-container-status.log").read_text()
