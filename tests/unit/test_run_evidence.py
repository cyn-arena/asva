"""Offline evidence integrity checks; GitHub, Docker, scanners and AI are mocked."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.unit


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


manifest = load("build-run-manifest")
collector = load("collect-run-evidence")
fallback = load("record-candidate-failure")
junit = load("junit-validation")


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def test_failed_run_publishes_honest_manifest_without_fake_findings(tmp_path):
    result = manifest.make_manifest(tmp_path, "pygoat", "123", "a" * 40,
                                    {"scan": "failure", "fix": "skipped", "validate": "skipped"})
    assert result["stages"]["scan"] == "failed"
    assert result["stages"]["fix"] == "skipped"
    assert "findings" not in result["artifacts"]
    assert result["scan_kind"] == "initial"
    assert (tmp_path / "manifest.json").exists()


def test_baseline_and_actual_processing_outcomes_are_referenced(tmp_path):
    write(tmp_path / "validation/baseline.json", {"commit_sha": "a" * 40, "result": "passed"})
    write(tmp_path / "stage-status.json", {"normalise": "success", "triage": "failure"})
    result = manifest.make_manifest(tmp_path, "pygoat", "123", "a" * 40,
                                    {"baseline": "success", "normalise": "failure", "triage": "failure"})
    assert result["stages"]["normalise"] == "completed"
    assert result["stages"]["triage"] == "failed"
    assert result["artifacts"]["baseline_validation"] == "validation/baseline.json"
    assert manifest.read(tmp_path / "validation/baseline.json")["phase"] == "baseline"


def test_rejects_scan_evidence_from_another_commit(tmp_path):
    write(tmp_path / "scan/scan-status.json", {"run_id": "123", "commit_sha": "b" * 40})
    with pytest.raises(ValueError, match="commit"):
        manifest.make_manifest(tmp_path, "pygoat", "123", "a" * 40, {"scan": "success"})


def test_validation_must_match_the_fix_candidate(tmp_path):
    write(tmp_path / "remediation/fixes.json", [{"batch_id": "batch", "candidate_sha": "b" * 40}])
    write(tmp_path / "validation/batch.json", {"tested_sha": "c" * 40, "result": "passed"})
    with pytest.raises(ValueError, match="candidate commit"):
        manifest.make_manifest(tmp_path, "pygoat", "123", "a" * 40, {})


def test_after_fix_record_keeps_candidate_sha_and_parent_link(tmp_path):
    result = manifest.make_manifest(tmp_path, "pygoat", "123-after-fix-batch", "b" * 40,
                                    {"scan": "success", "validate": "failure"},
                                    scan_kind="after_fix", after_fix_of="123")
    assert result["commit_sha"] == "b" * 40
    assert result["after_fix_of"] == "123"
    assert result["stages"]["validate"] == "failed"


def test_candidate_setup_failure_is_visible_and_does_not_overwrite_finished_check(tmp_path):
    fallback.record("pygoat", "batch", "b" * 40, tmp_path)
    report = manifest.read(tmp_path / "validation/batch.json")
    assert report["result"] == "failed" and report["app_started"] is False
    assert report["misuse_tests"] == "not_available"
    before = (tmp_path / "candidates/batch/candidate.json").read_bytes()
    fallback.record("pygoat", "batch", "c" * 40, tmp_path)
    assert (tmp_path / "candidates/batch/candidate.json").read_bytes() == before


def test_passing_junit_does_not_invent_app_readiness_or_misuse_coverage(tmp_path):
    path = tmp_path / "smoke.xml"
    path.write_text('<testsuite><testcase name="login"/></testsuite>')
    result = junit.convert([("smoke", path)], "nodegoat", "a" * 40)
    assert result["result"] == "failed" and result["app_started"] is False
    result = junit.convert([("smoke", path)], "nodegoat", "a" * 40, app_started=True)
    assert result["result"] == "passed" and result["misuse_tests"] == "not_available"


def test_collector_uses_latest_producing_attempt_and_all_pages(tmp_path, monkeypatch):
    def artifact(name, number, created, expired=False):
        return dict(name=name, id=number, created_at=created, expired=expired)
    pages = [{"artifacts": [artifact("pygoat-scan-123-1", 1, "01"),
                             artifact("pygoat-dashboard-123-2", 2, "02")]},
             {"artifacts": [artifact("pygoat-scan-123-2", 3, "03"),
                             artifact("pygoat-review-123-1", 4, "01"),
                             artifact("pygoat-review-123-3", 5, "04", True)]}]
    monkeypatch.setattr(collector, "gh_json", lambda *args: pages)
    downloaded = []
    def download(command, **kwargs):
        name = command[command.index("--name") + 1]
        downloaded.append(name)
        directory = Path(command[-1])
        directory.mkdir(parents=True)
        (directory / "test.json").write_text("{}")
    monkeypatch.setattr(collector.subprocess, "run", download)
    collector.collect("pygoat", "example/asva", "123", tmp_path / "evidence")
    assert downloaded == ["pygoat-scan-123-2", "pygoat-review-123-1"]


def test_python_prompt_and_exact_scan_branch(monkeypatch):
    from agent.agent_loop import build_fix_prompt
    from gitops import git_gh_ops
    from gitops import config
    monkeypatch.setenv("ASVA_APP_LANGUAGE", "python")
    monkeypatch.setattr(config, "FIX_PATH_PREFIX", "target-apps/PyGoat")  # independent of .env
    assert "Python/Django" in build_fix_prompt("views.py", "pass", [], "code_change")
    commands = []
    monkeypatch.setenv("ASVA_SCANNED_SHA", "a" * 40)
    monkeypatch.setattr(git_gh_ops, "_run", lambda command, *args: commands.append(command))
    git_gh_ops.create_branch("fix/test", "feat/app-types")
    assert commands[-1] == ["git", "switch", "-C", "fix/test", "a" * 40]


def test_full_candidate_layout_has_independent_manifest(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    source = tmp_path / "evidence"
    write(source / "candidates/batch/candidate.json", {"commit_sha": "b" * 40,
          "outcomes": {"scan": "failure", "validate": "failure"}})
    output = tmp_path / "dashboard"
    subprocess.run([sys.executable, str(ROOT / "scripts/build-run-manifest.py"), "--app", "pygoat",
                    "--input-dir", str(source), "--output-dir", str(output), "--outcomes", '{"scan":"failure"}'], check=True)
    child = manifest.read(output / "pygoat/123-after-fix-batch/manifest.json")
    assert child["commit_sha"] == "b" * 40 and child["after_fix_of"] == "123"
    assert manifest.read(output / "pygoat/123/manifest.json")["scan_kind"] == "initial"


def test_agent_failure_keeps_selected_and_unattempted_batch_outcomes(tmp_path, monkeypatch):
    runner = load("run-fix-stage")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GITHUB_REF_NAME", "feat/app-types")
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    batch_dir = tmp_path / "batches"
    for name in ("first", "second"):
        write(batch_dir / (name + ".json"), {"batch_id": name})
    monkeypatch.setattr(sys, "argv", ["run-fix-stage", "--app", "pygoat", "--batch-dir", str(batch_dir)])
    monkeypatch.setattr(runner.subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(args, 2))
    assert runner.main() == 2
    results = manifest.read(tmp_path / "asva-results/remediation/fixes.json")
    assert [(r["batch_id"], r["status"]) for r in results] == [("first", "failed"), ("second", "not_attempted")]


@pytest.mark.parametrize("target_still_present", [True, False])
def test_candidate_requires_targeted_findings_to_disappear(tmp_path, monkeypatch, target_still_present):
    """Exercise the full candidate checker with real SARIF and normalisation, mocked services."""
    from normaliser.normaliser import process_sarif_file
    candidate = load("check-fix-candidate")
    events = []
    monkeypatch.setattr(candidate, "capture_compose_diagnostics", lambda *args: events.append("capture"))
    fixtures = ROOT / "tests/fixtures/sarif"
    target = process_sarif_file(fixtures / "sast_sample.sarif.json")[0]
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    monkeypatch.setattr(sys, "argv", ["check-fix-candidate", "--batch-id", "batch", "--sha", "b" * 40])
    write(tmp_path / "asva-results/remediation/fix_batches/batch.json", {"files_to_fix": [{"findings": [target]}]})
    scans = tmp_path / "asva-results/candidates/batch/scan"
    monkeypatch.setattr(candidate.subprocess, "check_output", lambda *args, **kwargs: "b" * 40)
    real_run = subprocess.run
    def command(args, cwd=None):
        if args[-2:] == ["down", "-v"]:
            events.append("teardown")
        if args[0] == sys.executable and args[1] == "scripts/pygoat-smoke.py":
            write(Path(args[-1]), {"checks": [{"name": "login", "kind": "smoke", "status": "passed"}]})
        elif args[0] == "snyk" or args[0:2] == ["docker", "run"]:
            kind = "sast" if args[0:3] == ["snyk", "code", "test"] else "sca" if args[0] == "docker" else "container"
            data = json.loads((fixtures / (kind + "_sample.sarif.json")).read_text(encoding="utf-8"))
            if kind == "sast" and not target_still_present:
                for run in data["runs"]:
                    run["results"] = []
            write(scans / (kind + ".sarif.json"), data)
        elif args[0] == sys.executable and args[1] == "normaliser/normaliser.py":
            args[1] = str(ROOT / args[1])
            return real_run(args, capture_output=True).returncode
        return 0
    monkeypatch.setattr(candidate, "command", command)
    assert candidate.main() == (1 if target_still_present else 0)
    report = manifest.read(tmp_path / "asva-results/validation/batch.json")
    assert report["tested_sha"] == "b" * 40
    assert report["result"] == ("failed" if target_still_present else "passed")
    assert report["misuse_tests"] == "not_available"
    assert events == ["capture", "teardown"]
