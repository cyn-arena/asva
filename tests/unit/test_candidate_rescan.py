"""Offline candidate evidence flow: no Docker, scanner, AI, GitHub or Azure calls."""
from pathlib import Path
import json
import tempfile
import subprocess

import pytest

from scripts.candidate_rescan import rescan
from scripts import dashboard_evidence as evidence

pytestmark = pytest.mark.unit
SHA = "b" * 40
META = {"id": 123, "head_sha": "a" * 40, "head_branch": "feat/test", "name": "Pipeline",
        "created_at": "2026-10-17T00:00:00Z", "html_url": "https://example.test/run/123"}
ROW = {"batch_id": "batch-1", "candidate_sha": SHA, "pr_url": "https://example.test/pr/1", "branch": "fix/one"}


@pytest.fixture
def source(tmp_path, monkeypatch):
    app = tmp_path / "candidate"
    app.mkdir()
    (app / "requirements.txt").write_text("Django==3.0", encoding="utf-8")
    (app / "package.json").write_text('{"dependencies":{}}', encoding="utf-8")
    (app / "package-lock.json").write_text('{"lockfileVersion":2}', encoding="utf-8")
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    return app


def scan(source, out, *, ecosystem="pip", failure=None, **options):
    calls = []

    def run(args, cwd, log):
        calls.append((args, cwd))
        log.write_text("scanner diagnostics", encoding="utf-8")
        if args == ["snyk", "--version"]:
            pinned = Path(__file__).parents[2] / "scripts/snyk-version.txt"
            log.write_text("0.0.0" if failure == "snyk-version" else pinned.read_text().strip().lstrip("v"))
            return 0
        if args == ["npm", "--version"]:
            log.write_text("8.19.4", encoding="utf-8")
            return 0
        if args[:2] == ["docker", "build"]:
            return 1 if failure == "image-build" else 0
        if args[:2] == ["npm", "ci"]:
            assert Path(cwd) != source
            return 1 if failure == "install" else 0
        kind = "sca" if "asva-sca" in args or "--package-manager=pip" in args or args[:2] == ["snyk", "test"] else "sast" if "code" in args else "container"
        if failure and failure.startswith("sca-no-report-") and kind == "sca":
            return int(failure.rsplit("-", 1)[1])  # e.g. pip install failed before Snyk ran
        results = [{"ruleId": "bad", "locations": [None]}] if failure == "extraction" and kind == "sast" else []
        (out / f"{kind}.sarif.json").write_text(json.dumps({"runs": [{"results": results}]}), encoding="utf-8")
        return 2 if failure == kind else 1  # A scanner exit of 1 means findings, not an execution failure.

    options.setdefault("python_image", "python:9-slim")
    report = rescan(app="pygoat" if ecosystem == "pip" else "nodegoat", app_path=source, sha=SHA,
        batch_id=ROW["batch_id"], pr_url=ROW["pr_url"], run_id="123", output=out, ecosystem=ecosystem,
        manifest="requirements.txt" if ecosystem == "pip" else "package.json", container_file="Dockerfile",
        container_mode="application", run=run, verify_source=lambda path, sha: source, **options)
    return report, calls


@pytest.mark.parametrize("ecosystem", ["npm", "pip"])
def test_complete_rescan_is_linked_and_does_not_mutate_candidate(source, tmp_path, ecosystem):
    before = {p.name: p.read_bytes() for p in source.iterdir()}
    report, calls = scan(source, tmp_path / "scan", ecosystem=ecosystem)
    assert report["commit_sha"] == SHA and report["after_fix_of"] == "123"
    assert report["findings_status"] == "completed"
    assert all(row["status"] == "completed" for row in report["scans"].values())
    assert before == {p.name: p.read_bytes() for p in source.iterdir()}
    assert not any("compose" in args or "up" in args or "agent_loop" in args for args, _ in calls)
    if ecosystem == "pip":
        dependency = next(args for args, _ in calls if "--package-manager=pip" in args)
        assert "--entrypoint" in dependency and "/opt/asva-snyk" in dependency
        assert report["dependency_install"]["scope"] == "candidate image"


@pytest.mark.parametrize("failure,ecosystem,unavailable", [
    ("image-build", "pip", "container"), ("install", "npm", "sca"), ("sast", "pip", "sast"),
])
def test_partial_scans_survive_build_install_and_scanner_failures(source, tmp_path, failure, ecosystem, unavailable):
    out = tmp_path / "scan"
    report, calls = scan(source, out, ecosystem=ecosystem, failure=failure)
    assert report["scans"][unavailable]["status"] != "completed"
    assert report["findings_status"] == "partial"
    assert sum(s["status"] == "completed" for s in report["scans"].values()) == 2
    assert evidence.read(out / "findings/ranked_unified_findings.json") == []
    if failure == "image-build":
        assert report["dependency_install"]["scope"] == "dependency-only fallback"


@pytest.mark.parametrize("code,reason", [(1, "did not produce valid SARIF"), (2, "exited with code 2")])
def test_failed_dependency_scan_keeps_exit_code_and_points_to_log(source, tmp_path, code, reason):
    report, _ = scan(source, tmp_path / "scan", failure=f"sca-no-report-{code}")
    sca = report["scans"]["sca"]
    assert sca["status"] == "failed" and sca["exit_code"] == code
    assert reason in sca["detail"] and "sca.log" in sca["detail"]
    assert "No such file" not in sca["detail"]
    assert report["findings_status"] == "partial"


def test_wrong_candidate_sha_prevents_scanning(tmp_git_repo, tmp_path):
    def unexpected(*args):
        raise AssertionError("Scanner must not run against the wrong checkout")
    report = rescan(app="nodegoat", app_path=tmp_git_repo, sha=SHA, batch_id="batch-1", pr_url="pr",
        run_id="123", output=tmp_path / "scan", ecosystem="npm", manifest="package.json",
        container_file="Dockerfile", container_mode="application", run=unexpected)
    assert report["source_verified"] is False
    assert "SHA mismatch" in report["source_error"]
    assert all(s["status"] == "not_available" for s in report["scans"].values())


def test_stale_output_is_rejected_before_any_scan(source, tmp_path):
    out = tmp_path / "scan"
    scan(source, out)
    with pytest.raises(ValueError, match="stale reports"):
        scan(source, out)


def test_initial_and_candidate_npm_scans_share_policy_and_leave_source_unchanged(source, tmp_path):
    before = {p.name: p.read_bytes() for p in source.iterdir()}
    initial, initial_calls = scan(source, tmp_path / "initial", ecosystem="npm", scan_kind="initial")
    candidate, candidate_calls = scan(source, tmp_path / "candidate-scan", ecosystem="npm")
    assert initial["scan_kind"] == "initial" and "after_fix_of" not in initial
    assert initial["run_id"] == "123"
    assert initial["scan_policy"] == candidate["scan_policy"]
    assert initial["npm_version"] == candidate["npm_version"] == "8.19.4"
    assert [args[:3] for args, _ in initial_calls] == [args[:3] for args, _ in candidate_calls]
    for calls in (initial_calls, candidate_calls):
        sast = next(i for i, (args, _) in enumerate(calls) if args[:3] == ["snyk", "code", "test"])
        install = next(i for i, (args, _) in enumerate(calls) if args[:2] == ["npm", "ci"])
        assert sast < install
        sca = next(args for args, _ in calls if args[:2] == ["snyk", "test"])
        assert "--file=package.json" in sca
    assert before == {p.name: p.read_bytes() for p in source.iterdir()}


def test_wrong_scanner_version_is_unavailable_not_a_clean_scan(source, tmp_path):
    report, calls = scan(source, tmp_path / "scan", failure="snyk-version")
    assert report["toolchain_error"]
    assert all(s["status"] == "not_available" for s in report["scans"].values())
    assert len(calls) == 1


def test_normalisation_failure_cannot_publish_silently_skipped_results_as_clean(source, tmp_path):
    folder, out = tmp_path / "scan", tmp_path / "package"
    report, _ = scan(source, folder, failure="extraction")
    assert report["normalise"] == "failed"
    assert report["findings_status"] == "not_available"
    result = evidence.candidate_package("pygoat", ROW, folder, out, META)
    manifest = evidence.read(out / "manifest.json")
    assert result["status"] == "failed"
    assert manifest["stages"]["normalise"] == "failed"
    assert manifest["artifact_status"]["findings"] == "not_available"


@pytest.mark.parametrize("failure", [None, "pull", "compose", "no-images"])
def test_third_party_image_resolution_reads_candidate_compose_not_tooling(source, tmp_path, monkeypatch, failure):
    from scripts import candidate_rescan
    (source / "docker-compose.yml").write_text("mongo:corrected", encoding="utf-8")
    original = tmp_path / "tooling/docker-compose.yml"
    original.parent.mkdir()
    original.write_text("mongo:original", encoding="utf-8")
    out = tmp_path / "scan"
    calls = []

    def compose(args, cwd, stdout, **kwargs):
        assert cwd == source
        assert args == ["docker", "compose", "-f", "docker-compose.yml", "-f", "docker-compose.pr-check.yml", "config", "--format", "json"]
        if failure == "compose":
            raise subprocess.CalledProcessError(1, "docker")
        services = {"web": {"build": {"context": "."}, "image": "not-a-third-party-image"}}
        if failure != "no-images":
            services["mongo"] = {"image": (Path(cwd) / "docker-compose.yml").read_text()}
        json.dump({"services": services}, stdout)

    def run(args, cwd, log):
        calls.append(args)
        log.write_text("8.19.4" if args == ["npm", "--version"] else "diagnostic", encoding="utf-8")
        if args == ["snyk", "--version"]:
            log.write_text((Path(__file__).parents[2] / "scripts/snyk-version.txt").read_text().strip().lstrip("v"))
            return 0
        if args[0] == "npm":
            return 0
        if args[:2] == ["docker", "pull"]:
            return 1 if failure == "pull" else 0
        kind = "sast" if "code" in args else "container" if "container" in args else "sca"
        evidence.write(out / f"{kind}.sarif.json", {"runs": [{"results": []}]})
        return 1

    monkeypatch.setattr(candidate_rescan.subprocess, "run", compose)
    report = rescan(app="nodegoat", app_path=source, sha=SHA, batch_id="batch-1", pr_url=ROW["pr_url"],
        run_id="123", output=out, ecosystem="npm", manifest="package.json", container_file="docker-compose.yml",
        container_mode="third-party", compose_files=["docker-compose.yml", "docker-compose.pr-check.yml"],
        run=run, verify_source=lambda *args: source)
    assert original.read_text() == "mongo:original"
    assert not (out / "compose.json").exists()
    if failure is None:
        assert ["snyk", "container", "test", "mongo:corrected", f"--sarif-file-output={out / 'container.sarif.json'}"] in calls
        assert report["findings_status"] == "completed"
    else:
        assert report["scans"]["container"]["status"] == "not_available"
        assert report["findings_status"] == "partial"
        assert not any(args[:2] == ["snyk", "container"] for args in calls)


def test_independent_candidates_have_distinct_runs_and_initial_findings_are_preserved(source, tmp_path):
    artifacts, output = tmp_path / "artifacts", tmp_path / "package"
    fix = artifacts / "pygoat-fix-output"
    original = [{"finding_id": "original"}]
    evidence.write(fix / "findings/ranked_unified_findings.json", original)
    rows = [{**ROW, "status": "pr_opened"}, {**ROW, "batch_id": "batch-2", "candidate_sha": "c" * 40,
                                            "pr_url": "https://example.test/pr/2", "status": "pr_opened"}]
    evidence.write(fix / "fixes.json", rows)
    for row in rows:
        folder = artifacts / f"pygoat-after-fix-{row['batch_id']}"
        report, _ = scan(source, folder)
        report.update(batch_id=row["batch_id"], commit_sha=row["candidate_sha"], pr_url=row["pr_url"])
        evidence.write(folder / "scan-status.json", report)
    manifest = evidence.package("pygoat", artifacts, output, META, {"scan": "failure", "validate": "failure"})
    assert evidence.read(output / manifest["artifacts"]["findings"]) == original
    candidates = manifest["candidate_scans"]
    assert len({c["run_id"] for c in candidates}) == 2
    for candidate in candidates:
        child = evidence.read(output / "candidates" / candidate["run_id"] / "manifest.json")
        assert child["after_fix_of"] == "123" and child["candidate_sha"] == candidate["candidate_sha"]
        assert child["evidence_scope"] == "independent_candidate"
        assert child["fix_generation"] == "disabled" and child["stages"]["fix"] == "not_available"
    calls = []
    evidence.upload(output, "pygoat", "123", run=lambda args, **kwargs: calls.append(args),
                    account="account", container="container")
    names = [args[args.index("--name") + 1] for args in calls]
    assert names[-1] == "pygoat/123/manifest.json"
    assert all(c["manifest"] in names for c in candidates)
    assert not any("/123/candidates/" in n for n in names)


@pytest.mark.parametrize("failure", ["missing", "wrong-sha", "wrong-app", "wrong-run", "old-attempt", "bad-sarif", "partial", "bad-findings", "bad-scans", "bad-exit-code"])
def test_missing_invalid_and_partial_candidate_scans_never_become_clean(source, tmp_path, failure):
    folder, out = tmp_path / "scan", tmp_path / "package"
    report, _ = scan(source, folder)
    if failure == "missing":
        (folder / "scan-status.json").unlink()
    elif failure in ("wrong-sha", "wrong-app", "wrong-run", "old-attempt"):
        report[{"wrong-sha": "commit_sha", "wrong-app": "app", "wrong-run": "after_fix_of", "old-attempt": "run_attempt"}[failure]] = "invalid"
        evidence.write(folder / "scan-status.json", report)
    elif failure == "partial":
        report["scans"]["sca"] = {"status": "failed", "exit_code": 2}
        evidence.write(folder / "scan-status.json", report)
    elif failure == "bad-sarif":
        (folder / "sast.sarif.json").write_text("{", encoding="utf-8")
    elif failure in ("bad-scans", "bad-exit-code"):
        if failure == "bad-scans":
            report["scans"] = []
        else:
            report["scans"]["sca"]["exit_code"] = 2
        evidence.write(folder / "scan-status.json", report)
    else:
        (folder / "findings/ranked_unified_findings.json").unlink()
    result = evidence.candidate_package("pygoat", ROW, folder, out, META)
    manifest = evidence.read(out / "manifest.json")
    assert manifest["artifact_status"]["findings"] != "completed"
    assert result["status"] == "failed"


def test_partial_results_are_retained_but_unavailable_to_legacy_clean_comparisons(source, tmp_path):
    folder, out = tmp_path / "scan", tmp_path / "package"
    scan(source, folder, failure="image-build")
    partial = [{"finding_id": "remaining", "finding_type": "sast"}]
    evidence.write(folder / "findings/ranked_unified_findings.json", partial)
    evidence.candidate_package("pygoat", ROW, folder, out, META)
    manifest = evidence.read(out / "manifest.json")
    assert manifest["artifact_status"]["findings"] == "not_available"
    assert evidence.read(out / manifest["artifacts"]["findings"]) == []
    assert evidence.read(out / manifest["artifacts"]["partial_findings"]) == partial


def test_manual_after_fix_run_normalises_without_fix_artifacts(tmp_path):
    artifacts, out = tmp_path / "artifacts", tmp_path / "package"
    for kind in ("sast", "sca", "container"):
        evidence.write(artifacts / f"pygoat-scan-results/{kind}.sarif.json", {"runs": [{"results": []}]})
    manifest = evidence.package("pygoat", artifacts, out, META,
        {"scan": "success", "fix": "skipped", "validate": "skipped"}, scan_kind="after_fix", after_fix_of="122")
    assert manifest["stages"]["normalise"] == "completed"
    assert manifest["stages"]["fix"] == manifest["stages"]["triage"] == "not_available"
    assert manifest["artifact_status"]["findings"] == "completed"
    assert "remediation" not in manifest["artifacts"] and "candidate_scans" not in manifest


def test_failed_validation_does_not_suppress_successful_security_rescan(source, tmp_path):
    folder, out = tmp_path / "scan", tmp_path / "package"
    scan(source, folder)
    result = evidence.candidate_package("pygoat", ROW, folder, out, META,
        {"result": "failed", "app_started": False, "checks": [evidence.check("startup", False)]})
    manifest = evidence.read(out / "manifest.json")
    assert result["status"] == "completed" and manifest["stages"]["validate"] == "failed"


def test_the_scan_names_no_app_or_tool_version_of_its_own():
    text = (Path(__file__).parents[2] / "scripts/candidate_rescan.py").read_text(encoding="utf-8")
    for name in ("8.19.4", "22.0.4", "libpq-dev", "python:3.11", "docker-compose", "NodeGoat", "PyGoat"):
        assert name not in text


def test_an_app_without_an_npm_pin_uses_the_npm_it_has(tmp_path, source):
    report, calls = scan(source, tmp_path / "out", ecosystem="npm", npm_version="")
    assert any(args[:2] == ["npm", "ci"] for args, _ in calls)
    assert report["dependency_install"] == "npm ci --ignore-scripts"


def test_a_different_npm_than_the_app_pins_stops_the_install(tmp_path, source):
    report, calls = scan(source, tmp_path / "out", ecosystem="npm", npm_version="9.9.9")
    assert not any(args[:2] == ["npm", "ci"] for args, _ in calls)
    assert "Pinned npm unavailable" in report["scans"]["sca"]["detail"]


def test_the_apps_own_python_tools_are_what_the_fallback_installs(tmp_path, source):
    _, calls = scan(source, tmp_path / "out", failure="image-build", python_image="python:9-slim",
                    pip_version="1.2.3", system_packages="one-package other-package")
    command = next(args for args, _ in calls if "asva-sca" in args)
    assert "python:9-slim" in command
    script = command[command.index("-c") + 1]
    assert "-y one-package other-package &&" in script and "pip==1.2.3" in script


def test_without_system_packages_or_a_pip_pin_nothing_extra_is_installed(tmp_path, source):
    _, calls = scan(source, tmp_path / "out", failure="image-build", python_image="python:9-slim")
    command = next(args for args, _ in calls if "asva-sca" in args)
    script = command[command.index("-c") + 1]
    assert "apt-get" not in script and "pip==" not in script


def test_with_no_image_to_scan_with_the_report_says_so(tmp_path, source):
    report, calls = scan(source, tmp_path / "out", failure="image-build", python_image="")
    assert not any("asva-sca" in args for args, _ in calls)
    assert "--python-image" in report["scans"]["sca"]["detail"]
