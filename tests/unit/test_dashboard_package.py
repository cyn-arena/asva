"""Offline scan -> triage -> dashboard contract checks; no scanners or LLM calls."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
from jsonschema import ValidationError

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("package_scan_run", ROOT / "scripts/package-scan-run.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
pytestmark = pytest.mark.unit


@pytest.fixture
def prepared_run(tmp_path):
    source = tmp_path / "evidence"
    (source / "scan").mkdir(parents=True)
    for kind in ("sast", "sca", "container"):
        shutil.copyfile(ROOT / f"tests/fixtures/sarif/{kind}_sample.sarif.json",
                        source / f"scan/{kind}.sarif.json")
    # Keep container routing covered with an explicitly critical scanner rating.
    # The unmodified fixture is low/medium and should no longer be CVSS-promoted.
    container_path = source / "scan/container.sarif.json"
    container_data = json.loads(container_path.read_text(encoding="utf-8"))
    rule = next(r for r in container_data["runs"][0]["tool"]["driver"]["rules"]
                if "vulnerability in glibc" in r["shortDescription"]["text"])
    rule["shortDescription"]["text"] = rule["shortDescription"]["text"].replace("Low severity", "Critical severity")
    container_path.write_text(json.dumps(container_data), encoding="utf-8")
    metadata = dict(app="pygoat", run_id="offline-contract-test", sha="a" * 40,
                    branch="test-only", repository="example/asva",
                    created_at="2026-10-09T00:00:00Z", workflow="Offline contract test")
    (source / "scan/scan-status.json").write_text(json.dumps({
        "app": metadata["app"], "run_id": metadata["run_id"], "commit_sha": metadata["sha"],
        "scans": {kind: {"status": "completed"} for kind in ("sast", "sca", "container")},
    }))
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    subprocess.run([sys.executable, str(ROOT / "normaliser/normaliser.py"),
                    "--inputs", *[str(source / f"scan/{kind}.sarif.json") for kind in ("sast", "sca", "container")],
                    "--output-dir", str(source / "findings"), "--scan-run-id", metadata["run_id"]],
                   check=True, capture_output=True, env=env)
    subprocess.run([sys.executable, str(ROOT / "triage/triage.py"),
                    "--input", str(source / "findings/ranked_unified_findings.json"),
                    "--output", str(source / "findings/ranked_findings.json"),
                    "--batch-dir", str(source / "remediation/fix_batches"),
                    "--repo-name", "asva-pygoat", "--commit-sha", metadata["sha"],
                    "--container-file", "Dockerfile"],
                   check=True, capture_output=True, env=env)
    return source, tmp_path / "dashboard", metadata


def test_scan_triage_bundle_matches_dashboard_contract(prepared_run):
    source, output, metadata = prepared_run
    target = module.package_run(source, output, **metadata)
    manifest = module.read_json(target / "manifest.json")
    assert manifest["commit_sha"] == metadata["sha"]
    assert manifest["stages"]["fix"] == manifest["stages"]["validate"] == "not_available"
    assert "remediation" not in manifest["artifacts"]
    assert all(f["scan_run_id"] == metadata["run_id"] for f in module.read_json(target / manifest["artifacts"]["findings"]))
    container_files = [file["file"] for rel in manifest["artifacts"]["fix_batches"]
                       for file in module.read_json(target / rel)["files_to_fix"]
                       if file["finding_type"] == "container"]
    assert container_files and set(container_files) == {"Dockerfile"}


def test_package_rejects_a_different_scanned_commit(prepared_run):
    source, output, metadata = prepared_run
    with pytest.raises(ValueError, match="does not match"):
        module.package_run(source, output, **{**metadata, "sha": "b" * 40})
    assert not output.exists()


def test_package_rejects_findings_dashboard_cannot_display(prepared_run):
    source, output, metadata = prepared_run
    path = source / "findings/ranked_unified_findings.json"
    findings = module.read_json(path)
    findings[0]["severity"] = "unsupported-severity"
    path.write_text(json.dumps(findings))
    with pytest.raises(ValidationError):
        module.package_run(source, output, **metadata)
    assert not output.exists()


def test_package_handles_zero_actionable_findings(prepared_run):
    source, output, metadata = prepared_run
    (source / "findings/ranked_findings.json").write_text("[]")
    for batch in (source / "remediation/fix_batches").glob("*.json"):
        batch.unlink()
    target = module.package_run(source, output, **metadata)
    assert module.read_json(target / "manifest.json")["artifacts"]["fix_batches"] == []
