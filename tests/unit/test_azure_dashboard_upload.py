"""Check Azure publication ordering and failure handling without accessing Azure."""
import importlib.util
import json
from pathlib import Path
import subprocess

import pytest

spec = importlib.util.spec_from_file_location("azure_dashboard", Path(__file__).resolve().parents[2] / "scripts/upload-dashboard-azure.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
pytestmark = pytest.mark.unit


@pytest.fixture
def run_dir(tmp_path):
    for rel in ("scan/sast.sarif.json", "findings/all.json", "findings/triage.json"):
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("[]")
    (tmp_path / "manifest.json").write_text(json.dumps({
        "app": "pygoat", "run_id": "123", "artifacts": {
            "findings": "findings/all.json", "triage": "findings/triage.json",
            "scan": {"sast": "scan/sast.sarif.json"}, "fix_batches": [],
        },
    }))
    return tmp_path


def test_upload_preserves_paths_and_publishes_manifest_last(run_dir):
    calls = []
    result = module.upload_run(run_dir, "account", "container", execute=lambda args, **kwargs: calls.append(args))
    names = [args[args.index("--name") + 1] for args in calls]
    assert names[-1] == result == "pygoat/123/manifest.json"
    assert "pygoat/123/findings/all.json" in names
    assert all(args[args.index("--auth-mode") + 1] == "login" for args in calls)


def test_failed_file_upload_does_not_publish_manifest(run_dir):
    calls = []
    def fail(args, **kwargs):
        calls.append(args)
        raise subprocess.CalledProcessError(1, args)
    with pytest.raises(subprocess.CalledProcessError):
        module.upload_run(run_dir, "account", "container", execute=fail)
    assert len(calls) == 1
    assert not calls[0][calls[0].index("--name") + 1].endswith("manifest.json")


def test_logs_are_plain_text_and_json_keeps_json_content_type(run_dir):
    path = run_dir / "validation/pygoat.log"
    path.parent.mkdir(parents=True)
    path.write_text("Gunicorn started")
    calls = []
    module.upload_run(run_dir, "account", "container", execute=lambda args, **kwargs: calls.append(args))
    for args in calls:
        name = args[args.index("--name") + 1]
        expected = "text/plain" if name.endswith(".log") else "application/json"
        assert args[args.index("--content-type") + 1] == expected


def test_missing_artifact_prevents_any_upload(run_dir):
    (run_dir / "findings/all.json").unlink()
    calls = []
    with pytest.raises(ValueError, match="Missing or unsafe"):
        module.upload_run(run_dir, "account", "container", execute=lambda *args, **kwargs: calls.append(args))
    assert not calls
