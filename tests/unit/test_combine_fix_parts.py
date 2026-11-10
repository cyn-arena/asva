"""scripts/combine_fix_parts.py: one fix output from the parallel fix jobs."""

import json

import pytest

from scripts import combine_fix_parts

pytestmark = pytest.mark.unit


def _write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


@pytest.fixture
def run(tmp_path):
    prep, parts = tmp_path / "prep", tmp_path / "parts"
    _write(prep / "findings" / "ranked_unified_findings.json", [{"id": 1}])
    for batch_id, kind in (("app_sast_1", "sast"), ("app_sca", "sca"), ("app_container", "container")):
        _write(prep / "fix_batches" / f"{batch_id}.json", {"batch_id": batch_id, "batch_type": kind})
    return tmp_path, prep, parts


def _part(parts, name, rows, prs=None, batches=(), status=None):
    _write(parts / name / "fixes.json", rows)
    _write(parts / name / "prs.json", prs if prs is not None else [{"batch_id": r["batch_id"]} for r in rows])
    _write(parts / name / "stage-status.json", status or {"fix": "success", "evidence_errors": []})
    for batch in batches:
        _write(parts / name / "fix_batches" / f"{batch['batch_id']}.json", batch)


def _opened(batch_id, kind):
    return {"batch_id": batch_id, "batch_type": kind, "status": "pr_opened", "branch": f"fix/{batch_id}",
            "pr_url": f"https://x/pull/{batch_id}", "candidate_sha": "a" * 40}


def test_the_parts_become_one_output_and_one_matrix(run):
    tmp, prep, parts = run
    _part(parts, "fixpart-app-app_sast_1", [_opened("app_sast_1", "sast")],
          batches=[{"batch_id": "app_sast_1", "batch_type": "sast", "new_before_pr": ["x"]}])
    _part(parts, "fixpart-app-app_sca", [_opened("app_sca", "sca"), _opened("app_sca_same_major", "sca")],
          batches=[{"batch_id": "app_sca_same_major", "batch_type": "sca"}])
    _part(parts, "fixpart-app-app_container", [{"batch_id": "app_container", "batch_type": "container",
                                                 "status": "no_commits"}],
          status={"fix": "failure", "evidence_errors": []})
    matrix, planned = combine_fix_parts.combine(prep, parts, tmp / "out")
    assert planned == 3
    assert [p["batch_id"] for p in matrix] == ["app_sast_1", "app_sca", "app_sca_same_major"]
    out = tmp / "out"
    assert len(json.loads((out / "fixes.json").read_text())) == 4
    assert len(json.loads((out / "prs.json").read_text())) == 4
    assert json.loads((out / "stage-status.json").read_text())["fix"] == "success"
    assert (out / "findings" / "ranked_unified_findings.json").exists()
    # The agent's copy of a batch wins, and the batch it added is kept.
    assert json.loads((out / "fix_batches" / "app_sast_1.json").read_text())["new_before_pr"] == ["x"]
    assert (out / "fix_batches" / "app_sca_same_major.json").exists()


def test_a_fix_job_that_saved_nothing_shows_as_an_error(run):
    tmp, prep, parts = run
    _part(parts, "fixpart-app-app_sast_1", [_opened("app_sast_1", "sast")])
    combine_fix_parts.combine(prep, parts, tmp / "out")
    rows = {r["batch_id"]: r for r in json.loads((tmp / "out" / "fixes.json").read_text())}
    assert rows["app_sca"]["status"] == "error" and rows["app_container"]["status"] == "error"
    assert set(json.loads((tmp / "out" / "stage-status.json").read_text())["evidence_errors"]) == {"app_sca", "app_container"}


def test_no_pr_at_all_is_a_failed_fix_stage(run):
    tmp, prep, parts = run
    _part(parts, "fixpart-app-app_container", [{"batch_id": "app_container", "batch_type": "container",
                                                 "status": "no_commits"}])
    matrix, planned = combine_fix_parts.combine(prep, parts, tmp / "out")
    assert matrix == [] and planned == 3
    assert json.loads((tmp / "out" / "stage-status.json").read_text())["fix"] == "failure"


def test_nothing_to_fix_is_skipped(tmp_path):
    (tmp_path / "prep" / "findings").mkdir(parents=True)
    matrix, planned = combine_fix_parts.combine(tmp_path / "prep", tmp_path / "parts", tmp_path / "out")
    assert matrix == [] and planned == 0
    assert json.loads((tmp_path / "out" / "stage-status.json").read_text())["fix"] == "skipped"
    assert json.loads((tmp_path / "out" / "prs.json").read_text()) == []


def test_main_writes_the_matrix_and_counts_for_the_workflow(run, monkeypatch):
    tmp, prep, parts = run
    _part(parts, "fixpart-app-app_sast_1", [_opened("app_sast_1", "sast")])
    output = tmp / "github_output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setattr("sys.argv", ["combine", "--prep", str(prep), "--parts", str(parts), "--output", str(tmp / "out")])
    combine_fix_parts.main()
    lines = dict(line.split("=", 1) for line in output.read_text().splitlines())
    assert json.loads(lines["prs"])[0]["batch_id"] == "app_sast_1"
    assert lines["planned"] == "3" and lines["opened"] == "1"
