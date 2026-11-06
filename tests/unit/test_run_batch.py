"""Light coverage for gitops/run_batch.py -- a thin runner; only its batch
selection logic (_select_batches) is unit-tested here. It does not test; it just exercises
the GitOps + secrets-gate wiring, so deeper coverage belongs to the modules it calls."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gitops.run_batch import _select_batches

pytestmark = pytest.mark.unit


def _write_batch(d: Path, name: str, commit_sha: str) -> None:
    (d / name).write_text(json.dumps({"batch_id": name, "commit_sha": commit_sha,
                                       "files_to_fix": []}), encoding="utf-8")


def test_select_batches_globs_all_json_in_dir(tmp_path):
    _write_batch(tmp_path, "a.json", "deadbeef")
    _write_batch(tmp_path, "b.json", "deadbeef")
    batches = _select_batches(str(tmp_path), [], None)
    assert {b["batch_id"] for b in batches} == {"a.json", "b.json"}


def test_select_batches_explicit_files_override_dir_glob(tmp_path):
    _write_batch(tmp_path, "a.json", "deadbeef")
    _write_batch(tmp_path, "b.json", "deadbeef")
    only_a = str(tmp_path / "a.json")
    batches = _select_batches(str(tmp_path), [only_a], None)
    assert [b["batch_id"] for b in batches] == ["a.json"]


def test_select_batches_filters_by_sha_prefix(tmp_path):
    _write_batch(tmp_path, "a.json", "deadbeef00")
    _write_batch(tmp_path, "b.json", "cafebabe00")
    batches = _select_batches(str(tmp_path), [], "deadbeef")
    assert [b["batch_id"] for b in batches] == ["a.json"]


def test_select_batches_exits_when_none_found(tmp_path):
    with pytest.raises(SystemExit):
        _select_batches(str(tmp_path), [], None)


def test_select_batches_exits_on_multiple_scan_cycles_without_sha(tmp_path):
    _write_batch(tmp_path, "a.json", "deadbeef00")
    _write_batch(tmp_path, "b.json", "cafebabe00")
    with pytest.raises(SystemExit):
        _select_batches(str(tmp_path), [], None)
