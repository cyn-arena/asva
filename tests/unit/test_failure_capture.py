"""Unit tests for confirmed-vulnerability capture and handoff records."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent.failure_capture import (
    build_capture_record,
    capture_if_vulnerable,
    strip_param_suffix,
)

pytestmark = pytest.mark.unit


def test_strip_param_suffix_removes_bracket_params():
    assert strip_param_suffix("test_foo[chromium]") == "test_foo"


def test_strip_param_suffix_no_params_unchanged():
    assert strip_param_suffix("test_foo") == "test_foo"


def test_build_capture_record_shape_and_truncation():
    record = build_capture_record(
        "tests/e2e/api/test_misuse_cases.py::test_idor_allocations",
        ["app/routes/allocations.js"],
        "x" * 3000,
    )
    assert record["test_id"] == "tests/e2e/api/test_misuse_cases.py::test_idor_allocations"
    assert record["test_name"] == "test_idor_allocations"
    assert record["test_file"] == "tests/e2e/api/test_misuse_cases.py"
    assert record["files"] == ["app/routes/allocations.js"]
    assert len(record["detail"]) == 2000


def _write_annotated_test_file(tmp_path: Path) -> Path:
    src = tmp_path / "test_sample.py"
    src.write_text(
        "# @a app/routes/allocations.js\n"
        "def test_idor_allocations():\n"
        "    pass\n",
        encoding="utf-8",
    )
    return src


def test_capture_if_vulnerable_not_observed_is_noop(tmp_path):
    src = _write_annotated_test_file(tmp_path)
    out = tmp_path / "captured.json"

    result = capture_if_vulnerable(f"{src}::test_idor_allocations", False, "detail", out_path=str(out))

    assert result is None
    assert not out.exists()


def test_capture_if_vulnerable_no_out_path_is_noop(tmp_path, monkeypatch):
    monkeypatch.delenv("ASVA_CAPTURE_FAILURES_TO", raising=False)
    src = _write_annotated_test_file(tmp_path)

    result = capture_if_vulnerable(f"{src}::test_idor_allocations", True, "detail")

    assert result is None


def test_capture_if_vulnerable_unannotated_test_is_noop(tmp_path):
    src = tmp_path / "test_sample.py"
    src.write_text("def test_no_annotation():\n    pass\n", encoding="utf-8")
    out = tmp_path / "captured.json"

    result = capture_if_vulnerable(f"{src}::test_no_annotation", True, "detail", out_path=str(out))

    assert result is None
    assert not out.exists()


def test_capture_if_vulnerable_writes_record(tmp_path):
    src = _write_annotated_test_file(tmp_path)
    out = tmp_path / "captured.json"

    record = capture_if_vulnerable(
        f"{src}::test_idor_allocations", True, "leak detail", out_path=str(out)
    )

    assert record["files"] == ["app/routes/allocations.js"]
    saved = json.loads(out.read_text(encoding="utf-8"))
    assert saved == [record]


def test_capture_if_vulnerable_appends_to_existing_file(tmp_path):
    src = _write_annotated_test_file(tmp_path)
    out = tmp_path / "captured.json"
    out.write_text(json.dumps([{"existing": True}]), encoding="utf-8")

    capture_if_vulnerable(f"{src}::test_idor_allocations", True, "detail", out_path=str(out))

    saved = json.loads(out.read_text(encoding="utf-8"))
    assert len(saved) == 2
    assert saved[0] == {"existing": True}


def test_capture_if_vulnerable_missing_source_file_is_noop(tmp_path):
    out = tmp_path / "captured.json"

    result = capture_if_vulnerable(
        f"{tmp_path / 'does_not_exist.py'}::test_x", True, "detail", out_path=str(out)
    )

    assert result is None
    assert not out.exists()
