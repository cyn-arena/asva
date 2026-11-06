"""Unit tests for agent/browser_failure_batch.py -- captured misuse-case
failures turned into the same batch schema triage.build_batches produces."""

from __future__ import annotations

import pytest

from agent.browser_failure_batch import build_batch, build_batches

pytestmark = pytest.mark.unit

IDOR_FAILURE = {
    "test_id": "tests/e2e/api/test_misuse_cases.py::test_idor_allocations",
    "test_name": "test_idor_allocations",
    "test_file": "tests/e2e/api/test_misuse_cases.py",
    "files": [
        "app/data/allocations-dao.js",
        "app/routes/allocations.js",
        "app/routes/index.js",
    ],
    "detail": "user1 requesting /allocations/3 (user2's id) should not surface user2's name",
}

BENEFITS_FAILURE = {
    "test_id": "tests/e2e/api/test_misuse_cases.py::test_missing_access_control_benefits",
    "test_name": "test_missing_access_control_benefits",
    "test_file": "tests/e2e/api/test_misuse_cases.py",
    "files": ["app/routes/index.js"],
    "detail": "user1 (non-admin) POSTing /benefits should be rejected, not rendered",
}


def test_build_batch_shape():
    batch = build_batch(IDOR_FAILURE, "asva", "deadbeef12345")

    assert batch["batch_type"] == "logic"
    assert batch["repo_name"] == "asva"
    assert batch["commit_sha"] == "deadbeef"
    assert batch["total_files"] == 3
    assert batch["total_findings"] == 3
    assert batch["source_test_id"] == IDOR_FAILURE["test_id"]
    assert batch["batch_id"] == "asva_logic_deadbeef_test_idor_allocations"


def test_build_batch_files_to_fix_matches_annotated_order():
    batch = build_batch(IDOR_FAILURE, "asva", "deadbeef")
    assert [f["file"] for f in batch["files_to_fix"]] == IDOR_FAILURE["files"]


def test_build_batch_each_file_entry_is_logic_change_with_synthesized_finding():
    batch = build_batch(IDOR_FAILURE, "asva", "deadbeef")
    for file_entry in batch["files_to_fix"]:
        assert file_entry["fix_type"] == "logic_change"
        assert file_entry["finding_count"] == 1
        finding = file_entry["findings"][0]
        assert finding["source"] == "browser_test"
        assert finding["test_id"] == IDOR_FAILURE["test_id"]
        assert finding["description"] == IDOR_FAILURE["detail"]
        assert finding["identifiers"] == {"cve": None, "cwe": None, "rule_id": None}
        assert finding["location"]["file"] == file_entry["file"]


def test_build_batches_one_batch_per_failure_in_order():
    batches = build_batches([IDOR_FAILURE, BENEFITS_FAILURE], "asva", "deadbeef")

    assert [batch_id for batch_id, _ in batches] == [
        "asva_logic_deadbeef_test_idor_allocations",
        "asva_logic_deadbeef_test_missing_access_control_benefits",
    ]
    assert batches[1][1]["total_files"] == 1
