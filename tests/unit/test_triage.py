"""Unit tests for triage/triage.py — the "1 batch = 1 PR" contract."""

from __future__ import annotations

import pytest

from triage.triage import (
    MAX_FILES_PER_SAST_BATCH,
    build_batches,
    classify,
    filter_actionable,
    validate,
)

pytestmark = pytest.mark.unit


def make_finding(
    finding_id: str,
    *,
    finding_type: str = "sast",
    severity: str = "high",
    file: str = "app/routes/x.js",
    fixable: bool = True,
    is_node_modules: bool = False,
    priority: int = 1,
    rule_id: str = "some-rule",
) -> dict:
    return {
        "finding_id": finding_id,
        "finding_type": finding_type,
        "scan_run_id": "run1",
        "severity": severity,
        "score": 8.0,
        "has_real_score": finding_type != "sast",
        "identifiers": {"cve": None, "cwe": "CWE-94", "rule_id": rule_id},
        "title": f"finding {finding_id}",
        "summary": "summary",
        "description": "description",
        "location": {"kind": "source_file", "file": file, "line": 1, "package": None,
                      "display": file},
        "dependency": None,
        "remediation": {"type": "code_change", "fixable": fixable, "upgrade_to": None},
        "ecosystem": "unknown",
        "priority": priority,
        "is_node_modules": is_node_modules,
    }


# --------------------------------------------------------------------------------------
# filter_actionable
# --------------------------------------------------------------------------------------

def test_filter_actionable_keeps_critical_and_high():
    findings = [make_finding("1", severity="critical"), make_finding("2", severity="high")]
    assert len(filter_actionable(findings)) == 2


def test_filter_actionable_drops_medium_and_low():
    findings = [make_finding("1", severity="medium"), make_finding("2", severity="low")]
    assert filter_actionable(findings) == []


def test_filter_actionable_keeps_allowlisted_rule_at_medium():
    # A10 open redirect: scanner rates it medium, but the rule is on ALWAYS_FIX_RULES so it
    # still passes the cut.
    findings = [make_finding("1", severity="medium", rule_id="javascript/OR")]
    assert len(filter_actionable(findings)) == 1


def test_filter_actionable_denylist_overrides_high_severity():
    # NoHardcodedPasswords is denylisted — never fixed even at high severity, because in this
    # codebase those findings sit in the seed script whose creds every test logs in with.
    findings = [make_finding("1", severity="high", rule_id="javascript/NoHardcodedPasswords")]
    assert filter_actionable(findings) == []


def test_filter_actionable_drops_non_fixable():
    findings = [make_finding("1", fixable=False)]
    assert filter_actionable(findings) == []


def test_filter_actionable_drops_node_modules_flag():
    findings = [make_finding("1", is_node_modules=True)]
    assert filter_actionable(findings) == []


def test_filter_actionable_drops_node_modules_forward_slash_path():
    findings = [make_finding("1", file="node_modules/foo/bar.js")]
    assert filter_actionable(findings) == []


def test_filter_actionable_drops_node_modules_backslash_path():
    findings = [make_finding("1", file="node_modules\\foo\\bar.js")]
    assert filter_actionable(findings) == []


# --------------------------------------------------------------------------------------
# classify
# --------------------------------------------------------------------------------------

def test_classify_first_finding_per_file_is_root_rest_covered_by():
    findings = [
        make_finding("1", file="app/routes/contributions.js", priority=1),
        make_finding("2", file="app/routes/contributions.js", priority=2),
        make_finding("3", file="app/routes/other.js", priority=3),
    ]
    classified = classify(findings)
    by_id = {f["finding_id"]: f for f in classified}
    assert by_id["1"]["covered_by"] is None
    assert by_id["2"]["covered_by"] == "1"
    assert by_id["3"]["covered_by"] is None


def test_classify_container_findings_remap_to_docker_compose():
    findings = [make_finding("1", finding_type="container", file="mongo_4.0")]
    classified = classify(findings)
    assert classified[0]["location"]["file"] == "docker-compose.yml"


def test_classify_reason_mentions_docker_compose_for_container():
    findings = [make_finding("1", finding_type="container", file="mongo_4.0")]
    classified = classify(findings)
    assert "docker-compose.yml" in classified[0]["triage_reason"]


def test_classify_pygoat_container_targets_its_active_dockerfile():
    findings = [make_finding("1", finding_type="container", file="asva-pygoat_scan")]
    classified = classify(findings, container_file="Dockerfile.asva")
    assert classified[0]["location"]["file"] == "Dockerfile.asva"
    assert "Dockerfile.asva" in classified[0]["triage_reason"]


def test_classify_container_keeps_the_scanned_image_when_remapping_the_file():
    # location.file becomes the file to edit, so the image must survive in its own fields —
    # the agent's container prompt reads it from there.
    finding = make_finding("1", finding_type="container", file="mongo_4.4")
    finding["location"].update({"image_name": "mongo", "image_tag": "4.4"})
    location = classify([finding])[0]["location"]
    assert location["file"] == "docker-compose.yml"
    assert (location["image_name"], location["image_tag"]) == ("mongo", "4.4")


# --------------------------------------------------------------------------------------
# validate
# --------------------------------------------------------------------------------------

def test_validate_restores_missing_findings():
    actionable = [make_finding("1"), make_finding("2")]
    classified = classify(actionable)
    # simulate a finding accidentally dropped by some intermediate step
    dropped = [f for f in classified if f["finding_id"] != "2"]
    restored = validate(dropped, actionable)
    assert {f["finding_id"] for f in restored} == {"1", "2"}


def test_validate_noop_when_nothing_missing(capsys):
    actionable = [make_finding("1"), make_finding("2")]
    classified = classify(actionable)
    result = validate(list(classified), actionable)
    assert {f["finding_id"] for f in result} == {"1", "2"}


def test_restored_container_findings_keep_configured_target_and_single_edit():
    actionable = [make_finding("1", finding_type="container", file="image_one"),
                  make_finding("2", finding_type="container", file="image_two")]
    restored = validate(classify(actionable[:1], "Dockerfile.asva"), actionable, "Dockerfile.asva")
    batch = build_batches(restored, "app", "12345678", "run")[0][1]
    assert batch["total_files"] == 1 and batch["total_findings"] == 2
    assert batch["files_to_fix"][0]["file"] == "Dockerfile.asva"


# --------------------------------------------------------------------------------------
# build_batches — naming + SAST split
# --------------------------------------------------------------------------------------

def _classified_sast_files(n: int) -> list[dict]:
    findings = [make_finding(str(i), file=f"app/routes/f{i}.js", priority=i) for i in range(n)]
    return classify(findings)


def test_build_batches_sca_and_container_single_batch_each():
    findings = [
        make_finding("1", finding_type="sca", file="package.json"),
        make_finding("2", finding_type="container", file="mongo_4.0"),
    ]
    classified = classify(findings)
    batches = build_batches(classified, "asva", "e6919194", "run1")
    batch_ids = {bid for bid, _ in batches}
    assert "asva_sca_e6919194" in batch_ids
    assert "asva_container_e6919194" in batch_ids


def test_build_batches_sast_10_files_is_one_batch():
    classified = _classified_sast_files(MAX_FILES_PER_SAST_BATCH)
    batches = build_batches(classified, "asva", "sha00001", "run1")
    assert len(batches) == 1
    batch_id, batch = batches[0]
    assert batch_id == "asva_sast_sha00001_1"
    assert batch["total_files"] == MAX_FILES_PER_SAST_BATCH


def test_build_batches_sast_11_files_splits_into_two():
    classified = _classified_sast_files(MAX_FILES_PER_SAST_BATCH + 1)
    batches = build_batches(classified, "asva", "sha00001", "run1")
    assert len(batches) == 2
    ids = [bid for bid, _ in batches]
    assert ids == ["asva_sast_sha00001_1", "asva_sast_sha00001_2"]
    sizes = [b["total_files"] for _, b in batches]
    assert sizes == [MAX_FILES_PER_SAST_BATCH, 1]


def test_build_batches_naming_convention():
    findings = [make_finding("1", finding_type="sca", file="package.json")]
    classified = classify(findings)
    batches = build_batches(classified, "my-repo", "abcdef12", "run1")
    assert batches[0][0] == "my-repo_sca_abcdef12"


def test_build_batches_skips_types_with_no_files():
    findings = [make_finding("1", finding_type="sca", file="package.json")]
    classified = classify(findings)
    batches = build_batches(classified, "asva", "e6919194", "run1")
    assert len(batches) == 1  # no sast/container findings -> no empty batches
