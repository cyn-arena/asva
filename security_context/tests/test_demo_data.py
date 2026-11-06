"""The demo and evaluation data stay usable: the hardcoded NodeGoat findings match the cases
the scripts expect, and every finding is a valid request for the service."""

import json
import sys
from pathlib import Path

import pytest

from app.models import ContextRequest
from conftest import FIXTURES, fixture_json

sys.path.insert(0, str(Path(__file__).parent))
import eval_sources  # noqa: E402
import query_rag  # noqa: E402

FILES = fixture_json("nodegoat_findings.json")["files"]


def test_every_demo_case_has_findings_and_every_file_has_a_case():
    assert {entry["file"] for entry in FILES} == set(query_rag.CASES)


def test_the_default_demo_is_three_code_files_one_dependency_file_and_one_container_file():
    default = [e["finding_type"] for e in query_rag.load_fixture()["files"] if not query_rag.CASES[e["file"]].get("extra")]
    assert default == ["sast", "sast", "sast", "sca", "container"]


@pytest.mark.parametrize("entry", FILES, ids=[entry["file"] for entry in FILES])
def test_each_file_maps_to_a_valid_request(entry):
    findings = [query_rag.to_request(f) for f in entry["findings"]]
    assert findings == [eval_sources.to_request(f) for f in entry["findings"]]  # both scripts ask the same question
    request = ContextRequest(fix_type=entry["fix_type"], findings=findings)
    assert len(request.findings) == len(entry["findings"])


def test_container_findings_name_the_image_and_dependency_findings_carry_rule_cwes():
    container = next(e for e in FILES if e["finding_type"] == "container")
    assert all(f["location"]["image_name"] and f["location"]["image_tag"] for f in container["findings"])
    dependencies = next(e for e in FILES if e["finding_type"] == "sca")
    assert all(f["sarif_cwes"] for f in dependencies["findings"])


def test_validation_issues_each_list_their_key_advice():
    issues = json.loads((FIXTURES / "sast_validation.json").read_text(encoding="utf-8"))["issues"]
    assert len(issues) >= 12 and all(issue["facts"] and all(issue["facts"].values()) for issue in issues)
    titles = {issue["title"] for issue in issues}
    code_titles = {f["title"] for e in FILES if e["finding_type"] == "sast" for f in e["findings"]}
    assert code_titles <= titles  # every code finding of the demo has key advice to be measured against


def test_evaluation_knows_every_source_the_service_can_leave_out():
    from app import config
    assert set(eval_sources.SOURCES) == set(config.SOURCE_IDS)


def test_evaluation_facts_are_checked_against_a_response_shape():
    result = {"items": [{"title": "t", "section": None, "text": "Migration target: mongo:7.0", "kind": "container_summary"}],
              "references": [{"type": "cve", "cvss": 9.8}], "upgrades": [{"kind": "image", "target": "7.0"}]}
    present = {label for label, _, check in eval_sources.FACTS_CONTAINER if check(result)}
    assert present == {"migration target", "CVSS score and severity per CVE"}
