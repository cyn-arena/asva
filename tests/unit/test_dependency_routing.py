"""Regression coverage for scanner context loss and cross-type triage roots."""
from copy import deepcopy

import pytest

from normaliser.normaliser import extract_finding, deduplicate
from triage.triage import classify, build_batches, filter_actionable
from agent.agent_loop import build_fix_prompt

pytestmark = pytest.mark.unit


def observation(source, ecosystem="pip", file="requirements.txt", version="1.0", upgrade=True):
    result = {"ruleId": "advisory", "level": "error", "locations": [{
        "logicalLocations": [{"fullyQualifiedName": f"example@{version}"}],
        "physicalLocation": {"artifactLocation": {"uri": file}},
    }]}
    if upgrade:
        result["fixes"] = [{"description": {"text": "Upgrade to example@2.0.0"}}]
    rule = {"id": "advisory", "properties": {"tags": [ecosystem], "security-severity": "9.0"},
            "fullDescription": {"text": "CVE-2026-12345"}}
    return extract_finding(result, rule, source)


@pytest.mark.parametrize("ecosystem,manifest", [("pip", "requirements.txt"), ("npm", "package.json")])
@pytest.mark.parametrize("reverse", [False, True])
def test_container_cannot_discard_source_remediation(ecosystem, manifest, reverse):
    image = observation("container", ecosystem, "image_scan", upgrade=False)
    source = observation("sca", ecosystem, manifest)
    findings = deduplicate([source, image] if reverse else [image, source])
    assert len(findings) == 2
    assert image["location"]["kind"] == "dependency"
    assert source["package"] == {"name": "example", "version": "1.0"}
    classified = classify(filter_actionable(findings))
    batches = build_batches(classified, "app", "12345678", "run")
    assert len(batches) == 1
    batch = batches[0][1]
    assert batch["batch_type"] == "sca"
    entry = batch["files_to_fix"][0]
    assert entry["file"] == manifest
    assert entry["findings"][0]["remediation"]["upgrade_to"] == "example@2.0.0"
    prompt = build_fix_prompt(manifest, "example==1.0" if ecosystem == "pip" else '{}',
                              entry["findings"], entry["fix_type"])
    assert ("Python dependencies" if ecosystem == "pip" else "npm dependencies") in prompt


@pytest.mark.parametrize("ecosystem,kind", [("pip", "dependency"), ("npm", "dependency"),
                                           ("deb", "os_package"), ("rpm", "os_package"),
                                           ("apk", "os_package"), ("unrecognised", "container_package")])
def test_image_package_classification_uses_ecosystem(ecosystem, kind):
    assert observation("container", ecosystem)["location"]["kind"] == kind


@pytest.mark.parametrize("other", [
    {"version": "1.1"}, {"file": "other/requirements.txt"}, {"ecosystem": "npm"},
    {"source": "container"}, {"upgrade": False},
])
def test_distinct_package_contexts_remain_separate(other):
    first = observation("sca")
    second = observation(**{"source": "sca", **other})
    assert len(deduplicate([first, second])) == len(deduplicate([second, first])) == 2


def test_dependency_paths_and_advisories_are_part_of_context():
    first = observation("sca")
    # Exercise extraction of both dependency chains and separate advisories with a shared CVE.
    from normaliser.normaliser import make_dedup_key
    args = ("sca", "CVE-2026-12345", "rule", "example", "package.json", None)
    assert make_dedup_key(*args, dependency_path=["a", "example"]) != make_dedup_key(
        *args, dependency_path=["b", "example"])
    assert make_dedup_key(*args) != make_dedup_key(*("sca", args[1], "other-rule", *args[3:]))
    assert deduplicate([first, deepcopy(first)]) == [first]


@pytest.mark.parametrize("reverse", [False, True])
def test_multiple_images_resolve_before_root_selection(reverse):
    images = [observation("container", "deb", "image_one"), observation("container", "deb", "image_two")]
    if reverse:
        images.reverse()
    classified = classify(images, "Dockerfile")
    batch = build_batches(classified, "app", "12345678", "run")[0][1]
    assert batch["total_files"] == 1 and batch["total_findings"] == 2
    assert batch["files_to_fix"][0]["file"] == "Dockerfile"
    assert sum(f["covered_by"] is None for f in classified) == 1


@pytest.mark.parametrize("reverse", [False, True])
def test_sast_and_sca_at_same_path_have_independent_roots(reverse):
    findings = [observation("sast", "npm", "package.json"), observation("sca", "npm", "package.json")]
    if reverse:
        findings.reverse()
    classified = classify(findings)
    assert all(f["covered_by"] is None for f in classified)
    batches = build_batches(classified, "app", "12345678", "run")
    assert {b["batch_type"] for _, b in batches} == {"sast", "sca"}
    assert all(len(b["files_to_fix"][0]["findings"]) == 1 for _, b in batches)


def test_image_application_paths_are_deferred_without_source_mapping():
    findings = [observation("container", "pip", "/app/requirements.txt"),
                observation("container", "npm", "/usr/lib/node_modules/package.json")]
    classified = classify(findings, "Dockerfile")
    assert all(f["routing_status"] == "deferred" for f in classified)
    assert build_batches(classified, "app", "12345678", "run") == []
    assert {f["location"]["file"] for f in classified} == {f["location"]["file"] for f in findings}
