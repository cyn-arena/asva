"""The fix evaluation's own logic (tests/eval_fixes.py): how the three ways build their prompts
and how a returned file is judged. No LLM and no Docker here."""

import json
import sys
from pathlib import Path

import pytest

from conftest import FIXTURES, fixture_json

sys.path.insert(0, str(Path(__file__).parent))
import eval_fixes  # noqa: E402

FILES = {entry["file"]: entry for entry in fixture_json("nodegoat_findings.json")["files"]}
PACKAGE_JSON = (FIXTURES / "nodegoat_files" / "package.json").read_text(encoding="utf-8").replace("\r\n", "\n")
COMPOSE = (FIXTURES / "nodegoat_files" / "docker-compose.yml").read_text(encoding="utf-8").replace("\r\n", "\n")
UPGRADES = [
    {"kind": "package", "name": "body-parser", "current": "1.18.3", "target": "1.20.4", "compatible_target": "1.20.4", "note": None},
    {"kind": "package", "name": "express", "current": "4.16.4", "target": "4.16.4", "compatible_target": None, "note": "already there"},
    {"kind": "package", "name": "forever", "current": "2.0.0", "target": "2.0.0", "compatible_target": None, "note": "already there"},
    {"kind": "package", "name": "marked", "current": "0.3.5", "target": "0.3.18", "compatible_target": "0.3.18", "note": None},
    {"kind": "package", "name": "mongodb", "current": "2.2.36", "target": "3.1.13", "compatible_target": None, "note": "No compatible fix"},
    {"kind": "package", "name": "underscore", "current": "1.9.1", "target": "1.13.8", "compatible_target": "1.13.8", "note": None},
]
IMAGE = {"kind": "image", "name": "mongo", "current": "4.4", "target": "7.0", "compatible_target": None,
         "fixes": ["CVE-1", "CVE-2"], "note": "No compatible fix",
         "candidates": [{"tag": "5.0", "cves_resolved": 0, "cves_checked": 2, "end_of_life": True},
                        {"tag": "8.0", "cves_resolved": 2, "cves_checked": 2, "end_of_life": False}]}


def with_versions(**versions) -> str:
    document = json.loads(PACKAGE_JSON)
    for name, version in versions.items():
        name = name.replace("_", "-")
        section = "dependencies" if name in document["dependencies"] else "devDependencies"
        document[section][name] = version
    return json.dumps(document, indent=2)


def test_the_app_files_match_the_findings():
    assert '"mongodb"' in PACKAGE_JSON and "image: mongo:4.4" in COMPOSE


def test_way_a_asks_for_every_scanner_target_as_asva_does_today():
    upgrade_map = eval_fixes.asva_upgrade_map(FILES["package.json"]["findings"])
    assert upgrade_map == {"express": "4.16.4", "marked": "0.3.18", "forever": "2.0.0", "body-parser": "1.20.4",
                           "underscore": "1.13.8", "mongodb": "3.1.13"}


def test_the_three_ways_differ_only_in_context_instruction_and_upgrade_list():
    response = {"items": [{"source": "OSV.dev", "key": "k", "kind": "upgrade_notes", "title": "Upgrade notes", "section": None,
                           "text": "- mongodb 2.2.36 → 3.1.13: MAJOR"}], "upgrades": UPGRADES}
    prompts = eval_fixes.prompts_for("package.json", PACKAGE_JSON, FILES["package.json"]["findings"], response)
    assert "REFERENCE MATERIAL" not in prompts["A"] and '"package": "mongodb"' in prompts["A"]
    assert "===REFERENCE MATERIAL===" in prompts["B"] and eval_fixes.RESPECT_SCA in prompts["B"] and '"package": "mongodb"' in prompts["B"]
    assert "===REFERENCE MATERIAL===" in prompts["C"] and eval_fixes.RESPECT_SCA not in prompts["C"]
    assert '"package": "mongodb"' not in prompts["C"] and '"package": "marked"' in prompts["C"]
    assert prompts["A"].count("Current file content:") == prompts["B"].count("Current file content:") == 1


def test_way_c_makes_no_llm_call_for_an_image_without_a_compatible_line():
    response = {"items": [], "upgrades": [IMAGE]}
    prompts = eval_fixes.prompts_for("docker-compose.yml", COMPOSE, FILES["docker-compose.yml"]["findings"], response)
    assert prompts["C"] is None and "latest stable version" in prompts["A"]
    compatible = {"items": [], "upgrades": [{**IMAGE, "compatible_target": "4.8"}]}
    prompt = eval_fixes.prompts_for("docker-compose.yml", COMPOSE, FILES["docker-compose.yml"]["findings"], compatible)["C"]
    assert "- Update the image to exactly mongo:4.8." in prompt and "latest stable version" not in prompt


def test_sca_outcome_counts_what_a_fix_resolves_and_which_bumps_are_major():
    findings = FILES["package.json"]["findings"]
    everything = eval_fixes.sca_outcome(PACKAGE_JSON, with_versions(body_parser="1.20.4", marked="0.3.18", mongodb="3.1.13",
                                                                   underscore="1.13.8"), findings, UPGRADES)
    assert everything["major"] == ["mongodb"] and (everything["fixed"], everything["total"]) == (12, 26)
    compatible = eval_fixes.sca_outcome(PACKAGE_JSON, with_versions(body_parser="1.20.4", marked="0.3.18", underscore="1.13.8"),
                                        findings, UPGRADES)
    assert compatible["major"] == [] and compatible["fixed"] == 9 and compatible["not_fixable_by_bump"] == 14
    assert "mongodb" not in compatible["summary"]


def test_sca_outcome_reports_an_unchanged_or_broken_answer():
    findings = FILES["package.json"]["findings"]
    assert eval_fixes.sca_outcome(PACKAGE_JSON, PACKAGE_JSON, findings, UPGRADES)["summary"] == "no change"
    assert eval_fixes.sca_outcome(PACKAGE_JSON, "{ not json", findings, UPGRADES)["valid"] is False


@pytest.mark.parametrize("tag, summary, major, fixed", [
    ("8.0", "mongo:8.0", ["mongo"], 2), ("5.0", "mongo:5.0", ["mongo"], 0), ("4.4", "mongo:4.4 (unchanged)", [], 0)])
def test_container_outcome_reads_the_tag_and_what_its_base_resolves(tag, summary, major, fixed):
    outcome = eval_fixes.container_outcome(COMPOSE, COMPOSE.replace("image: mongo:4.4", f"image: mongo:{tag}"), [IMAGE])
    assert (outcome["summary"], outcome["major"], outcome["fixed"], outcome["total"]) == (summary, major, fixed, 2)


def test_identical_answers_share_one_app_check():
    assert eval_fixes.content_key("package.json", "a\n") == eval_fixes.content_key("package.json", "a")
    assert eval_fixes.content_key("package.json", "a") != eval_fixes.content_key("docker-compose.yml", "a")
