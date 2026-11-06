"""Real pip SARIF without result.fixes must still reach Python candidate generation."""
from pathlib import Path
import json

import pytest

from normaliser.normaliser import python_remediation, extract_finding, process_sarif_file
from triage.triage import filter_actionable, classify, build_batches
from agent.agent_loop import process_batch
from gitops import config

pytestmark = pytest.mark.unit
FIXTURE = Path(__file__).parents[1] / "fixtures/sarif/pip_remediation_sample.sarif.json"


@pytest.mark.parametrize("installed,targets,expected", [
    ("4.2", "3.2.25, 4.2.11, 5.0.3", "4.2.11"),
    ("4.2", "5.2.18, 6.0.9, 6.1.2", "5.2.18"),
    ("5.1", "4.2.29, 5.2.12, 6.0.3", "5.2.12"),
])
def test_selects_scanner_recommended_branch_without_downgrading(installed, targets, expected):
    evidence = python_remediation(f"# Remediation\nUpgrade `Django` to version {targets} or higher.\n",
                                  "django", installed, True)
    assert evidence["upgrade_to"] == f"django@{expected}"


@pytest.mark.parametrize("guidance,package,version,direct", [
    ("Upgrade `other` to version 2.0 or higher.", "django", "1.0", True),
    ("Upgrade `django` to version >=2.0.", "django", "1.0", True),
    ("Upgrade `django` to version 2.0 or higher.", "django", "3.0", True),
    ("Upgrade `django` to version 2.0 or higher.", "django", "1.0rc1", True),
    ("Upgrade `django` to version 2.0 or higher.", "django", "1.0", False),
    ("Upgrade `django` to version 2.0 or higher.", "django", "1.0", None),
    ("There is no fixed version.", "django", "1.0", True),
])
def test_unsupported_guidance_is_preserved_without_inventing_an_upgrade(guidance, package, version, direct):
    evidence = python_remediation(f"# Remediation\n{guidance}\n# References\nUpgrade to other@99.0",
                                  package, version, direct)
    assert evidence["guidance"] == guidance
    assert evidence["status"] == "unsupported" and evidence["upgrade_to"] is None
    assert evidence["reason"]


def test_python_package_names_are_canonicalised():
    evidence = python_remediation("# Remediation\nUpgrade `my_package` to version 2.0 or higher.",
                                  "My-Package", "1.0", True)
    assert evidence["upgrade_to"] == "My-Package@2.0"


def test_explicit_result_fixes_take_precedence_over_markdown():
    sarif = json.loads(FIXTURE.read_text(encoding="utf-8"))["runs"][0]
    result = sarif["results"][0]
    rule = next(r for r in sarif["tool"]["driver"]["rules"] if r["id"] == result["ruleId"])
    result["fixes"] = [{"description": {"text": "There is no fixed version for this vulnerability"}}]
    finding = extract_finding(result, rule, "sca")
    assert finding["remediation"]["fixable"] is False
    assert "remediation_evidence" not in finding


def test_real_sarif_routes_to_one_requirements_batch_and_python_llm(tmp_path, monkeypatch, fake_llm):
    findings = process_sarif_file(FIXTURE, strict=True)
    assert len(findings) == 5
    assert all(f["remediation"]["fixable"] for f in findings)
    django = next(f for f in findings if f["package"]["name"].lower() == "django")
    assert django["remediation"]["upgrade_to"] == "django@4.2.11"
    batches = build_batches(classify(filter_actionable(findings)), "asva-pygoat", "12345678", "run")
    assert len(batches) == 1
    batch = batches[0][1]
    assert batch["batch_type"] == "sca" and batch["total_files"] == 1
    assert batch["files_to_fix"][0]["file"] == "requirements.txt"
    path = tmp_path / "batch.json"
    path.write_text(json.dumps(batch), encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("certifi==2022.12.7\nDjango==4.2\n", encoding="utf-8")
    monkeypatch.setattr(config, "FIX_PATH_PREFIX", "")
    process_batch(path, str(tmp_path))
    assert len(fake_llm.calls) == 1
    assert "Python dependencies" in fake_llm.calls[0]
    assert "requirements.txt" in fake_llm.calls[0]
