"""memory/decisions_loader.py -- finding keys must match the dashboard's (src/lib/compare.ts
findingKey in asva-web-prototype), or a reviewer's decision is silently never applied."""

from __future__ import annotations

import json

import pytest

from memory import decisions_loader
from memory.decisions_loader import apply_decision, find_decision, make_finding_key

pytestmark = pytest.mark.unit


def _finding(finding_type, identifiers, location):
    return {"finding_type": finding_type, "identifiers": identifiers, "location": location}


# Real normalised findings from the NodeGoat pipeline (fix_batches), trimmed to the keyed fields.
SAST = _finding("sast", {"rule_id": "javascript/Ssrf", "cve": None},
                {"file": "app/routes/research.js", "line": 16})
SCA = _finding("sca", {"cve": "CVE-2026-90711", "rule_id": "SNYK-JS-PROXYADDR-19812342"},
               {"file": "package.json", "line": None, "package": "proxy-addr@2.0.4"})
SCA_NO_CVE = _finding("sca", {"cve": None, "rule_id": "SNYK-JS-HANDLEBARS-534988"},
                      {"file": "package.json", "line": None, "package": "handlebars@4.0.5"})
CONTAINER = _finding("container", {"cve": "CVE-2026-8376", "rule_id": "SNYK-UBUNTU2004-PERL-16800832"},
                     {"kind": "os_package", "file": "docker-compose.yml", "line": None,
                      "package": "perl@5.30.0-9ubuntu0.5", "image_name": "mongo", "image_tag": "4.4"})


@pytest.mark.parametrize("finding, key", [
    (SAST, "javascript/Ssrf|app/routes/research.js|16"),
    (SCA, "CVE-2026-90711|proxy-addr@2.0.4"),
    (SCA_NO_CVE, "SNYK-JS-HANDLEBARS-534988|handlebars@4.0.5"),
    (CONTAINER, "CVE-2026-8376|perl@5.30.0-9ubuntu0.5"),
])
def test_keys_match_the_dashboard(finding, key):
    assert make_finding_key(finding) == key


def test_container_key_uses_package_not_image():
    # Container findings carry image_name/image_tag, not image/version; keying by image
    # gave "CVE-...|unknown", which no dashboard decision could ever match.
    assert "unknown" not in make_finding_key(CONTAINER)


def test_dashboard_flattened_metadata_gives_the_same_key():
    decision = {"finding": {"finding_type": "container", "cve": "CVE-2026-8376",
                            "rule_id": "SNYK-UBUNTU2004-PERL-16800832",
                            "package": "perl@5.30.0-9ubuntu0.5", "file": "docker-compose.yml"}}
    assert make_finding_key(decision["finding"]) == make_finding_key(CONTAINER)


def test_container_false_positive_is_applied(tmp_path, monkeypatch):
    path = tmp_path / "decisions.json"
    path.write_text(json.dumps({"decisions": [{
        "finding_key": "CVE-2026-8376|perl@5.30.0-9ubuntu0.5", "decision": "false_positive",
        "note": "perl is not reachable in this image", "decided_by": "reviewer",
        "decided_at": "2026-11-04T00:00:00Z", "expires_at": None}]}))
    monkeypatch.setenv("ASVA_DECISIONS_PATH", str(path))
    data = decisions_loader.load_decisions_file()
    decision = find_decision(data, make_finding_key(CONTAINER))
    assert decision is not None
    assert apply_decision(decision, dict(CONTAINER)) == "skip"
