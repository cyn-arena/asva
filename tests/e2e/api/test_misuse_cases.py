"""Blue-vs-green misuse-case suite: request-level checks for the six A-case
vulnerabilities the fix pipeline targets, plus the scanner-backed configuration check.
The behavioural cases are keyed against tests/expectations.py so a case not yet
remediated on a given target skips instead of failing.

Run against blue (unpatched) or green (patched) via BASE_URL, e.g.:
    BASE_URL=http://localhost:4000 pytest -m api   # blue
    BASE_URL=http://localhost:4001 pytest -m api   # green

TARGET env var picks which side of tests/expectations.py to check against ("blue",
"green", or "candidate" -- a pre-merge fix-PR's own ephemeral instance, always FIXED, see
tests/expectations.py::expected); defaults to "blue" so a stray run against an unlabelled
target doesn't silently pass on a false FIXED expectation.

A `# @a <repo-relative-file>` comment block directly above a test names the file(s) a fix
for that test would touch. `agent.failure_capture.py` uses annotations for captured
vulnerable cases, while `agent.pr_test_selector.py` uses them to select a PR check.
"""

from __future__ import annotations

import os
import json
import re
import subprocess
from pathlib import Path

import pytest

from agent.failure_capture import capture_if_vulnerable
from agent.candidate_source import application_path
from tests.e2e.api._helpers import assert_case
from tests.expectations import expected

pytestmark = pytest.mark.api

TARGET = os.environ.get("TARGET", "blue")
REPO_ROOT = Path(__file__).resolve().parents[3]


# @a app/data/allocations-dao.js
# @a app/routes/allocations.js
# @a app/routes/index.js
def test_idor_allocations(request, user1_client, user2_client):
    """user1 asks for user2's allocations by putting user2's id straight in the URL.
    The route trusts req.params.userId instead of the logged-in session's own id
    (allocations.js) -- vulnerable behavior is user2's own name showing up in the
    response to user1's request."""
    user2_own = user2_client.get("/allocations/3")
    assert user2_own.status_code == 200
    assert "Will Smith" in user2_own.text  # sanity: user2 really is "Will Smith"

    resp = user1_client.get("/allocations/3")
    leaked = resp.status_code == 200 and "Will Smith" in resp.text
    detail = "user1 requesting /allocations/3 (user2's id) should not surface user2's name"
    capture_if_vulnerable(request.node.nodeid, leaked, detail)
    assert_case(expected("a4_idor", TARGET), leaked, detail)


# @a app/routes/index.js
def test_missing_access_control_benefits(request, user1_client):
    """user1 (non-admin) POSTs a benefits change directly -- /benefits has no isAdmin
    check on the update handler (index.js), so nothing but the isLoggedIn middleware
    stands in the way."""
    resp = user1_client.post(
        "/benefits", data={"userId": "3", "benefitStartDate": "2099-01-01"}
    )
    # A non-admin being let all the way through to a 200 render (rather than turned
    # away at /login or a 403) is the vulnerable behavior.
    allowed = resp.status_code == 200
    detail = "user1 (non-admin) POSTing /benefits should be rejected, not rendered"
    capture_if_vulnerable(request.node.nodeid, allowed, detail)
    assert_case(expected("a2_missing_access_control", TARGET), allowed, detail)


# @a app/routes/index.js
def test_unvalidated_redirect_learn(user1_client):
    """/learn?url= redirects wherever the query string says, with no same-origin
    check (index.js) -- classic open redirect, useful for phishing."""
    off_site = "https://example.com/phish"
    resp = user1_client.get("/learn", params={"url": off_site})
    redirected_off_site = (
        resp.status_code in (301, 302, 303, 307, 308)
        and resp.headers.get("location") == off_site
    )
    assert_case(
        expected("a10_unvalidated_redirect", TARGET),
        redirected_off_site,
        f"/learn?url={off_site} should not redirect off-site",
    )


# @a app/routes/contributions.js
def test_ssji_eval_contributions(user1_client):
    """preTax="(2+3)" is not a valid percentage, but eval() (contributions.js) happily
    computes it to 5 and accepts it; parseInt() (the real fix) can't parse a string
    starting with "(" and correctly rejects it as invalid. Distinguishes blue from
    green without running any actually dangerous payload."""
    resp = user1_client.post(
        "/contributions", data={"preTax": "(2+3)", "afterTax": "0", "roth": "0"}
    )
    accepted_as_valid = (
        resp.status_code == 200 and "Invalid contribution percentages" not in resp.text
    )
    assert_case(
        expected("a1_ssji_eval", TARGET),
        accepted_as_valid,
        "preTax='(2+3)' should be rejected as invalid, not evaluated to 5",
    )


# @a app/routes/profile.js
def test_redos_regex_bankrouting_still_validates(user1_client):
    """Check normal validation behavior without timing or expensive ReDoS payloads."""
    resp = user1_client.post(
        "/profile",
        data={
            "firstName": "John",
            "lastName": "Doe",
            "ssn": "",
            "dob": "",
            "address": "",
            "bankAcc": "",
            "bankRouting": "not-a-routing-number",
        },
    )
    assert resp.status_code == 200
    assert "does not comply with requirements" in resp.text


# @a app/routes/research.js
def test_ssrf_research_symbol_lookup(user1_client, target_base_url):
    """?url= gets ?symbol= appended and fetched server-side with no allowlist
    (research.js) -- pointing url at this same instance's own /login page and getting
    its markup reflected back in the response proves the server followed a fully
    attacker-controlled destination, without the test ever reaching outside this
    instance."""
    resp = user1_client.get(
        "/research", params={"url": f"{target_base_url}/login", "symbol": "#"}
    )
    ssrf_confirmed = resp.status_code == 200 and 'name="userName"' in resp.text
    detail = "research?url= should not fetch and reflect an arbitrary attacker-supplied URL"
    assert_case(expected("a10_ssrf", TARGET), ssrf_confirmed, detail)


# @a config/env/development.js
def test_development_zap_key_uses_environment_and_rescans_clean(tmp_path):
    """Verify the CWE-547 candidate both directly and with an independent Snyk rescan."""
    app_root = application_path(REPO_ROOT / "target-apps" / "NodeGoat")
    config_path = app_root / "config" / "env" / "development.js"
    source = config_path.read_text(encoding="utf-8")
    uses_environment = bool(re.search(
        r"zapApiKey\s*:\s*process\.env(?:\.ZAP_API_KEY\b|\[\s*[\"'`]ZAP_API_KEY[\"'`]\s*\])", source
    ))
    has_literal = bool(re.search(r"zapApiKey\s*:\s*[\"'`][^\"'`]+[\"'`]", source))

    if TARGET == "blue":
        assert has_literal and not uses_environment
        return

    assert uses_environment and not has_literal, (
        "development.js must load zapApiKey from process.env.ZAP_API_KEY and must not "
        "contain a literal key"
    )

    sentinel = "asva-zap-key-from-environment"
    node_check = subprocess.run(
        [
            "node",
            "-e",
            (
                "process.env.ZAP_API_KEY=process.argv[1];"
                "const c=require('./config/env/development.js');"
                "if(c.zapApiKey!==process.argv[1])process.exit(1);"
            ),
            sentinel,
        ],
        cwd=app_root,
        capture_output=True,
        text=True,
    )
    assert node_check.returncode == 0, (
        "development configuration did not return the ZAP_API_KEY environment value: "
        f"{node_check.stderr or node_check.stdout}"
    )

    # The live scanner check is only needed for a candidate PR. Green may be a deployed
    # environment whose source checkout is not the exact code serving BASE_URL.
    if TARGET != "candidate":
        return

    sarif_path = tmp_path / "candidate-sast.sarif.json"
    command = ["snyk", "code", "test", f"--sarif-file-output={sarif_path}"]
    if org := os.environ.get("SNYK_ORG"):
        command.append(f"--org={org}")
    scan = subprocess.run(command, cwd=app_root, capture_output=True, text=True)
    assert scan.returncode in (0, 1), f"Snyk candidate scan failed: exit {scan.returncode}"
    assert sarif_path.exists(), (
        "Snyk did not produce a candidate SARIF report: "
        f"{scan.stderr or scan.stdout or f'exit {scan.returncode}'}"
    )

    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert sarif.get("runs"), "Candidate Snyk report has no completed scan run"
    persisted = []
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            if result.get("ruleId") != "javascript/HardcodedNonCryptoSecret":
                continue
            for location in result.get("locations", []):
                uri = (
                    location.get("physicalLocation", {})
                    .get("artifactLocation", {})
                    .get("uri", "")
                    .replace("\\", "/")
                )
                if uri.endswith("config/env/development.js"):
                    persisted.append(uri)

    assert persisted == [], (
        "CWE-547 persisted in the post-fix Snyk rescan of development.js"
    )
