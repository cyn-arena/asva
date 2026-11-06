#!/usr/bin/env python3
"""Does a built image start and answer? The check the image workflow
(.github/workflows/security-context.yml) runs on a fresh container before it publishes the image:

  1. /healthz answers within the wait time, with the built-in MITRE CWE, OWASP and CISA KEV data
  2. a code finding (CWE-94, eval injection) gets OWASP guidance for the prompt and its CWE's
     OWASP Top 10 label for the PR: local data only
  3. a dependency finding (marked 0.3.5, CVE-2016-10531) gets an upgrade entry. This one also
     asks NVD and OSV.dev; what they return is printed, and an outage there is a note, not a
     failure, so a slow NVD never blocks a new image

Standard library only, so it runs on a bare CI runner. Exits 1 on a failed check.

    python tools/image_check.py --url http://localhost:8000
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.request

BUILT_IN = ("MITRE CWE", "OWASP Cheat Sheet Series", "CISA KEV")
CODE_FINDING = {
    "finding_type": "sast", "cwe": "CWE-94", "rule_id": "javascript/CodeInjection", "title": "Code Injection",
    "summary": "Unsanitized input from the HTTP request body flows into eval, where it is executed as JavaScript code.",
}
DEPENDENCY_FINDING = {
    "finding_type": "sca", "cve": "CVE-2016-10531", "package": "marked@0.3.5", "ecosystem": "npm",
    "upgrade_to": "marked@0.3.6", "title": "Cross-site Scripting (XSS) vulnerability in marked",
}


def _get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=5) as response:
        return json.load(response)


def _post(url: str, payload: dict) -> dict:
    request = urllib.request.Request(url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=180) as response:
        return json.load(response)


def fail(message: str) -> None:
    print(f"FAIL  {message}")
    sys.exit(1)


def wait_for_health(url: str, seconds: int) -> dict:
    deadline = time.monotonic() + seconds
    while True:
        try:
            return _get(f"{url}/healthz")
        except (urllib.error.URLError, OSError):
            if time.monotonic() > deadline:
                fail(f"{url}/healthz did not answer within {seconds} s")
            time.sleep(2)


def main(url: str, wait: int) -> None:
    started = time.monotonic()
    health = wait_for_health(url, wait)
    if health.get("status") != "ok":
        fail(f"/healthz status is {health.get('status')!r}, not 'ok'")
    missing = [s for s in BUILT_IN if not (health.get("snapshot") or {}).get(s, {}).get("items")]
    if missing:
        fail(f"built-in data missing: {', '.join(missing)}")
    online = health.get("online") or {}
    print(f"ok    healthy after {time.monotonic() - started:.0f} s; "
          + "; ".join(f"{s}: {health['snapshot'][s]['version']}" for s in BUILT_IN))
    print(f"note  NVD key: {'yes' if online.get('nvd_api_key') else 'no'}; Context7 key: {'yes' if online.get('context7') else 'no'}")

    code = _post(f"{url}/v1/context", {"fix_type": "code_change", "findings": [CODE_FINDING]})
    guidance = [i for i in code["items"] if i["kind"] == "guidance"]
    if not guidance:
        fail("the code finding got no OWASP guidance")
    top10 = next((r.get("owasp_top10") for r in code["references"] if r["type"] == "cwe" and r["id"] == "CWE-94"), None)
    if not top10:
        fail("CWE-94 has no OWASP Top 10 label (has the CWE catalogue's format changed?)")
    print(f"ok    code finding: {len(guidance)} OWASP section(s), e.g. {guidance[0]['title']}"
          + (f" › {guidance[0]['section']}" if guidance[0].get("section") else "") + f"; CWE-94 in {'; '.join(top10)}")

    dependency = _post(f"{url}/v1/context", {"fix_type": "version_upgrade", "findings": [DEPENDENCY_FINDING]})
    upgrade = next((u for u in dependency.get("upgrades") or [] if u["name"] == "marked"), None)
    if upgrade is None:
        fail("the dependency finding got no upgrade entry for marked")
    cve = next((r for r in dependency["references"] if r["type"] == "cve"), None)
    print(f"ok    dependency finding: marked {upgrade.get('current')} → compatible fix {upgrade.get('compatible_target') or 'none'}; "
          f"CVSS from NVD: {cve.get('cvss') if cve else 'not found'}")
    for warning in dependency.get("warnings") or []:
        print(f"note  {warning}")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")  # cheat-sheet titles and arrows, also on a Windows console
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", default="http://localhost:8000")
    parser.add_argument("--wait", type=int, default=90, help="Seconds to wait for /healthz (default 90).")
    args = parser.parse_args()
    main(args.url.rstrip("/"), args.wait)
