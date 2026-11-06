#!/usr/bin/env python3
"""Regenerate tests/fixtures/sarif/*.sarif.json from the real samples/scans/*.sarif.json.

Run this whenever the Snyk SARIF schema changes and the trimmed fixtures need
refreshing. It keeps a small, hand-picked set of results (chosen to cover direct
vs transitive SCA deps, critical-promotion, no-fix, and varied SAST severities)
plus only the rules those results reference, so the trimmed files stay valid
SARIF without carrying the full ~200-1000 result payload.

Usage (from repo root):
    python scripts/make_test_fixtures.py
"""

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCANS_DIR = REPO_ROOT / "samples" / "scans"
OUT_DIR = REPO_ROOT / "tests" / "fixtures" / "sarif"

# ruleId (or first N results, if a ruleId list isn't given) to keep per source file.
SELECTIONS = {
    "nodegoat-sca.sarif.json": {
        "out": "sca_sample.sarif.json",
        "rule_ids": [
            "npm:marked:20150520",     # direct dependency, has a fixed version
            "SNYK-JS-QS-14724253",     # transitive dependency
        ],
        "fallback_count": 4,  # used if none of rule_ids are found
    },
    "nodegoat-image.sarif.json": {
        "out": "container_sample.sarif.json",
        "rule_ids": [
            "SNYK-UBUNTU1604-GLIBC-2356812",  # CVSS 9.8 -> promoted to critical
        ],
        "fallback_count": 4,
    },
    "nodegoat-sast.sarif.json": {
        "out": "sast_sample.sarif.json",
        # (ruleId, uri-prefix) pairs — a ruleId alone can match both an app file and a
        # node_modules file, so pin the file too. Chosen to cover: error/warning/note
        # levels, and one node_modules hit (to exercise triage's node_modules filter).
        "rule_uri_pairs": [
            ("javascript/CodeInjection", "app/routes/contributions.js"),        # error, A1 (eval)
            ("javascript/Ssrf", "app/routes/research.js"),                      # error, SSRF
            ("javascript/OR", "app/routes/index.js"),                           # warning, A10 (open redirect)
            ("javascript/NoRateLimitingForExpensiveWebOperation", "app/routes/contributions.js"),  # warning
            ("javascript/WebCookieSecureDisabledByDefault", "app/views/login.html"),  # note
            ("javascript/CodeInjection", "node_modules/ajv/scripts/bundle.js"),  # warning, node_modules
        ],
        "fallback_count": 6,
    },
}


def trim(src_name: str, spec: dict) -> None:
    src = SCANS_DIR / src_name
    if not src.exists() or src.stat().st_size == 0:
        print(f"[skip] {src} missing or empty")
        return

    data = json.loads(src.read_text(encoding="utf-8"))
    run = data["runs"][0]
    results = run["results"]
    rules = run["tool"]["driver"]["rules"]
    rules_by_id = {r["id"]: r for r in rules if "id" in r}

    def uri_of(r: dict) -> str:
        return r.get("locations", [{}])[0].get("physicalLocation", {}) \
            .get("artifactLocation", {}).get("uri", "")

    picked: list[dict] = []
    if "rule_uri_pairs" in spec:
        for rule_id, uri in spec["rule_uri_pairs"]:
            match = next(
                (r for r in results if r.get("ruleId") == rule_id and uri_of(r) == uri),
                None,
            )
            if match:
                picked.append(match)
    else:
        wanted_ids = set(spec.get("rule_ids", []))
        picked = [r for r in results if r.get("ruleId") in wanted_ids]

    if len(picked) < spec["fallback_count"] and "rule_uri_pairs" not in spec:
        # Some/all requested rule ids weren't found (schema drift) — pad with the
        # first few results so the fixture still has something to assert on.
        seen_keys = {id(r) for r in picked}
        for r in results:
            if len(picked) >= spec["fallback_count"]:
                break
            if id(r) not in seen_keys:
                picked.append(r)

    picked = picked[: max(len(picked), spec["fallback_count"])]
    used_rule_ids = {r.get("ruleId") for r in picked}
    used_rules = [rules_by_id[rid] for rid in used_rule_ids if rid in rules_by_id]

    trimmed = {
        **data,
        "runs": [{
            **run,
            "tool": {**run["tool"], "driver": {**run["tool"]["driver"], "rules": used_rules}},
            "results": picked,
        }],
    }

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / spec["out"]
    out_path.write_text(json.dumps(trimmed, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[wrote] {out_path}  ({len(picked)} result(s), {len(used_rules)} rule(s))")


def main() -> None:
    for src_name, spec in SELECTIONS.items():
        trim(src_name, spec)


if __name__ == "__main__":
    main()
