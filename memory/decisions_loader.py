"""
memory/decisions_loader.py
==========================
Loads and applies reviewer decisions from decisions.json.
"""

import json
import os
import sys
from pathlib import Path
from datetime import datetime, timezone


# Local sample file. In CI the workflow downloads the dashboard's file from Azure
# (<container>/<app>/memory/decisions.json) and points ASVA_DECISIONS_PATH at it.
DECISIONS_PATH = Path(__file__).parent / "decisions.json"

VALID_DECISIONS = {"retry_fix", "needs_manual_fix", "accepted_risk", "false_positive"}
REQUIRED_FIELDS = ("finding_key", "decision", "decided_by", "decided_at")


def get_decisions_path() -> Path:
    env_path = os.environ.get("ASVA_DECISIONS_PATH")
    return Path(env_path) if env_path else DECISIONS_PATH


def load_decisions_file() -> dict:
    """Load decisions.json — returns empty dict if file doesn't exist."""
    path = get_decisions_path()
    if not path.exists():
        print(f"[memory] No decisions file at {path}; no reviewer decisions applied.")
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    print(f"[memory] Loaded {len(data.get('decisions', []))} decision(s) from {path}")
    return data


def validate_decisions(data: dict) -> list[str]:
    """Return a list of format problems in a decisions file (empty list = valid)."""
    if not isinstance(data.get("decisions"), list):
        return ["top-level 'decisions' must be a list"]

    errors = []
    for i, d in enumerate(data["decisions"]):
        label = f"decisions[{i}] ({d.get('finding_key', '?')})"
        missing = [f for f in REQUIRED_FIELDS if not d.get(f)]
        if missing:
            errors.append(f"{label}: missing {', '.join(missing)}")
        if d.get("decision") not in VALID_DECISIONS:
            errors.append(f"{label}: unknown decision '{d.get('decision')}'")
        if d.get("finding") and make_finding_key(d["finding"]) != d.get("finding_key"):
            errors.append(
                f"{label}: finding_key does not match its finding metadata "
                f"(expected '{make_finding_key(d['finding'])}')"
            )
    return errors



def make_finding_key(finding: dict) -> str:
    """Generate a key using the dashboard's finding_key format (findingKey in the dashboard's
    src/lib/compare.ts): rule_id|file|line for SAST, cve-or-rule_id|package for SCA and container."""
    identifiers = finding.get("identifiers") or {}
    location = finding.get("location") or {}

    # Support both nested scanner findings and the dashboard's flattened metadata.
    metadata = finding.get("finding") or finding
    finding_type = finding.get("finding_type") or metadata.get("finding_type") or "sast"

    if finding_type == "sast":
        rule_id = identifiers.get("rule_id") or metadata.get("rule_id") or "unknown"
        file = location.get("file") or metadata.get("file") or "unknown"
        line = location.get("line")
        if line is None:
            line = metadata.get("line")
        if line is None:
            line = "0"
        return f"{rule_id}|{file}|{line}"

    # Container findings are OS packages inside an image; the dashboard keys them by package too.
    if finding_type in ("sca", "container"):
        cve = identifiers.get("cve") or metadata.get("cve")
        rule_id = identifiers.get("rule_id") or metadata.get("rule_id") or "unknown"
        package = location.get("package") or metadata.get("package") or "unknown"

        # If package and version are separate, combine them.
        version = location.get("version") or metadata.get("version")
        if version and "@" not in package:
            package = f"{package}@{version}"

        key = cve or rule_id
        return f"{key}|{package}"

    return "unknown"



def find_decision(decisions_data: dict, finding_key: str) -> dict | None:
    """Find a matching decision for a finding_key. Returns None if expired or not found."""
    now = datetime.now(timezone.utc).isoformat()

    for d in decisions_data.get("decisions", []):
        if d["finding_key"] == finding_key:
            # check expiry
            if d.get("expires_at") and d["expires_at"] < now:
                return None
            return d
    return None


def apply_decision(decision: dict, finding: dict) -> str:
    """
    Apply a decision to a finding.
    Returns action: 'fix_with_hint' | 'skip_pr' | 'skip' | 'fix'
    """
    d_type = decision["decision"]

    if d_type == "retry_fix":
        print(f"    [MEMORY] Retry fix requested by {decision['decided_by']}: {decision['note']}")
        finding["retry_hint"] = decision["note"]
        finding["memory_applied"] = {
            "decision": d_type,
            "decided_at": decision["decided_at"]
        }
        return "fix_with_hint"

    elif d_type == "needs_manual_fix":
        print(f"    [MEMORY] Needs manual fix — skipping PR: {decision['note']}")
        finding["memory_applied"] = {
            "decision": d_type,
            "decided_at": decision["decided_at"],
            "note": decision.get("note", ""),  # shown by the PR check (agent_loop.save_for_pr_check)
        }
        return "skip_pr"

    elif d_type in ("accepted_risk", "false_positive"):
        print(f"    [MEMORY] {d_type} — skipping: {decision['note']}")
        finding["memory_applied"] = {
            "decision": d_type,
            "decided_at": decision["decided_at"],
            "note": decision.get("note", ""),
        }
        return "skip"

    return "fix"

if __name__ == "__main__":
    # Format check: python -m memory.decisions_loader [path]
    if len(sys.argv) > 1:
        os.environ["ASVA_DECISIONS_PATH"] = sys.argv[1]
    data = load_decisions_file()
    if not data:
        sys.exit(0)
    problems = validate_decisions(data)
    for p in problems:
        print(f"[memory] INVALID: {p}")
    if not problems:
        print("[memory] Decisions file format OK.")
    sys.exit(1 if problems else 0)
