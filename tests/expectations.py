"""Per-case, per-target expected states for the misuse-case suite.

UNKNOWN skips a case whose remediation state is not confirmed. Candidate PR targets always
expect FIXED; blue and green use the table below.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class State(Enum):
    VULNERABLE = "vulnerable"  # the exploit/misuse should succeed
    FIXED = "fixed"            # the exploit/misuse should be blocked
    UNKNOWN = "unknown"        # remediation status not yet confirmed — don't assert either way


@dataclass(frozen=True)
class CaseExpectation:
    case_id: str
    description: str
    blue: State   # dvng1 — vulnerabilities present
    green: State  # dvng2 — remediated


CASES = [
    CaseExpectation(
        "a4_idor",
        "GET /allocations/:userId — user1 requests user2's allocation data",
        blue=State.VULNERABLE, green=State.UNKNOWN,
    ),
    CaseExpectation(
        "a2_missing_access_control",
        "POST /benefits without isAdmin — non-admin changes a benefit",
        blue=State.VULNERABLE, green=State.UNKNOWN,
    ),
    CaseExpectation(
        "a10_unvalidated_redirect",
        "GET /learn?url=<off-site> — open redirect to an untrusted origin",
        blue=State.VULNERABLE, green=State.UNKNOWN,
    ),
    CaseExpectation(
        "a1_ssji_eval",
        "Malformed contribution payload — SSJI via eval() in contributions.js",
        blue=State.VULNERABLE, green=State.FIXED,
    ),
    CaseExpectation(
        "a1_redos_bankrouting",
        "Malformed bankRouting value — ReDoS-shaped regex in profile.js "
        "(assert on validation response, never on timing)",
        blue=State.VULNERABLE, green=State.FIXED,
    ),
    CaseExpectation(
        "a10_ssrf",
        "GET /research?url=<attacker-controlled>&symbol=# — server-side request "
        "forgery via needle.get() in research.js",
        blue=State.VULNERABLE, green=State.UNKNOWN,
    ),
]

_BY_ID = {c.case_id: c for c in CASES}


def expected(case_id: str, target: str) -> State:
    """Return the expected state for blue, green, or candidate.

    Candidate always returns FIXED; blue and green use the per-case table.
    """
    if target not in ("blue", "green", "candidate"):
        raise ValueError(f"target must be 'blue', 'green', or 'candidate', got {target!r}")
    case = _BY_ID[case_id]
    if target == "candidate":
        return State.FIXED
    return case.blue if target == "blue" else case.green
