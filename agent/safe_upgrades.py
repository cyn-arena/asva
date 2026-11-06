"""
agent/safe_upgrades.py -- which version a dependency or image fix may use (ITP2 3.3).

The scanner's upgrade_to is often a new major version, which is what broke NodeGoat (mongodb 2.x ->
3.x) and PyGoat. So before anything acts on the findings, each one's remediation.upgrade_to is
replaced by the RAG's compatible version, or cleared when there is none. The npm path and the LLM
prompt both read that field, so neither needs to know about this. The scanner's own value is kept
in remediation.scanner_upgrade_to, and that is what the RAG is asked about.

Without an answer from the RAG for a package, the plain rule applies to it: the scanner's version
if it stays in the installed major version, otherwise nothing. The rule is only a fallback: it
cannot see date-based versions or a fix within the major version that the scanner did not suggest.
"""

from __future__ import annotations

import re

from agent import rag_client

# A container image the RAG knows about and has no compatible tag for: there is nothing to edit.
_IMAGE_NOTHING_TO_EDIT = ("newer_line_needed", "rebuild_may_suffice")


def _numbers(version: str | None) -> list[int]:
    return [int(n) for n in re.findall(r"\d+", (version or "").split("-")[0])]


def same_major(current: str | None, target: str | None) -> bool:
    """Not a breaking change by the version numbers: the same major version; for 0.x, the same minor."""
    a, b = _numbers(current), _numbers(target)
    if not a or not b or a[0] != b[0]:
        return False
    return a[0] != 0 or (len(a) > 1 and len(b) > 1 and a[1] == b[1])


def _installed(finding: dict, name: str) -> str | None:
    """The installed version of `name`: the vulnerable package itself, or a parent on its dependency path."""
    for spec in [(finding.get("location") or {}).get("package"), *((finding.get("dependency") or {}).get("path") or [])]:
        found, _, version = (spec or "").rpartition("@")
        if found == name and version:
            return version
    return None


def apply(batch: dict) -> None:
    """Rewrite upgrade_to in a dependency batch's findings, in place. Records how in
    batch["upgrade_source"]: "rag", "rule" (the RAG gave no answer) or "mixed"."""
    used = set()
    kept = held = 0
    for entry in batch.get("files_to_fix", []):
        findings = [f for f in entry.get("findings", []) if f.get("finding_type") == "sca"]
        if not findings:
            continue
        answer = rag_client.response(findings, entry.get("fix_type"))
        known = {u["name"]: u for u in (answer or {}).get("upgrades") or [] if u.get("kind") == "package"}
        for f in findings:
            remediation = f.get("remediation") or {}
            scanner = remediation.get("scanner_upgrade_to", remediation.get("upgrade_to"))
            if not scanner:
                continue
            remediation["scanner_upgrade_to"] = scanner
            name, _, version = scanner.rpartition("@")
            if name in known:
                used.add("rag")
                safe = known[name].get("compatible_target")
                remediation["upgrade_to"] = f"{name}@{safe}" if safe else None
            else:
                used.add("rule")
                remediation["upgrade_to"] = scanner if same_major(_installed(f, name), version) else None
            kept += bool(remediation["upgrade_to"])
            held += not remediation["upgrade_to"]
    if used:
        batch["upgrade_source"] = used.pop() if len(used) == 1 else "mixed"
        print(f"    Safe versions ({batch['upgrade_source']}): {kept} finding(s) keep an upgrade, {held} held back")


def add_pr_text(batch: dict, answers: list[dict | None], held: dict[str, str] | None = None) -> None:
    """What the PR description says from the RAG: how the versions were chosen, any file held
    back, then the upgrade summary, upgrades to try next and references."""
    parts = [{"rule": "> **RAG unavailable:** versions were chosen by the same-major-version rule.",
              "mixed": "> **RAG had no answer for some packages:** those used the same-major-version rule.",
              }.get(batch.get("upgrade_source"), ""),
             "\n".join(f"- `{path}` was left unchanged: {reason}" for path, reason in (held or {}).items()),
             rag_client.pr_text(*answers)]
    batch["rag_pr_text"] = "\n\n".join(p for p in parts if p)


def nothing_to_edit(entry: dict) -> str:
    """Why this file should not go to the LLM at all, or "" if it should. A dependency file where
    every upgrade was held back, or an image the RAG found no compatible tag for."""
    findings = entry.get("findings", [])
    if entry.get("fix_type") != "version_upgrade" or not findings:
        return ""
    if all(f.get("finding_type") == "sca" for f in findings):
        scanner_had_one = any((f.get("remediation") or {}).get("scanner_upgrade_to") for f in findings)
        if scanner_had_one and not any((f.get("remediation") or {}).get("upgrade_to") for f in findings):
            reasons = rag_client.held_back(rag_client.response(findings, entry["fix_type"]))
            return "held back, no upgrade without a major version change" + (f": {'; '.join(reasons)}" if reasons else "")
        return ""
    if all(f.get("finding_type") == "container" for f in findings):
        answer = rag_client.response(findings, entry["fix_type"])
        images = [u for u in (answer or {}).get("upgrades") or [] if u.get("kind") == "image"]
        if images and all(not u.get("compatible_target") and u.get("status") in _IMAGE_NOTHING_TO_EDIT for u in images):
            return "held back, no compatible image: " + " ".join(u.get("note") or u["name"] for u in images)
    return ""
