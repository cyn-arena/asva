"""
agent/fix_context.py -- the single entry point for extra context in a fix prompt.

Three ITP2 features add text to the same fix prompt: RAG security guidance (3.3), memory of
previous attempts (3.5) and repo-aware usage context (3.1). They all go through FixContext,
so the prompt has one place, one order and one set of labels for extra context, rather than
three separate parameters.

Each provider is responsible for capping its own section. An empty FixContext renders to "",
so a prompt without context is byte-identical to the pre-ITP2 prompt.
"""

from __future__ import annotations

from dataclasses import dataclass

# (field name, section heading) in render order: guidance about the vulnerability first,
# then history for this finding, then where this file is used.
_SECTIONS: tuple[tuple[str, str], ...] = (
    ("rag", "Security guidance for these findings"),
    ("memory", "Previous remediation attempts for these findings"),
    ("repo", "Related code in the app"),
)


@dataclass(frozen=True)
class FixContext:
    rag: str = ""      # 3.3: authoritative vuln/mitigation guidance for this file's findings
    memory: str = ""   # 3.5: prior attempts and outcomes for this finding fingerprint
    repo: str = ""     # 3.1: importers, call sites, local imports and SAST data flow of this file

    def is_empty(self) -> bool:
        return not any(getattr(self, name).strip() for name, _ in _SECTIONS)


def render_context(context: FixContext | None) -> str:
    """Render the non-empty sections as one read-only block, ending in a blank line so it
    can be dropped straight into a prompt template. Returns "" when there is nothing."""
    if context is None or context.is_empty():
        return ""
    parts = [
        "Additional context (read-only reference. Do NOT edit, rewrite or return any other "
        "file shown here; use it only to keep your fix compatible):",
    ]
    for name, heading in _SECTIONS:
        body = getattr(context, name).strip()
        if body:
            parts.append(f"\n### {heading}\n{body}")
    return "\n".join(parts) + "\n\n"
