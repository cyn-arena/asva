"""
memory/memory_context.py
=========================
Builds the memory section (3.5) of the fix prompt.

The prompt itself is built in agent/agent_loop.py (build_fix_prompt). Extra context goes
through agent/fix_context.FixContext, which has one field per ITP2 feature:
rag (3.3), memory (3.5) and repo (3.1). This module renders the text for the memory field:

    Memory = Decisions + Code Context
    Code Context = remediated files committed in passes 1 to N-1 + errors from pass N-1 only
"""

# FixContext asks each provider to cap its own section. Previous attempts carry whole files,
# so keep the newest ones and drop the rest rather than crowd out the file being fixed.
MEMORY_SECTION_LIMIT = 12000
# One error can carry the end of the app's log; keep enough to name the cause.
ERROR_LIMIT = 1500


def _newest_first(history: list[dict]) -> list[dict]:
    # created_at has one-second resolution; the row id breaks ties in the order rows were saved
    return sorted(history, key=lambda h: (h.get("created_at") or "", h.get("id") or 0), reverse=True)


def previous_errors(history: list[dict]) -> tuple[str | None, list[str]]:
    """Errors from pass N-1 only: the most recent earlier run of these findings, and what it broke
    (an app check or scan that still failed, or a gate that rejected the fix). (None, []) if none."""
    if not history:
        return None, []
    last_run = _newest_first(history)[0]["run_id"]
    errors = []
    for h in history:
        error = (h.get("error") or "").strip()
        if h["run_id"] == last_run and error and error not in errors:
            errors.append(error)
    return (str(last_run), errors) if errors else (None, [])


def build_memory_context(memory: dict, hint: str | None = None) -> str:
    """
    Text for FixContext.memory, built from:
    - hint:      reviewer instructions for these findings (dashboard retry_fix notes)
    - history:   earlier fix attempts for these findings; committed ones are shown as code
                 context, and the errors of the most recent run as "errors from pass N-1"
    Returns "" when there is nothing to add.
    """
    memory = memory or {}
    history = memory.get("history") or []
    parts = []

    # Reviewer instructions
    if hint:
        parts.append(f"Reviewer instructions (follow these when fixing the findings):\n{hint}")

    # Errors from pass N-1
    last_run, errors = previous_errors(history)
    if errors:
        lines = "\n".join(f"- {e[:ERROR_LIMIT]}" + (" ... [truncated]" if len(e) > ERROR_LIMIT else "")
                          for e in errors)
        parts.append(f"Errors from the previous pass (run {last_run}) -- avoid repeating them:\n{lines}")

    # Code context: remediated files committed in passes 1 to N-1
    committed = [h for h in history if h.get("outcome") == "committed"]
    if committed:
        # One row is saved per finding, all carrying the same whole-file content, so a
        # 26-finding package.json would otherwise repeat the file 26 times per past run.
        unique_history, seen = [], set()
        for h in _newest_first(committed):
            attempt_key = (h["run_id"], h.get("fixed_content"))
            if attempt_key not in seen:
                seen.add(attempt_key)
                unique_history.append(h)

        header = (
            "Previous fix attempts for these vulnerabilities (they are still reported, so "
            "these attempts did not fully resolve them -- do not simply repeat them):"
        )
        used = len(header) + sum(len(p) for p in parts)
        lines, omitted = [], 0
        for h in unique_history:
            line = f"- Run {h['run_id']}: {h['outcome']}"
            if h.get("fix_summary"):
                line += f" — {h['fix_summary']}"
            if h.get("fixed_content"):
                line += f"\n  Previously fixed content:\n{h['fixed_content']}"
            if lines and used + len(line) > MEMORY_SECTION_LIMIT:
                omitted += 1
                continue
            lines.append(line)
            used += len(line)
        if omitted:
            lines.append(f"- ({omitted} older attempt(s) omitted to keep the prompt short)")
        parts.append(header + "\n" + "\n".join(lines))

    return "\n\n".join(parts)
