"""
agent/rag_client.py -- the fix agent's access to the RAG (ITP2 3.3, security_context/).

A thin layer over the service's own client (security_context/integration/asva_rag_client.py).
The RAG is an enhancement, so a failure is logged and the agent carries on without it: after the
first failure it is not asked again in this run, so a hung service costs one timeout, not one per
file. Off when ASVA_RAG_URL is empty (the fix workflows set it once the container is healthy).
The client remembers answers for the life of the process, so asking twice costs nothing.
"""

from __future__ import annotations

from pathlib import Path

from security_context.integration import asva_rag_client as _client

# GitHub rejects a PR body over 65,536 characters; leave room for ASVA's own part of the body.
PR_TEXT_LIMIT = 45_000

_unavailable = False


def enabled() -> bool:
    return _client.enabled() and not _unavailable


def response(findings: list[dict], fix_type: str, *, manifest: tuple[str, str] | None = None,
             dev_only: list[str] | None = None, copies: dict | None = None) -> dict | None:
    """The RAG's answer for one file's findings, or None when it is off or something went wrong."""
    global _unavailable
    if not findings or not enabled():
        return None
    try:
        return _client.fetch_context(findings, fix_type, manifest=manifest, dev_only=dev_only, copies=copies)
    except _client.RAGUnavailableError as e:
        _unavailable = True
        print(f"    [WARN] RAG unavailable ({e}) — continuing without it for the rest of this run")
        return None


def prompt_context(file_path: str, findings: list[dict], fix_type: str) -> str:
    """The RAG's reference material for one file's findings, as one block for FixContext.rag."""
    answer = response(findings, fix_type)
    if answer is None:
        return ""
    text = _client.prompt_block(answer)
    print(f"    RAG context: {len(text)} chars")
    for warning in answer.get("warnings") or []:
        print(f"    RAG note: {warning}")
    return text


def npm_response(findings: list[dict], fix_type: str, manifest_text: str, lock_text: str) -> dict | None:
    """The answer for an npm dependency file, with the trial plan for the candidate npm just wrote."""
    if not enabled():
        return None
    names = sorted({((f.get("location") or {}).get("package") or "").rsplit("@", 1)[0] for f in findings} - {""})
    return response(findings, fix_type, manifest=("package.json", manifest_text),
                    dev_only=_client.npm_dev_only(lock_text), copies=_client.npm_copies(lock_text, names))


def manifest_response(file_path: str, content: str, findings: list[dict], fix_type: str) -> dict | None:
    """The answer for a dependency file the LLM edits, with the trial plan for that file."""
    return response(findings, fix_type, manifest=(Path(file_path).name, content))


def held_back(answer: dict | None) -> list[str]:
    return _client.held_back(answer)


def pr_text(*answers: dict | None) -> str:
    """The RAG's part of a PR body: upgrade summary, upgrades to try next, references. The references
    come last and are what gets cut when a big batch would not fit in a PR body."""
    sections = [_client.pr_upgrades(*answers), _client.trial_plan(*answers)]
    text = "\n\n".join(s for s in sections if s)
    references = _client.pr_references(*answers)
    room = PR_TEXT_LIMIT - len(text)
    if len(references) > room:
        kept = references[:max(room, 0)].rsplit("\n", 1)[0]
        references = f"{kept}\n\n*... references cut here to fit the PR description.*" if kept else ""
    return "\n\n".join(s for s in (text, references) if s)
