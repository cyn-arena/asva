"""
agent/test_annotations.py -- parse "# @a <repo-relative-file>" header comments above a
test function.

A misuse-case test for a business-logic bug (A4 IDOR, A2 missing access control) can't be
found by the scanner, so there's no SARIF finding to point the fix agent at a file. This
convention lets a test name its own fix target(s) directly, in plain text any tool (or
human) can grep for -- not a pytest-only mechanism.

Convention: one or more contiguous "# @a <path>" comment lines directly above a
`def test_...` line (or its decorators, if any sit between the comments and the def).
"""

from __future__ import annotations

import ast
import re

_ANNOTATION_RE = re.compile(r"^\s*#\s*@a\s+(\S+)\s*$")


def parse_annotated_files(source: str) -> dict[str, list[str]]:
    """Map test function name -> list of annotated files, in source order.

    Only functions with at least one "# @a" line directly above them appear in the
    result; a test with no annotation is not a candidate for the browser-failure ->
    fix-agent handoff.
    """
    lines = source.splitlines()
    tree = ast.parse(source)

    result: dict[str, list[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not node.name.startswith("test_"):
            continue
        top_line = node.decorator_list[0].lineno if node.decorator_list else node.lineno
        files = _scan_upward(lines, top_line)
        if files:
            result[node.name] = files
    return result


def _scan_upward(lines: list[str], def_or_decorator_line: int) -> list[str]:
    """Collect contiguous "# @a <path>" lines directly above `def_or_decorator_line`
    (1-indexed), stopping at the first line that isn't an annotation."""
    files: list[str] = []
    i = def_or_decorator_line - 2  # 0-indexed line just above
    while i >= 0:
        m = _ANNOTATION_RE.match(lines[i])
        if not m:
            break
        files.append(m.group(1))
        i -= 1
    files.reverse()
    return files
