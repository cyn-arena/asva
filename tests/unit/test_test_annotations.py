"""Unit tests for agent/test_annotations.py -- parsing "# @a <file>" header
comments above a test function, purely from source text (no pytest collection involved)."""

from __future__ import annotations

import pytest

from agent.test_annotations import parse_annotated_files

pytestmark = pytest.mark.unit


MULTI_SOURCE = '''\
import pytest

# @a app/data/allocations-dao.js
# @a app/routes/allocations.js
def test_idor_allocations(user1_client):
    pass


def test_no_annotation(user1_client):
    pass


# @a app/routes/index.js
def test_single_annotation():
    pass
'''

DECORATED_SOURCE = '''\
import pytest

# @a app/x.js
@pytest.mark.slow
def test_decorated():
    pass
'''

GAP_SOURCE = '''\
# @a app/x.js

def test_with_gap():
    pass
'''


def test_parse_annotated_files_multiple_files_in_order():
    result = parse_annotated_files(MULTI_SOURCE)
    assert result["test_idor_allocations"] == [
        "app/data/allocations-dao.js",
        "app/routes/allocations.js",
    ]


def test_parse_annotated_files_single_file():
    result = parse_annotated_files(MULTI_SOURCE)
    assert result["test_single_annotation"] == ["app/routes/index.js"]


def test_parse_annotated_files_unannotated_test_absent():
    result = parse_annotated_files(MULTI_SOURCE)
    assert "test_no_annotation" not in result


def test_parse_annotated_files_handles_decorator_between_comment_and_def():
    result = parse_annotated_files(DECORATED_SOURCE)
    assert result == {"test_decorated": ["app/x.js"]}


def test_parse_annotated_files_blank_line_breaks_the_chain():
    result = parse_annotated_files(GAP_SOURCE)
    assert "test_with_gap" not in result


def test_parse_annotated_files_empty_source_returns_empty():
    assert parse_annotated_files("") == {}


def test_parse_annotated_files_ignores_non_test_functions():
    source = "# @a app/x.js\ndef helper():\n    pass\n"
    assert parse_annotated_files(source) == {}
