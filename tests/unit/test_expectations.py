"""Unit tests for tests/expectations.py -- the per-target expected-state table used by
tests/e2e/api/test_misuse_cases.py, including the "candidate" target added for pr-check."""

from __future__ import annotations

import pytest

from tests.expectations import CASES, State, expected

pytestmark = pytest.mark.unit


def test_expected_blue_is_vulnerable_for_every_case():
    for case in CASES:
        assert expected(case.case_id, "blue") == State.VULNERABLE


def test_expected_green_matches_the_table():
    assert expected("a1_ssji_eval", "green") == State.FIXED
    assert expected("a1_redos_bankrouting", "green") == State.FIXED
    assert expected("a4_idor", "green") == State.UNKNOWN
    assert expected("a2_missing_access_control", "green") == State.UNKNOWN
    assert expected("a10_unvalidated_redirect", "green") == State.UNKNOWN
    assert expected("a10_ssrf", "green") == State.UNKNOWN


def test_expected_candidate_is_always_fixed_even_when_green_is_unknown():
    # a4_idor is UNKNOWN on green (never confirmed merged) -- candidate must still assert
    # FIXED unconditionally, since a PR only reaches pr-check by claiming to fix it.
    assert expected("a4_idor", "candidate") == State.FIXED
    assert expected("a2_missing_access_control", "candidate") == State.FIXED
    assert expected("a10_unvalidated_redirect", "candidate") == State.FIXED
    assert expected("a1_ssji_eval", "candidate") == State.FIXED
    assert expected("a1_redos_bankrouting", "candidate") == State.FIXED
    assert expected("a10_ssrf", "candidate") == State.FIXED


def test_expected_rejects_unknown_target():
    with pytest.raises(ValueError):
        expected("a1_ssji_eval", "purple")


def test_expected_unknown_case_id_raises():
    with pytest.raises(KeyError):
        expected("not_a_real_case", "candidate")
