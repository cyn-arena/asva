from __future__ import annotations

import pytest

from tests.e2e.browser._helpers import login


@pytest.fixture
def logged_in_page(page, target_base_url):
    """A page already logged in as the standard non-admin seed user (user1)."""
    login(page, target_base_url, "user1", "User1_123")
    return page
