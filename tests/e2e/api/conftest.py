from __future__ import annotations

import pytest

from tests.e2e.api._helpers import login_client


@pytest.fixture
def user1_client(target_base_url):
    """Logged in as user1 (_id=2, "John Doe") -- the standard non-admin seed user."""
    client = login_client(target_base_url, "user1", "User1_123")
    yield client
    client.close()


@pytest.fixture
def user2_client(target_base_url):
    """Logged in as user2 (_id=3, "Will Smith") -- used as the "victim" account that
    user1 should never be able to see or modify."""
    client = login_client(target_base_url, "user2", "User2_123")
    yield client
    client.close()
