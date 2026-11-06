"""Pre-merge happy-path smoke suite: login, dashboard loads, a normal contribution
submits, profile renders, and the Learning Resources link still reaches its off-site
destination. Meant to run against green (dvng2, or a local NodeGoat that matches it)
before a fix PR merges -- proves core flows still work. Attaching this result to the PR
is a separate CI/reporting concern, not done by this file.

Requires BASE_URL and Playwright's chromium browser installed
(`python -m playwright install chromium`).
"""

from __future__ import annotations

import pytest

from tests.e2e.api._helpers import login_client
from tests.e2e.browser._helpers import login

pytestmark = pytest.mark.smoke

# The Learning Resources nav link (app/views/layout.html) legitimately points OFF-SITE.
LEARN_KHAN_URL = (
    "https://www.khanacademy.org/economics-finance-domain/core-finance/"
    "investment-vehicles-tutorial/ira-401ks/v/traditional-iras"
)


def test_login_redirects_to_dashboard(page, target_base_url):
    login(page, target_base_url, "user1", "User1_123")
    assert page.url == f"{target_base_url}/dashboard"


def test_dashboard_loads_for_logged_in_user(logged_in_page, target_base_url):
    logged_in_page.goto(f"{target_base_url}/dashboard")
    assert logged_in_page.locator(".breadcrumb li.active").inner_text().strip() == "Dashboard"
    assert logged_in_page.locator("#logout-menu-link").is_visible()


def test_normal_contribution_submits(logged_in_page, target_base_url):
    logged_in_page.goto(f"{target_base_url}/contributions")
    logged_in_page.fill("input[name=preTax]", "10")
    logged_in_page.fill("input[name=roth]", "5")
    logged_in_page.fill("input[name=afterTax]", "5")
    logged_in_page.click("form[action='/contributions'] button[type=submit]")
    logged_in_page.wait_for_load_state("networkidle")

    success = logged_in_page.locator(".alert-success")
    assert success.is_visible()
    assert "Contributions updated successfully" in success.inner_text()


def test_profile_renders(logged_in_page, target_base_url):
    logged_in_page.goto(f"{target_base_url}/profile")
    assert logged_in_page.locator("#firstName").is_visible()
    assert logged_in_page.locator("#bankRouting").is_visible()
    assert logged_in_page.locator(".breadcrumb li.active").inner_text().strip() == "My Profile"


def test_learning_resources_link_reaches_offsite(target_base_url):
    """Keep the legitimate Khan Academy redirect working after open-redirect fixes."""
    client = login_client(target_base_url, "user1", "User1_123")
    try:
        resp = client.get("/learn", params={"url": LEARN_KHAN_URL})
    finally:
        client.close()
    assert resp.status_code == 302
    assert resp.headers.get("location") == LEARN_KHAN_URL
