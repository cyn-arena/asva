"""Shared Playwright helpers for the browser e2e tier."""

from __future__ import annotations

from playwright.sync_api import Page


def login(page: Page, base_url: str, username: str, password: str) -> None:
    """Log in through the real login form (not a raw POST), so session cookies and any
    CSRF token are handled exactly as a real user's browser would."""
    page.goto(f"{base_url}/login")
    page.fill("#userName", username)
    page.fill("#password", password)
    page.click("#loginform button[type=submit]")
    page.wait_for_load_state("networkidle")
