"""HTTP functional smoke checks for local or CI PyGoat; standard library only."""
import argparse
import datetime
import http.cookiejar
import json
import os
import sys
import urllib.parse
import urllib.request
import uuid
from html.parser import HTMLParser
from pathlib import Path


class Page(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.csrf = None
        self.static = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "input" and attrs.get("name") == "csrfmiddlewaretoken":
            self.csrf = attrs.get("value")
        for key in ("href", "src"):
            value = attrs.get(key, "")
            if value.startswith("/static/"):
                self.static.append(value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8001")
    parser.add_argument("--output", default="asva-results/pygoat-validation.json")
    args = parser.parse_args()
    base = args.base_url.rstrip("/")
    checks = []
    started = False
    client = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )

    def request(path, data=None):
        payload = urllib.parse.urlencode(data).encode() if data is not None else None
        req = urllib.request.Request(base + path, data=payload)
        with client.open(req, timeout=15) as response:
            return response.geturl(), response.read().decode("utf-8", errors="replace")

    def check(name, action):
        try:
            action()
            checks.append({"name": name, "kind": "smoke", "status": "passed", "detail": None})
        except Exception as exc:
            checks.append({"name": name, "kind": "smoke", "status": "failed", "detail": str(exc)})

    def require(condition, message):
        if not condition:
            raise AssertionError(message)

    def login_page():
        nonlocal started
        _, html = request("/login/")
        require(Page(html).csrf, "Login form has no CSRF token")
        started = True

    check("login page loads", login_page)
    username = "asva_" + uuid.uuid4().hex[:12]
    password = "ASVA-test-" + uuid.uuid4().hex

    def register():
        _, html = request("/register")
        token = Page(html).csrf
        require(token, "Registration form has no CSRF token")
        url, _ = request("/register", {"csrfmiddlewaretoken": token, "username": username,
            "email": username + "@example.invalid", "password1": password, "password2": password})
        require(urllib.parse.urlparse(url).path in ("/", "/login/"),
            "Registration did not redirect away from the form")

    check("register test account", register)

    def logout():
        request("/logout/")
        url, _ = request("/")
        require("login" in urllib.parse.urlparse(url).path, "Logout did not clear authentication")

    check("logout clears authentication", logout)

    def login():
        _, html = request("/login/")
        url, _ = request("/login/", {"csrfmiddlewaretoken": Page(html).csrf,
            "username": username, "password": password})
        require(urllib.parse.urlparse(url).path == "/", "Login did not reach authenticated home")

    check("login with saved account", login)

    def lab():
        url, html = request("/broken_access_control")
        require("login" not in urllib.parse.urlparse(url).path, "Lab redirected to login")
        require("broken" in html.lower(), "Lab content missing")

    check("broken access control page loads", lab)

    def assets():
        _, html = request("/")
        paths = list(dict.fromkeys(Page(html).static))
        require(paths, "No local static assets found on home page")
        for path in paths:
            with client.open(base + path, timeout=15) as response:
                require(bool(response.read()), "Empty static asset: " + path)

    check("home page static assets load", assets)
    result = {
        "app": "pygoat", "commit_sha": os.environ.get("SOURCE_SHA", "local-uncommitted"),
        "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "app_started": started, "result": "passed" if all(c["status"] == "passed" for c in checks) else "failed",
        "checks": checks,
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    for item in checks:
        if item["status"] != "passed":
            print(f"FAILED {item['name']}: {item.get('detail')}")
    return 0 if result["result"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
