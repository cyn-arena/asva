"""Ask a running service to sync sources (POST /admin/sync). Used by the Kubernetes CronJobs.

    python -m app.trigger kev nvd          # SERVICE_URL and ADMIN_TOKEN from the environment
    python -m app.trigger                  # all sources

Uses only the standard library, so it runs in the same image with no extra setup.
"""

import json
import os
import sys
import urllib.error
import urllib.request


def main(argv: list[str]) -> int:
    url = os.environ.get("SERVICE_URL", "http://localhost:8000").rstrip("/") + "/admin/sync"
    token = os.environ.get("ADMIN_TOKEN", "")
    if not token:
        print("ADMIN_TOKEN is not set", file=sys.stderr)
        return 2
    body = json.dumps({"sources": argv or None, "force": False}).encode()
    request = urllib.request.Request(url, data=body, method="POST", headers={
        "Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            print(f"{response.status}: {response.read().decode()}")
            return 0
    except urllib.error.HTTPError as error:
        print(f"{error.code}: {error.read().decode()}", file=sys.stderr)
        return 0 if error.code == 409 else 1  # 409 = a sync is already running: fine for a CronJob
    except urllib.error.URLError as error:
        print(f"cannot reach {url}: {error.reason}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
