#!/usr/bin/env python3
"""Save trimmed real API answers as test fixtures (one-off maintenance; needs the network).

    python tools/capture_fixtures.py

Writes, under tests/fixtures/:
  osv_ubuntu_<cve>.json     OSV.dev's copy of Ubuntu's security data for a CVE (per-release fixes)
  dockerhub_mongo.json      the mongo image's tags and, per release line, its image config
  endoflife_mongodb.json    release and end-of-life dates per MongoDB line
The unit tests answer from these files through tests/conftest.py and never call the network.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import net  # noqa: E402
from app.sources import lifecycle, osv, registry  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"
OSV_CVES = {"CVE-2026-8376": ["perl"], "CVE-2021-46848": ["libtasn1-6"], "CVE-2022-23219": ["glibc"]}
IMAGE, LINES = "mongo", ["4.4", "5.0", "6.0", "7.0", "8.0", "9.0"]


def save(name: str, data) -> None:
    path = FIXTURES / name
    path.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {path.name} ({path.stat().st_size:,} bytes)")


def main() -> None:
    with net.make_client(timeout=60) as client:
        for cve, packages in OSV_CVES.items():
            vuln = net.request(client, "GET", osv.VULN_API_URL.format(id=f"UBUNTU-{cve}")).json()
            affected = [{"package": a["package"], "ranges": a.get("ranges", []),
                         "ecosystem_specific": {"availability": (a.get("ecosystem_specific") or {}).get("availability")}}
                        for a in vuln.get("affected", []) if a["package"]["name"] in packages]
            save(f"osv_ubuntu_{cve.lower().replace('-', '_')}.json",
                 {"id": vuln["id"], "upstream": vuln.get("upstream", []), "affected": affected})

        repository = registry.repository_of(IMAGE)
        token = net.request(client, "GET", registry.AUTH_URL, params={
            "service": "registry.docker.io", "scope": f"repository:{repository}:pull"}).json()["token"]
        auth = {"Authorization": f"Bearer {token}"}
        base = registry.REGISTRY_URL.format(repository=repository)
        configs = {}
        for tag in LINES:
            headers = {**auth, "Accept": registry.MANIFEST_TYPES}
            index = net.request(client, "GET", f"{base}/manifests/{tag}", headers=headers).json()
            digest = next(m["digest"] for m in index["manifests"] if (m.get("platform") or {}).get("os") == "linux"
                          and (m.get("platform") or {}).get("architecture") == "amd64")
            manifest = net.request(client, "GET", f"{base}/manifests/{digest}", headers=headers).json()
            config = net.request(client, "GET", f"{base}/blobs/{manifest['config']['digest']}", headers=auth).json()
            configs[tag] = {"created": config.get("created"),
                            "config": {"Labels": (config.get("config") or {}).get("Labels"),
                                       "Env": [e for e in (config.get("config") or {}).get("Env", []) if "VERSION" in e]},
                            "history": config.get("history", [])[:3]}
        save("dockerhub_mongo.json", {"tags": ["latest", "4", "4.4.30", "8.0.32-noble", *LINES], "configs": configs})

        cycles = net.request(client, "GET", lifecycle.API_URL.format(product="mongodb")).json()
        save("endoflife_mongodb.json", [c for c in cycles if str(c.get("cycle")) in LINES])


if __name__ == "__main__":
    main()
