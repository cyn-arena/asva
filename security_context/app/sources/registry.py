"""Docker Hub: the release lines of a container image, and what each one is built on.

Version context only, not a security authority. For an image such as mongo:4.4 it lists the
newer release lines (5.0, 6.0, 7.0 ...) with the exact version each tag ships and its base
operating system, read from the image's own metadata (no image is pulled). The base OS is
what decides whether a newer tag can resolve OS-package findings. Looked up per image when a
request needs it and cached (REGISTRY_CACHE_HOURS).

Newer lines are tags written like the current one: "16" -> "18", "20" (a line per major
version), "4.4" -> "5.0", "6.0", and with the same variant where it exists
("3.11-slim" -> "3.12-slim"). A variant is never changed for another one (alpine stays alpine).
"""

import re
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import httpx

from app import config, net, store

SOURCE = "Docker Hub"
AUTH_URL = "https://auth.docker.io/token"
REGISTRY_URL = "https://registry-1.docker.io/v2/{repository}"
HUB_URL = "https://hub.docker.com/{path}"
LICENSE = "Docker Hub image metadata (https://hub.docker.com)"
MANIFEST_TYPES = ", ".join((
    "application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"))
MAX_NEWER_LINES = 8

# "4.4.30-focal" -> line "4.4" (numbers 4, 4), patch ".30", variant "focal"; "16-alpine" -> line "16"
_TAG = re.compile(r"^v?((\d+)(?:\.(\d+))?)((?:\.\d+)*)(?:-(.+))?$")
# variant parts that name an OS release: they differ from line to line, so they are not required
_OS_RELEASE_PART = re.compile(r"^(?:focal|jammy|noble|bionic|xenial|stretch|buster|bullseye|bookworm|trixie|forky|alpine\d[\d.]*)$")
_DEBIAN_BASE = re.compile(r"debian\.sh .*?'([a-z]+)' '@")     # build step of Debian's official base image
_ALPINE_BASE = re.compile(r"alpine-minirootfs-(\d+\.\d+)")    # root filesystem of Alpine's official base image
DEBIAN_RELEASES = {"stretch": "9", "buster": "10", "bullseye": "11", "bookworm": "12", "trixie": "13", "forky": "14"}
_OTHER_REGISTRY = re.compile(r"^[^/]+[.:][^/]*/")  # "ghcr.io/org/app", "localhost:5000/app"


def repository_of(image_name: str) -> str | None:
    """Docker Hub repository for an image name, or None for images hosted elsewhere."""
    if not image_name or _OTHER_REGISTRY.match(image_name):
        return None
    return image_name if "/" in image_name else f"library/{image_name}"


def split_tag(tag: str | None) -> dict | None:
    """A versioned tag's parts: {"line": (4, 4), "text": "4.4", "is_line": False, "variant": "focal"}
    for "4.4.30-focal". `is_line` is True for a tag that names a whole release line ("4.4",
    "16-alpine"). None for tags without a version ("latest")."""
    match = _TAG.match(tag or "")
    if not match:
        return None
    numbers = (int(match.group(2)),) if match.group(3) is None else (int(match.group(2)), int(match.group(3)))
    return {"line": numbers, "text": match.group(1), "is_line": not match.group(4), "variant": match.group(5)}


def line_of(tag: str | None) -> tuple[int, ...] | None:
    """The release line a tag belongs to: (4, 4) for "4.4.30-focal", (16,) for "16-alpine"."""
    parts = split_tag(tag)
    return parts["line"] if parts else None


def line_text(tag: str | None) -> str | None:
    """The release line as the tag writes it: "4.4" for "4.4.30-focal", "24.04" for "24.04"."""
    parts = split_tag(tag)
    return parts["text"] if parts else None


def _general_variant(variant: str | None) -> str | None:
    """"slim-bookworm" -> "slim", "alpine3.20" -> "alpine", "focal" -> None."""
    kept = ["alpine" if part.startswith("alpine") else part for part in (variant or "").split("-")
            if part and (part.startswith("alpine") or not _OS_RELEASE_PART.match(part))]
    return "-".join(kept) or None


def newer_lines(tags: list[str], current_tag: str | None) -> list[str]:
    """The tags of the release lines above the current tag's, written as the current tag is:
    one or two numbers, and the same variant (or the variant without its OS release name)."""
    current = split_tag(current_tag)
    if not current:
        return []
    wanted = list(dict.fromkeys([current["variant"], _general_variant(current["variant"])]))
    found: dict[tuple, dict[str | None, str]] = {}
    for tag in tags:
        parts = split_tag(tag)
        if (parts and parts["is_line"] and not tag.startswith("v") and parts["variant"] in wanted
                and len(parts["line"]) == len(current["line"]) and parts["line"] > current["line"]):
            found.setdefault(parts["line"], {})[parts["variant"]] = tag
    lines = [next(by_variant[v] for v in wanted if v in by_variant) for _, by_variant in sorted(found.items())]
    return lines[-MAX_NEWER_LINES:]


def describe(tag: str, image_config: dict) -> dict:
    """One tag's facts from its image config: the version it ships and its base OS."""
    settings = image_config.get("config") or {}
    labels = settings.get("Labels") or {}
    env = dict(e.split("=", 1) for e in settings.get("Env") or [] if "=" in e)
    prefix = line_text(tag) or tag
    version = next((value for name, value in env.items()
                    if name.endswith("_VERSION") and (value == prefix or value.startswith(prefix + "."))), None)
    distro = (labels.get("org.opencontainers.image.ref.name") or "").lower() or None
    release = labels.get("org.opencontainers.image.version")
    history = "\n".join(h.get("created_by") or "" for h in image_config.get("history") or [])
    if not distro and "LAUNCHPAD_BUILD_ARCH" in history:
        distro = "ubuntu"  # build argument of Ubuntu's official base images
    elif not distro and (debian := _DEBIAN_BASE.search(history)):
        distro, release = "debian", DEBIAN_RELEASES.get(debian.group(1))
    elif not distro and (alpine := _ALPINE_BASE.search(history)):
        distro, release = "alpine", alpine.group(1)
    return {"tag": tag, "line": prefix, "version": version, "base_distro": distro, "base_release": release,
            "built": (image_config.get("created") or "")[:10] or None}


def _fetch(client: httpx.Client, repository: str, current_tag: str) -> dict | None:
    token = net.request(client, "GET", AUTH_URL, retries=1, params={
        "service": "registry.docker.io", "scope": f"repository:{repository}:pull"}).json().get("token")
    auth = {"Authorization": f"Bearer {token}"}
    base = REGISTRY_URL.format(repository=repository)

    def tag_facts(tag: str) -> dict | None:
        headers = {**auth, "Accept": MANIFEST_TYPES}
        try:
            manifest = net.request(client, "GET", f"{base}/manifests/{tag}", headers=headers, retries=1).json()
            if "manifests" in manifest:  # multi-platform: take linux/amd64
                digest = next((m["digest"] for m in manifest["manifests"]
                               if (m.get("platform") or {}).get("os") == "linux"
                               and (m.get("platform") or {}).get("architecture") == "amd64"), None)
                if not digest:
                    return None
                manifest = net.request(client, "GET", f"{base}/manifests/{digest}", headers=headers, retries=1).json()
            image_config = net.request(client, "GET", f"{base}/blobs/{manifest['config']['digest']}", headers=auth, retries=1).json()
        except (net.LookupFailed, KeyError, ValueError):
            return None
        return describe(tag, image_config)

    if line_of(current_tag) is None:
        return None
    tags = net.request(client, "GET", f"{base}/tags/list", headers=auth, retries=1).json().get("tags") or []
    lines = newer_lines(tags, current_tag)
    with ThreadPoolExecutor(max_workers=4) as pool:
        facts = list(pool.map(tag_facts, [current_tag] + lines))
    return {"repository": repository, "current": facts[0], "newer": [f for f in facts[1:] if f]}


def image_lines(conn, client: httpx.Client | None, image_name: str, current_tag: str | None, warnings: list[str], *,
                online: bool = True, max_age: timedelta | None = None) -> dict | None:
    """{"repository", "current": {...}, "newer": [{...}]} for name:tag, or None when unknown
    (not on Docker Hub, an unversioned tag such as "latest", or the registry couldn't be asked)."""
    repository = repository_of(image_name)
    if not repository or line_of(current_tag) is None:
        return None
    max_age = timedelta(hours=config.REGISTRY_CACHE_HOURS) if max_age is None else max_age
    key = f"image:{repository}:{current_tag}"
    row = store.get_record(conn, key, SOURCE)
    if store.is_fresh(row, max_age) or not online or client is None:
        return store.record_data(row)
    try:
        data = _fetch(client, repository, current_tag)
    except net.LookupFailed:
        warnings.append(f"Docker Hub unavailable for {image_name}; no newer image lines listed")
        return store.record_data(row)
    if data is None:
        return store.record_data(row)
    path = f"_/{image_name}" if repository.startswith("library/") else f"r/{repository}"
    store.upsert_records(conn, SOURCE, [{
        "key": key, "kind": "image_lines", "title": f"{image_name}:{current_tag}",
        "text": f"{len(data['newer'])} newer release lines of {image_name}", "url": HUB_URL.format(path=path),
        "license": LICENSE, "data": data}])
    conn.commit()
    return data
