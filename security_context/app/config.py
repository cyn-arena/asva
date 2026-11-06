"""Settings, read from the environment (and `.env` for local development).

Docker/Kubernetes set DB_PATH, SNAPSHOT_PATH and MODEL_CACHE_DIR explicitly; locally they
default to folders under security-context/data/.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")  # never overrides variables already set (e.g. by Docker/Kubernetes)

# huggingface_hub warns on Windows because symlinks aren't available; caching still works.
os.environ.setdefault("HF_HUB_DISABLE_SYMLINKS_WARNING", "1")


def _path(name: str, default: Path) -> Path:
    value = os.environ.get(name)
    return Path(value) if value else default


def _int(name: str, default: int) -> int:
    return int(os.environ.get(name) or default)


def _bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    return default if not value else value.strip().lower() in ("1", "true", "yes", "on")


# -- storage ------------------------------------------------------------------
DB_PATH = _path("DB_PATH", BASE_DIR / "data" / "security_context.db")
# A pre-built database baked into the Docker image; copied to DB_PATH on first start.
SNAPSHOT_PATH = Path(os.environ["SNAPSHOT_PATH"]) if os.environ.get("SNAPSHOT_PATH") else None
MODEL_CACHE_DIR = _path("MODEL_CACHE_DIR", BASE_DIR / "data" / "models")
EMBED_MODEL = "sentence-transformers/all-MiniLM-L6-v2"

# -- response size (tuned against LLM attention dilution, see README "Retrieval tuning") --
DEFAULT_MAX_CHARS = _int("DEFAULT_MAX_CHARS", 2500)
PASSAGE_MAX_CHARS = _int("PASSAGE_MAX_CHARS", 800)
MIN_SIMILARITY = float(os.environ.get("MIN_SIMILARITY") or 0.35)
GUIDANCE_TOP_K = _int("GUIDANCE_TOP_K", 3)
MAX_LIBRARY_NOTES = _int("MAX_LIBRARY_NOTES", 2)  # Context7 notes per request (major upgrades only)
# Context7's breaking-change notes describe a major upgrade, which is held back for a person
# (see "Compatible fixes first" in the README), so by default they go to the references for
# that person and not into the prompt. true puts them into the prompt as well.
LIBRARY_NOTES_IN_PROMPT = _bool("LIBRARY_NOTES_IN_PROMPT", False)
# For a container image the prompt says whether a compatible fix exists and which tag it is.
# The list of newer release lines and the migration target are for the person who plans a
# held-back migration: they are always in the upgrade data (`upgrades`), and in the prompt
# only when this is true.
IMAGE_LINES_IN_PROMPT = _bool("IMAGE_LINES_IN_PROMPT", False)
# Keyword fallback: when a finding's best similarity score is below this, its lowest-ranked
# sections are replaced by the best keyword (BM25) matches. 0 results = fallback off.
KEYWORD_FALLBACK_BELOW = float(os.environ.get("KEYWORD_FALLBACK_BELOW") or 0.62)
KEYWORD_FALLBACK_RESULTS = _int("KEYWORD_FALLBACK_RESULTS", 2)

# -- sources --------------------------------------------------------------------------
# Every source can be switched off, e.g. DISABLED_SOURCES=dockerhub,endoflife. Ids: cwe, owasp,
# nvd, kev, osv, context7, dockerhub, endoflife, registries (PyPI/npm metadata for the trial plan);
# "keyword" switches off the keyword fallback.
SOURCE_IDS = ("cwe", "owasp", "nvd", "kev", "osv", "context7", "dockerhub", "endoflife", "registries", "keyword")
DISABLED_SOURCES = frozenset(
    name.strip().lower() for name in (os.environ.get("DISABLED_SOURCES") or "").split(",") if name.strip())

# -- online sources (looked up at request time and cached in SQLite) --------------
ONLINE_LOOKUPS = _bool("ONLINE_LOOKUPS", True)
HTTP_TIMEOUT = float(os.environ.get("HTTP_TIMEOUT") or 20)

NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
NVD_SYNC_MODE = (os.environ.get("NVD_SYNC_MODE") or "lazy").strip().lower()  # lazy | full
NVD_CACHE_DAYS = _int("NVD_CACHE_DAYS", 7)

OSV_CACHE_HOURS = _int("OSV_CACHE_HOURS", 24)
REGISTRY_CACHE_HOURS = _int("REGISTRY_CACHE_HOURS", 24)  # Docker Hub image lines
LIFECYCLE_CACHE_DAYS = _int("LIFECYCLE_CACHE_DAYS", 7)   # endoflife.date support dates
PACKAGES_CACHE_HOURS = _int("PACKAGES_CACHE_HOURS", 24)  # PyPI / npm package metadata (trial plan)

CONTEXT7_API_KEY = os.environ.get("CONTEXT7_API_KEY", "")
CONTEXT7_CACHE_DAYS = _int("CONTEXT7_CACHE_DAYS", 30)

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")

# -- admin ----------------------------------------------------------------------------
# Enables POST /admin/sync (used by the Kubernetes CronJob). Empty = endpoint disabled.
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")

USER_AGENT = "asva-security-context/1.0 (+https://github.com/cyn-arena/asva)"
