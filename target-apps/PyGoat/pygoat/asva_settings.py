"""Local ASVA deployment settings; preserve the upstream vulnerable application."""
import os

from .settings import *  # noqa: F403

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": os.environ.get("PYGOAT_DB_PATH", os.path.join(BASE_DIR, "db.sqlite3")),
    }
}

# Upstream CSS refers to absent optional font files. Collect and compress assets
# without manifest hashing, which otherwise rejects those references at build time.
STATICFILES_STORAGE = "whitenoise.storage.CompressedStaticFilesStorage"
