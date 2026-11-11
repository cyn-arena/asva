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

# Behind an HTTPS proxy the browser's Origin is https://<site>, while Django sees plain HTTP, so
# form posts fail the CSRF origin check. The Kubernetes deploy sets the public site address here;
# local and pipeline runs leave it unset.
CSRF_TRUSTED_ORIGINS = CSRF_TRUSTED_ORIGINS + [  # noqa: F405
    origin.strip().rstrip("/")
    for origin in os.environ.get("PYGOAT_CSRF_TRUSTED_ORIGINS", "").split(",")
    if origin.strip()
]
