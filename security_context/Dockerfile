# ASVA Security Context Service
#
# The image carries the embedding model and a knowledge snapshot (MITRE CWE + OWASP Top 10
# categories, OWASP Cheat Sheets, CISA KEV), so a fresh container answers immediately. On first
# start the snapshot is copied to the data volume (/data); later syncs update that copy.
# NVD, OSV.dev and Context7 are looked up at runtime (API keys come from the environment,
# never from the image).
#
#   docker build -t asva-security-context .
#   docker run -p 8800:8000 --env-file .env asva-security-context
#
# Building needs internet access (the sync downloads the sources and the MiniLM model).
# Optional: --secret id=github_token,env=GITHUB_TOKEN lets the OWASP listing use a GitHub token
# (a shared runner can hit the anonymous API limit); the token is mounted for that step only
# and is not stored in the image.

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HF_HUB_DISABLE_SYMLINKS_WARNING=1 \
    MODEL_CACHE_DIR=/opt/models \
    SNAPSHOT_PATH=/opt/snapshot/security_context.db \
    DB_PATH=/data/security_context.db \
    NVD_SYNC_MODE=lazy

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# Download the model and build the snapshot at build time (no API keys needed for these sources).
# Readable by every user, so the container can also run as a CI runner's user (docker run --user).
RUN --mount=type=secret,id=github_token \
    GITHUB_TOKEN="$(cat /run/secrets/github_token 2>/dev/null || true)" \
    DB_PATH=$SNAPSHOT_PATH python -m app.sync --source cwe --source owasp --source kev \
    && chmod -R a+rX /opt/models /opt/snapshot

# At runtime the model is only read, never downloaded.
ENV HF_HUB_OFFLINE=1

RUN useradd --uid 1000 --no-create-home --shell /usr/sbin/nologin app \
    && mkdir -p /data && chown app:app /data
USER 1000

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz', timeout=4)"]

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
