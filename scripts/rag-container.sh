#!/usr/bin/env bash
# Run the RAG (security_context/, ITP2 3.3) next to the agent in a fix job, keeping its database
# between runs in Azure Blob so CVE lookups are not repeated.
#
#   bash scripts/rag-container.sh start   download rag.db, pull the image, start it, wait until healthy, set ASVA_RAG_URL
#   bash scripts/rag-container.sh stop    stop it, show the end of its log, upload rag.db
#
# The RAG is an enhancement, so this script never fails the job: if anything goes wrong it warns,
# and the fixes go ahead without the RAG or without the saved database. The database is only a
# cache of public data, so losing it costs some lookups and nothing else: a damaged download is
# dropped (the RAG starts from the copy in its image), and when two jobs upload, the last one wins.
#
# The image comes from .github/workflows/security-context.yml: this branch's own build if it has
# one, otherwise `latest`. On start the RAG takes any newer CWE, OWASP and KEV data from the image
# and keeps its saved lookups.
#
# Environment: GHCR_TOKEN (a token with packages:read), NVD_API_KEY, CONTEXT7_API_KEY.
# Azure: uses the job's `az` login (azure/login) and ASVA_RAG_STORAGE_ACCOUNT, ASVA_RAG_STORAGE_CONTAINER
# and ASVA_RAG_BLOB (where the database is kept); without them, the database is not kept.

set -u

NAME=asva-rag
PORT=8000
WAIT_SECONDS=90
IMAGE="${ASVA_RAG_IMAGE:-ghcr.io/${GITHUB_REPOSITORY_OWNER:-}/asva-security-context}"
REF_NAME="${GITHUB_REF_NAME:-}"
BRANCH_TAG="${REF_NAME//\//-}"
DATA_DIR="${RUNNER_TEMP:-/tmp}/asva-rag-data"
DB_FILE="$DATA_DIR/rag.db"
ACCOUNT="${ASVA_RAG_STORAGE_ACCOUNT:-}"
CONTAINER="${ASVA_RAG_STORAGE_CONTAINER:-}"
BLOB="${ASVA_RAG_BLOB:-}"

give_up() {
  echo "::warning::RAG not available: $1. Fixes go ahead without it."
  docker logs --tail 40 "$NAME" 2>/dev/null
  docker rm -f "$NAME" >/dev/null 2>&1
  exit 0
}

# Fold SQLite's write-ahead log into the file, and check the file is a sound database.
sound_database() {
  python3 -c "
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.execute('PRAGMA wal_checkpoint(TRUNCATE)')
sys.exit(c.execute('PRAGMA quick_check').fetchone()[0] != 'ok')
" "$1" 2>/dev/null
}

storage_configured() {
  [ -n "$ACCOUNT" ] && [ -n "$CONTAINER" ] && [ -n "$BLOB" ]
}

download_database() {
  storage_configured || { echo "No storage settings: the RAG database is not kept between runs."; return; }
  az account show >/dev/null 2>&1 || { echo "No Azure login: the RAG database is not kept between runs."; return; }
  local exists
  exists=$(az storage blob exists --account-name "$ACCOUNT" --container-name "$CONTAINER" --name "$BLOB" \
    --auth-mode login --query exists -o tsv 2>/dev/null)
  if [ "$exists" != true ]; then
    echo "No saved RAG database yet (or no access to $CONTAINER/$BLOB): starting from the image's copy."
    return
  fi
  az storage blob download --account-name "$ACCOUNT" --container-name "$CONTAINER" --name "$BLOB" \
    --file "$DB_FILE" --auth-mode login --overwrite -o none --no-progress 2>/dev/null \
    || { echo "::warning::Could not download the saved RAG database: starting from the image's copy."; rm -f "$DB_FILE"; return; }
  if sound_database "$DB_FILE"; then
    echo "Saved RAG database downloaded ($(du -h "$DB_FILE" | cut -f1))"
  else
    echo "::warning::The saved RAG database is damaged: starting from the image's copy."
    rm -f "$DB_FILE"*
  fi
}

upload_database() {
  # Only a database a healthy RAG worked with: a run that never got going has nothing to add.
  [ -n "${ASVA_RAG_URL:-}" ] && [ -f "$DB_FILE" ] && storage_configured || return
  az account show >/dev/null 2>&1 || return
  if ! sound_database "$DB_FILE"; then
    echo "::warning::The RAG database is damaged: not saving it."
    return
  fi
  if az storage blob upload --account-name "$ACCOUNT" --container-name "$CONTAINER" --name "$BLOB" \
      --file "$DB_FILE" --auth-mode login --overwrite -o none --no-progress 2>/dev/null; then
    echo "Saved the RAG database ($(du -h "$DB_FILE" | cut -f1)) to $CONTAINER/$BLOB"
  else
    echo "::warning::Could not save the RAG database to $CONTAINER/$BLOB: the next run repeats its lookups."
  fi
}

start() {
  mkdir -p "$DATA_DIR"
  download_database

  echo "${GHCR_TOKEN:-}" | docker login ghcr.io -u "${GITHUB_ACTOR:-asva}" --password-stdin >/dev/null \
    || give_up "could not log in to ghcr.io"

  local image=""
  for tag in "$BRANCH_TAG" latest; do
    if docker pull --quiet "$IMAGE:$tag" >/dev/null 2>&1; then
      image="$IMAGE:$tag"
      break
    fi
    echo "No image $IMAGE:$tag"
  done
  [ -n "$image" ] || give_up "no image to pull"

  # As the runner's user, so the container can write the folder and the job can upload the file.
  docker run -d --name "$NAME" -p "127.0.0.1:$PORT:8000" --user "$(id -u):$(id -g)" \
    -v "$DATA_DIR:/data" -e DB_PATH=/data/rag.db -e NVD_API_KEY -e CONTEXT7_API_KEY "$image" >/dev/null \
    || give_up "the container did not start"

  local waited=0
  until curl -sf "http://localhost:$PORT/healthz" >/dev/null; do
    [ "$waited" -lt "$WAIT_SECONDS" ] || give_up "/healthz did not answer within $WAIT_SECONDS s"
    sleep 2
    waited=$((waited + 2))
  done

  echo "RAG running from $image after about $waited s"
  echo "ASVA_RAG_URL=http://localhost:$PORT" >> "${GITHUB_ENV:-/dev/null}"
}

stop() {
  docker stop "$NAME" >/dev/null 2>&1
  docker logs --tail 40 "$NAME" 2>/dev/null
  docker rm -f "$NAME" >/dev/null 2>&1
  upload_database
  exit 0
}

case "${1:-}" in
  start) start ;;
  stop) stop ;;
  *) echo "usage: $0 start|stop" >&2; exit 2 ;;
esac
