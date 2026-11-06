# ── Base ──────────────────────────────────────────────────────────────────────
FROM python:3.12-slim AS base

WORKDIR /app

# System deps: git (for GitHub module), curl (healthchecks), gitleaks binary
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install gitleaks (for task 3.6 / secrets-scan check)
ARG GITLEAKS_VERSION=8.30.1
RUN curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz \
    | tar -xz -C /usr/local/bin gitleaks

# ── Dependencies ─────────────────────────────────────────────────────────────
FROM base AS deps

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Final image ───────────────────────────────────────────────────────────────
FROM deps AS final

COPY . .

RUN useradd -m agent
USER agent

ENTRYPOINT ["python", "-m", "agent"]


# Python 3.12 + git + curl + gitleaks + your code + requirements.txt
#         ↓
# Single Docker image that runs locally

## how to run (to be placed in readme)

# build once
# docker build -t asva:dev .

# normaliser and triage still needs to be run as per normal

# run the agent
# docker run --rm --env-file .env asva:dev --batch-dir fix_batches

# dry run
# docker run --rm --env-file .env -v "${PWD}/dry_run_output:/app/dry_run_output" asva:dev --batch-dir fix_batches --dry-run --output-dir dry_run_output

