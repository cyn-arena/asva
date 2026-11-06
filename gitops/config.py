"""
Configuration for the git/gh GitOps backend.

Settings come from environment variables — a local `.env` during development, or the
GitHub Actions environment in CI. Auth is NOT handled here: git uses the credentials the
checkout persisted, and gh reads GITHUB_TOKEN/GH_TOKEN from the environment.
"""

import os

from dotenv import load_dotenv

load_dotenv()

# Integration branch that ASVA opens fix PRs into for human review. ASVA never merges.
GITHUB_BASE_BRANCH = os.environ.get("GITHUB_BASE_BRANCH", "feat/agent").strip()

# Maps an app-relative finding path (e.g. "app/routes/x.js") to its location in the repo
# working tree. The NodeGoat target lives under target-apps/NodeGoat, so set the prefix to
# that when fixing it inside this repo. Empty = paths are already repo-relative.
FIX_PATH_PREFIX = os.environ.get("ASVA_FIX_PATH_PREFIX", "").strip().strip("/")

# Optional explicit "owner/repo" for gh. Empty = gh auto-detects from the checkout.
GITHUB_TARGET_REPO = os.environ.get("GITHUB_TARGET_REPO", "").strip()

# Committer identity used for fix commits.
GIT_AUTHOR_NAME = os.environ.get("ASVA_GIT_NAME", "asva-bot").strip()
GIT_AUTHOR_EMAIL = os.environ.get("ASVA_GIT_EMAIL", "asva-bot@users.noreply.github.com").strip()
