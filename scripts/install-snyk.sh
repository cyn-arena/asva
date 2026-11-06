#!/usr/bin/env bash
#
# install-snyk.sh — download a pinned, checksum-verified Snyk CLI standalone binary.
#
# One source of truth for the version: scripts/snyk-version.txt. Same pattern as
# install-gitleaks.sh, adapted to snyk/cli's release layout: one binary per platform plus a
# matching per-file "<asset>.sha256" companion (no single combined checksums file).
#
# Usage:
#   ./scripts/install-snyk.sh                        # installs to /usr/local/bin
#   INSTALL_DIR="$HOME/.local/bin" ./scripts/install-snyk.sh
#
set -euo pipefail

REPO="snyk/cli"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="$(tr -d '[:space:]' < "${SCRIPT_DIR}/snyk-version.txt")"  # e.g. v1.1305.2
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# --- Detect OS/arch asset name (snyk/cli ships one binary per OS, amd64 only + separate
#     "-arm64" builds for linux/macos; Windows has no arm64 build) ---
case "$(uname -s)" in
  Linux)
    case "$(uname -m)" in
      x86_64|amd64)  ASSET="snyk-linux" ;;
      arm64|aarch64) ASSET="snyk-linux-arm64" ;;
      *) echo "ERROR: unsupported arch: $(uname -m)" >&2; exit 1 ;;
    esac
    BIN="snyk"
    ;;
  Darwin)
    case "$(uname -m)" in
      x86_64|amd64)  ASSET="snyk-macos" ;;
      arm64|aarch64) ASSET="snyk-macos-arm64" ;;
      *) echo "ERROR: unsupported arch: $(uname -m)" >&2; exit 1 ;;
    esac
    BIN="snyk"
    ;;
  MINGW*|MSYS*|CYGWIN*|Windows_*)
    ASSET="snyk-win.exe"
    BIN="snyk.exe"
    ;;
  *) echo "ERROR: unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac

BASE="https://github.com/${REPO}/releases/download/${VERSION}"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "snyk ${VERSION} — ${ASSET}"
echo "Downloading ${ASSET} ..."
curl -fsSL "${BASE}/${ASSET}"          -o "${TMP}/${ASSET}"
curl -fsSL "${BASE}/${ASSET}.sha256"   -o "${TMP}/${ASSET}.sha256"

echo "Verifying sha256 ..."
EXPECTED="$(awk '{print $1}' "${TMP}/${ASSET}.sha256")"
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL="$(sha256sum "${TMP}/${ASSET}" | awk '{print $1}')"
else
  ACTUAL="$(shasum -a 256 "${TMP}/${ASSET}" | awk '{print $1}')"
fi
if [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "ERROR: checksum mismatch for ${ASSET}" >&2
  echo "  expected: ${EXPECTED}" >&2
  echo "  actual:   ${ACTUAL}"   >&2
  exit 1
fi
echo "Checksum OK."

mkdir -p "$INSTALL_DIR"
if ! install -m 0755 "${TMP}/${ASSET}" "${INSTALL_DIR}/${BIN}" 2>/dev/null; then
  cp "${TMP}/${ASSET}" "${INSTALL_DIR}/${BIN}" && chmod +x "${INSTALL_DIR}/${BIN}"
fi

echo "Installed: ${INSTALL_DIR}/${BIN}"
echo "Ensure ${INSTALL_DIR} is on PATH, or set SNYK_BINARY=${INSTALL_DIR}/${BIN} in .env"
