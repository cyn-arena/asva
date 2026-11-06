#!/usr/bin/env bash
#
# install-gitleaks.sh — download a pinned, checksum-verified gitleaks binary.
#
# One source of truth for the version: scripts/gitleaks-version.txt.
# Reused by dev setup, the agent Dockerfile, and CI. PowerShell variant: install-gitleaks.ps1.
#
# Usage:
#   ./scripts/install-gitleaks.sh                 # installs to /usr/local/bin
#   INSTALL_DIR="$HOME/.local/bin" ./scripts/install-gitleaks.sh
#
set -euo pipefail

REPO="gitleaks/gitleaks"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="$(tr -d '[:space:]' < "${SCRIPT_DIR}/gitleaks-version.txt")"  # e.g. v8.30.1
VERSION_NO_V="${VERSION#v}"                                           # e.g. 8.30.1
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# --- Detect OS / archive extension (gitleaks uses lowercase OS names) ---
case "$(uname -s)" in
  Linux)                          OS="linux";   EXT="tar.gz" ;;
  Darwin)                         OS="darwin";  EXT="tar.gz" ;;
  MINGW*|MSYS*|CYGWIN*|Windows_*) OS="windows"; EXT="zip"    ;;
  *) echo "ERROR: unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac

# --- Detect arch (gitleaks naming: x64 / x32 / arm64 / armv7 / armv6) ---
case "$(uname -m)" in
  x86_64|amd64)  ARCH="x64"   ;;
  arm64|aarch64) ARCH="arm64" ;;
  i386|i686)     ARCH="x32"   ;;
  armv7l)        ARCH="armv7" ;;
  armv6l)        ARCH="armv6" ;;
  *) echo "ERROR: unsupported arch: $(uname -m)" >&2; exit 1 ;;
esac

ASSET="gitleaks_${VERSION_NO_V}_${OS}_${ARCH}.${EXT}"
CHECKSUMS="gitleaks_${VERSION_NO_V}_checksums.txt"
BASE="https://github.com/${REPO}/releases/download/${VERSION}"
BIN="gitleaks"; [ "$OS" = "windows" ] && BIN="gitleaks.exe"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "gitleaks ${VERSION} — ${OS}/${ARCH}"
echo "Downloading ${ASSET} ..."
curl -fsSL "${BASE}/${ASSET}"     -o "${TMP}/${ASSET}"
curl -fsSL "${BASE}/${CHECKSUMS}" -o "${TMP}/${CHECKSUMS}"

echo "Verifying sha256 ..."
EXPECTED="$(awk -v f="$ASSET" '$2==f {print $1}' "${TMP}/${CHECKSUMS}")"
if [ -z "$EXPECTED" ]; then
  echo "ERROR: no checksum for ${ASSET} in ${CHECKSUMS}" >&2; exit 1
fi
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

echo "Extracting ..."
mkdir -p "${TMP}/extracted"
if [ "$EXT" = "zip" ]; then
  unzip -o -q "${TMP}/${ASSET}" -d "${TMP}/extracted"
else
  tar -xzf "${TMP}/${ASSET}" -C "${TMP}/extracted"
fi

SRC="$(find "${TMP}/extracted" -type f -name "$BIN" | head -n1)"
if [ -z "$SRC" ]; then
  echo "ERROR: ${BIN} not found in archive" >&2; exit 1
fi

mkdir -p "$INSTALL_DIR"
if ! install -m 0755 "$SRC" "${INSTALL_DIR}/${BIN}" 2>/dev/null; then
  cp "$SRC" "${INSTALL_DIR}/${BIN}" && chmod +x "${INSTALL_DIR}/${BIN}"
fi

echo "Installed: ${INSTALL_DIR}/${BIN}"
echo "Ensure ${INSTALL_DIR} is on PATH, or set GITLEAKS_BINARY=${INSTALL_DIR}/${BIN} in .env"
