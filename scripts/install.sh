#!/usr/bin/env bash
# dotvault one-line installer.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/oliveagle/dotvault/main/scripts/install.sh | bash
#
# Downloads the latest release binary for your OS/arch from GitHub Releases and
# installs it to ~/.dotvault/bin/dotvault, then prints next steps.
# Supports macOS and Linux on x86_64/arm64. Windows users: download the .zip
# from the Releases page.

set -euo pipefail

OWNER="oliveagle"
REPO="dotvault"
INSTALL_DIR="${DOTVAULT_INSTALL_DIR:-$HOME/.dotvault/bin}"

# ---------- helpers ----------

err()  { printf 'install: error: %s\n' "$*" >&2; exit 1; }
info() { printf '%s\n' "$*"; }

need() { command -v "$1" >/dev/null 2>&1 || err "required command not found: $1"; }

# ---------- detect OS + arch ----------

detect_platform() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$os" in
    Darwin) os="Darwin" ;;
    Linux)  os="Linux" ;;
    MINGW*|MSYS*|CYGWIN*) err "Windows detected: download the .zip from https://github.com/$OWNER/$REPO/releases" ;;
    *) err "unsupported OS: $os" ;;
  esac
  case "$arch" in
    x86_64|amd64) arch="x86_64" ;;
    arm64|aarch64) arch="arm64" ;;
    *) err "unsupported architecture: $arch" ;;
  esac
  PLATFORM="dotvault-${os}-${arch}"
}

# ---------- find latest release ----------

latest_tag() {
  local api="https://api.github.com/repos/${OWNER}/${REPO}/releases/latest"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$api" | grep -m1 '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/'
  else
    wget -qO- "$api" | grep -m1 '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/'
  fi
}

# ---------- main ----------

need uname
detect_platform

TAG="$(latest_tag)"
[ -n "$TAG" ] || err "could not determine latest release tag"

ARTIFACT="${PLATFORM}.tar.gz"
URL="https://github.com/${OWNER}/${REPO}/releases/download/${TAG}/${ARTIFACT}"
SHA_URL="${URL}.sha256"

info "Detected platform: $PLATFORM"
info "Latest release:    $TAG"
info "Downloading:       $URL"

# Download to a temp file.
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

dl() {
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"
  else wget -qO "$2" "$1"; fi
}

dl "$URL" "$TMPDIR/$ARTIFACT" || err "download failed"

# Verify SHA256 if a checksum file is published.
if dl "$SHA_URL" "$TMPDIR/checksum" 2>/dev/null; then
  need sha256sum
  EXPECTED="$(tr -d '[:space:]' < "$TMPDIR/checksum")"
  ACTUAL="$(sha256sum "$TMPDIR/$ARTIFACT" | awk '{print $1}')"
  [ "$EXPECTED" = "$ACTUAL" ] || err "checksum mismatch (expected $EXPECTED, got $ACTUAL)"
  info "Checksum verified."
else
  info "No checksum file at $SHA_URL — skipping verification."
fi

# Extract.
tar -xzf "$TMPDIR/$ARTIFACT" -C "$TMPDIR"
mkdir -p "$INSTALL_DIR"
# The archive contains a top dir named "$PLATFORM" with the binary inside.
BIN_SRC="$TMPDIR/$PLATFORM/dotvault"
[ -f "$BIN_SRC" ] || BIN_SRC="$(find "$TMPDIR" -type f -name dotvault | head -1)"
[ -f "$BIN_SRC" ] || err "could not find dotvault binary in archive"
install -m 0755 "$BIN_SRC" "$INSTALL_DIR/dotvault"

info ""
info "Installed dotvault $TAG to $INSTALL_DIR/dotvault"
info ""
info "Next steps:"
info "  1. Add it to your PATH (add to your shell profile):"
info "       export PATH=\"$INSTALL_DIR:\$PATH\""
info "  2. Run the environment setup:"
info "       dotvault install"
info "  3. Bind a project to a namespace:"
info "       dotvault init myapp"
info ""
info "Done."
