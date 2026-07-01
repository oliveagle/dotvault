#!/usr/bin/env bash
# scripts/lib.sh — shared functions for install.sh and upgrade.sh.
# Sourced, not executed directly.

OWNER="oliveagle"
REPO="dotvault"
INSTALL_DIR="${DOTVAULT_INSTALL_DIR:-$HOME/.dotvault/bin}"

# ---------- output helpers ----------

err()  { printf 'dotvault: error: %s\n' "$*" >&2; exit 1; }
info() { printf '%s\n' "$*"; }

need() { command -v "$1" >/dev/null 2>&1 || err "required command not found: $1"; }

# ---------- platform detection ----------

# Sets PLATFORM="dotvault-<OS>-<ARCH>".
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

# ---------- networking ----------

# Download URL to a file, using curl or wget.
dl() {
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"
  else wget -qO "$2" "$1"; fi
}

# Query GitHub Releases for the latest tag (e.g. "v0.3.0"), or empty on failure.
latest_tag() {
  local api="https://api.github.com/repos/${OWNER}/${REPO}/releases/latest"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --max-time 5 "$api" 2>/dev/null | grep -m1 '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/'
  else
    wget -qO- --timeout=5 "$api" 2>/dev/null | grep -m1 '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/'
  fi
}

# ---------- checksum ----------

# SHA256 hex digest of a file (Linux: sha256sum; macOS: shasum).
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# ---------- version comparison ----------

# Strip a leading 'v' from a version tag.
strip_v() { printf '%s' "${1#v}"; }

# Compare two versions (X.Y.Z). Returns 0 if $1 > $2, else 1.
# Numeric per-component, so 0.10.0 > 0.9.0.
ver_gt() {
  local a b
  IFS='.' read -r a1 a2 a3 <<<"$(strip_v "$1")"
  IFS='.' read -r b1 b2 b3 <<<"$(strip_v "$2")"
  a1="${a1:-0}"; a2="${a2:-0}"; a3="${a3:-0}"
  b1="${b1:-0}"; b2="${b2:-0}"; b3="${b3:-0}"
  for pair in "$a1 $b1" "$a2 $b2" "$a3 $b3"; do
    set -- $pair
    if (( $1 > $2 )); then return 0; fi
    if (( $1 < $2 )); then return 1; fi
  done
  return 1  # equal → not greater
}

# ---------- download + install a release artifact ----------

# download_and_install <tag> <platform>
# Downloads, verifies sha256 (if present), and installs to INSTALL_DIR.
download_and_install() {
  local tag="$1" platform="$2"
  local artifact="${platform}.tar.gz"
  local url="https://github.com/${OWNER}/${REPO}/releases/download/${tag}/${artifact}"
  local sha_url="${url}.sha256"

  info "Downloading: $url"
  local tmp; tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" RETURN

  dl "$url" "$tmp/$artifact" || err "download failed"

  if dl "$sha_url" "$tmp/checksum" 2>/dev/null; then
    local expected actual
    expected="$(tr -d '[:space:]' < "$tmp/checksum")"
    actual="$(sha256 "$tmp/$artifact")"
    [ "$expected" = "$actual" ] || err "checksum mismatch (expected $expected, got $actual)"
    info "Checksum verified."
  else
    info "No checksum file — skipping verification."
  fi

  tar -xzf "$tmp/$artifact" -C "$tmp"
  mkdir -p "$INSTALL_DIR"
  local bin_src="$tmp/$platform/dotvault"
  [ -f "$bin_src" ] || bin_src="$(find "$tmp" -type f -name dotvault | head -1)"
  [ -f "$bin_src" ] || err "could not find dotvault binary in archive"
  install -m 0755 "$bin_src" "$INSTALL_DIR/dotvault"
}
