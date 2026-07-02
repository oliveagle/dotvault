#!/usr/bin/env bash
# dotvault installer + upgrader (self-contained — safe for `curl | bash`).
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/oliveagle/dotvault/main/scripts/install.sh | bash
#   scripts/install.sh            # install or upgrade (idempotent)
#
# Behavior:
#   - No dotvault installed → install the latest release.
#   - dotvault installed & up to date → "Already up to date", exit 0.
#   - dotvault installed & outdated → upgrade to the latest release.
#
# Installs to ~/.dotvault/bin/dotvault (or $DOTVAULT_INSTALL_DIR). macOS/Linux
# on x86_64/arm64. Windows users: download the .zip from Releases.

set -euo pipefail

OWNER="oliveagle"
REPO="dotvault"
INSTALL_DIR="${DOTVAULT_INSTALL_DIR:-$HOME/.dotvault/bin}"

# ---------- helpers ----------

err()  { printf 'dotvault: error: %s\n' "$*" >&2; exit 1; }
info() { printf '%s\n' "$*"; }
need() { command -v "$1" >/dev/null 2>&1 || err "required command not found: $1"; }

# ---------- platform detection ----------

detect_platform() {
  local os arch
  os="$(uname -s)"; arch="$(uname -m)"
  case "$os" in
    Darwin) os="Darwin" ;;
    Linux)  os="Linux" ;;
    MINGW*|MSYS*|CYGWIN*) err "Windows: download the .zip from https://github.com/$OWNER/$REPO/releases" ;;
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

dl() {
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"
  else wget -qO "$2" "$1"; fi
}

latest_tag() {
  local page="https://github.com/${OWNER}/${REPO}/releases/latest"
  # Prefer the releases-page redirect (follows 302 to .../tag/vX.Y.Z). This
  # does NOT consume the rate-limited API, so it survives heavy use.
  if command -v curl >/dev/null 2>&1; then
    local url
    url="$(curl -fsSL -o /dev/null -w '%{url_effective}' --max-time 8 "$page" 2>/dev/null || true)"
    echo "$url" | grep -oE 'releases/tag/v[0-9][0-9.]*[0-9]' | sed -E 's#releases/tag/##'
  else
    wget -qO- --timeout=8 --max-redirect=5 "$page" 2>/dev/null \
      | grep -m1 -oE 'releases/tag/v[0-9][0-9.]*[0-9]' | sed -E 's#releases/tag/##'
  fi
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# ---------- version compare ----------

strip_v() { printf '%s' "${1#v}"; }

# ver_gt A B → 0 if A > B (numeric per-component), else 1.
ver_gt() {
  local a1 a2 a3 b1 b2 b3
  IFS='.' read -r a1 a2 a3 <<<"$(strip_v "$1")"
  IFS='.' read -r b1 b2 b3 <<<"$(strip_v "$2")"
  a1="${a1:-0}"; a2="${a2:-0}"; a3="${a3:-0}"
  b1="${b1:-0}"; b2="${b2:-0}"; b3="${b3:-0}"
  for pair in "$a1 $b1" "$a2 $b2" "$a3 $b3"; do
    set -- $pair
    if (( $1 > $2 )); then return 0; fi
    if (( $1 < $2 )); then return 1; fi
  done
  return 1
}

# ---------- download + install one release ----------

download_and_install() {
  local tag="$1" platform="$2"
  local artifact="${platform}.tar.gz"
  local url="https://github.com/${OWNER}/${REPO}/releases/download/${tag}/${artifact}"
  info "Downloading: $url"
  local tmp; tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" RETURN
  dl "$url" "$tmp/$artifact" || err "download failed"
  if dl "$url.sha256" "$tmp/checksum" 2>/dev/null; then
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

# ---------- main ----------

need uname
detect_platform

TAG="$(latest_tag)"
[ -n "$TAG" ] || err "could not determine latest release tag (network issue?)"

INSTALLED=""
INSTALLED_BIN=""
if [ -x "$INSTALL_DIR/dotvault" ]; then
  INSTALLED_BIN="$INSTALL_DIR/dotvault"
elif command -v dotvault >/dev/null 2>&1; then
  INSTALLED_BIN="$(command -v dotvault)"
fi
if [ -n "$INSTALLED_BIN" ]; then
  # Best-effort version parse; pre-0.2.0 binaries lack `version`, treat as
  # unknown (forces an upgrade, which is what we want for old builds).
  INSTALLED="$("$INSTALLED_BIN" version 2>/dev/null | awk 'NR==1{print $2}' || true)"
fi

if [ -n "$INSTALLED_BIN" ]; then
  if [ -n "$INSTALLED" ] && [ "$INSTALLED" = "$(strip_v "$TAG")" ]; then
    info "Already up to date ($INSTALLED)."
    exit 0
  fi
  if [ -n "$INSTALLED" ] && ! ver_gt "$(strip_v "$TAG")" "$INSTALLED"; then
    info "Installed ($INSTALLED) is newer than latest release ($TAG); nothing to do."
    exit 0
  fi
  # Installed but version unknown or older → upgrade.
  if [ -n "$INSTALLED" ]; then
    info "Upgrading: $INSTALLED → $(strip_v "$TAG")"
  else
    info "Upgrading existing install (old version, no version command) → $(strip_v "$TAG")"
  fi
else
  info "Detected platform: $PLATFORM"
  info "Latest release:    $TAG"
fi

download_and_install "$TAG" "$PLATFORM"

if [ -n "$INSTALLED" ]; then
  info "Upgraded dotvault to $TAG at $INSTALL_DIR/dotvault"
else
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
fi
info ""
info "Done."
