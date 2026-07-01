#!/usr/bin/env bash
# dotvault upgrade — replace the installed binary with the latest release.
#
# Usage:
#   scripts/upgrade.sh
#
# Idempotent: if the installed version is already the latest, does nothing.
# Compares the installed `dotvault version` against GitHub Releases' latest tag,
# downloads + sha256-verifies + replaces the binary at ~/.dotvault/bin/dotvault
# (or $DOTVAULT_INSTALL_DIR).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$SCRIPT_DIR/lib.sh"

# ---------- find the installed binary ----------

DOTVAULT_BIN="${DOTVAULT_BIN:-$INSTALL_DIR/dotvault}"
if [ ! -x "$DOTVAULT_BIN" ]; then
  # Try PATH lookup as a fallback.
  if command -v dotvault >/dev/null 2>&1; then
    DOTVAULT_BIN="$(command -v dotvault)"
  else
    err "dotvault not found at $DOTVAULT_BIN (and not on PATH); run install.sh first"
  fi
fi

# ---------- current vs latest ----------

# Parse "dotvault X.Y.Z" from `dotvault version`'s first line.
CURRENT="$("$DOTVAULT_BIN" version 2>/dev/null | awk 'NR==1{print $2}')"
[ -n "$CURRENT" ] || err "could not determine installed version (is $DOTVAULT_BIN a dotvault binary?)"

need uname
detect_platform

TAG="$(latest_tag)"
[ -n "$TAG" ] || err "could not determine latest release tag (network issue?)"

LATEST="$(strip_v "$TAG")"

if [ "$CURRENT" = "$LATEST" ]; then
  info "Already up to date ($CURRENT)."
  exit 0
fi

if ! ver_gt "$LATEST" "$CURRENT"; then
  info "Installed ($CURRENT) is newer than or equal to latest release ($LATEST); nothing to do."
  exit 0
fi

info "Upgrading: $CURRENT → $LATEST"
# Install to the same dir as the existing binary.
DOTVAULT_INSTALL_DIR="$(dirname "$DOTVAULT_BIN")" \
  download_and_install "$TAG" "$PLATFORM"
info "Upgraded dotvault to $TAG at $DOTVAULT_BIN"
info "Verify: $DOTVAULT_BIN version"
