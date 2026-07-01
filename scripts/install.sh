#!/usr/bin/env bash
# dotvault one-line installer.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/oliveagle/dotvault/main/scripts/install.sh | bash
#
# Downloads the latest release binary for your OS/arch from GitHub Releases and
# installs it to ~/.dotvault/bin/dotvault. macOS/Linux on x86_64/arm64.
# To upgrade an existing install: scripts/upgrade.sh (idempotent).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$SCRIPT_DIR/lib.sh"

# ---------- main ----------

need uname
detect_platform

TAG="$(latest_tag)"
[ -n "$TAG" ] || err "could not determine latest release tag"

info "Detected platform: $PLATFORM"
info "Latest release:    $TAG"
download_and_install "$TAG" "$PLATFORM"

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
