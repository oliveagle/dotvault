#!/usr/bin/env bash
# dotvault one-line installer (root entry point).
#
# This is a thin wrapper that delegates to scripts/install.sh, so users can
# use the shorter, conventional URL:
#
#   curl -fsSL https://raw.githubusercontent.com/oliveagle/dotvault/main/install.sh | bash
#
# The real logic (platform detection, download, sha256 verify, PATH hint)
# lives in scripts/install.sh — kept there so curl|bash never fetches a
# multi-file indirection.

set -euo pipefail

# Resolve the directory of this script (works for both local clone and the
# curl|bash temp-file case).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

# When piped via curl|bash, BASH_SOURCE is empty and the script runs from a
# temp dir — we can't find a sibling scripts/install.sh. In that case, fetch
# it directly from the repo.
REAL_INSTALLER="$SCRIPT_DIR/scripts/install.sh"

if [ -f "$REAL_INSTALLER" ]; then
  exec bash "$REAL_INSTALLER" "$@"
else
  # curl|bash mode: download scripts/install.sh and run it.
  OWNER="oliveagle"
  REPO="dotvault"
  BRANCH="${DOTVAULT_INSTALL_BRANCH:-main}"
  URL="https://raw.githubusercontent.com/${OWNER}/${REPO}/${BRANCH}/scripts/install.sh"

  if command -v curl >/dev/null 2>&1; then
    bash <(curl -fsSL "$URL") "$@"
  elif command -v wget >/dev/null 2>&1; then
    bash <(wget -qO- "$URL") "$@"
  else
    echo "dotvault: error: neither curl nor wget found" >&2
    exit 1
  fi
fi
