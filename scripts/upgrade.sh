#!/usr/bin/env bash
# dotvault upgrade — idempotent upgrade to the latest release.
#
# This is a thin alias: install.sh now handles both install and upgrade
# (it detects an existing install and upgrades only if a newer release exists).
# Kept as a separate entry point for discoverability.
#
# Usage:
#   scripts/upgrade.sh
#   # equivalent to:
#   scripts/install.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/install.sh"
