#!/usr/bin/env bash
# scripts/bump.sh — bump the dotvault version and tag a release.
#
# Usage:
#   ./scripts/bump.sh patch     # 0.2.0 → 0.2.1
#   ./scripts/bump.sh minor     # 0.2.0 → 0.3.0
#   ./scripts/bump.sh major     # 0.2.0 → 1.0.0
#
# What it does:
#   1. Read the current version from Cargo.toml.
#   2. Compute the next version (patch/minor/major).
#   3. Update Cargo.toml + Cargo.lock.
#   4. Run `cargo check` to confirm it still compiles.
#   5. Commit "release vX.Y.Z", tag `vX.Y.Z`, push both.
#
# The push triggers the release workflow, which builds platform binaries and
# attaches them to a GitHub Release for vX.Y.Z.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

# ---------- helpers ----------

err()  { printf 'bump: error: %s\n' "$*" >&2; exit 1; }
info() { printf '%s\n' "$*"; }

# ---------- args ----------

BUMP="${1:-}"
case "$BUMP" in
  patch|minor|major) ;;
  *) err "usage: $0 <patch|minor|major>";;
esac

# ---------- current version ----------

need() { command -v "$1" >/dev/null 2>&1 || err "required command not found: $1"; }
need cargo
need git
need sed

CURRENT="$(grep -m1 -E '^version = ' Cargo.toml | sed -E 's/^version = "([^"]+)".*/\1/')"
[ -n "$CURRENT" ] || err "could not read version from Cargo.toml"
info "Current version: $CURRENT"

# Parse major.minor.patch (ignore any pre-release/build suffix).
IFS='.' read -r MAJOR MINOR PATCH <<<"$CURRENT"
PATCH="${PATCH%%-*}"  # strip pre-release like -rc1
for v in MAJOR MINOR PATCH; do
  [[ "${!v}" =~ ^[0-9]+$ ]] || err "invalid version component: $v=${!v}"
done

# ---------- compute next ----------

case "$BUMP" in
  major)  MAJOR=$((MAJOR+1)); MINOR=0; PATCH=0;;
  minor)  MINOR=$((MINOR+1)); PATCH=0;;
  patch)  PATCH=$((PATCH+1));;
esac
NEXT="${MAJOR}.${MINOR}.${PATCH}"
info "Bumping to:      $NEXT  ($BUMP)"

# ---------- sanity: clean tree, on main ----------

[ -z "$(git status --porcelain --untracked-files=no)" ] \
  || err "working tree has uncommitted changes; commit or stash first"
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [ "$BRANCH" != "main" ] && [ "$BRANCH" != "master" ]; then
  err "must be on main/master (on '$BRANCH')"
fi

# ---------- update Cargo.toml + Cargo.lock ----------

sed -i.bak -E "s/^version = \"$CURRENT\"/version = \"$NEXT\"/" Cargo.toml
rm -f Cargo.toml.bak
# Refresh Cargo.lock's version entry too.
cargo update -p dotvault --precise "$NEXT" >/dev/null 2>&1 || true

# ---------- verify it compiles ----------

info "Running cargo check..."
cargo check --quiet || err "cargo check failed; aborting before commit"

# ---------- commit + tag + push ----------

git add Cargo.toml Cargo.lock
git commit -m "release v$NEXT" >/dev/null
git tag -a "v$NEXT" -m "dotvault v$NEXT"
info "Created commit + tag v$NEXT."
info "Pushing (this triggers the release workflow)..."
git push origin "$BRANCH"
git push origin "v$NEXT"
info ""
info "Done. v$NEXT released. Watch: https://github.com/$(git remote get-url origin | sed -E 's#.*[:/]([^/]+/[^/]+)(\.git)?$#\1#')/actions"
