#!/usr/bin/env bash
# Push helper for ha-omada-logger
# Automatically increments the version number in config.yaml and pushes to remote.
#
# Usage:
#   ./scripts/push.sh                 # Bumps patch version and pushes (e.g. 1.7.0 -> 1.7.1)
#   ./scripts/push.sh --minor         # Bumps minor version and pushes (e.g. 1.7.0 -> 1.8.0)
#   ./scripts/push.sh --major         # Bumps major version and pushes (e.g. 1.7.0 -> 2.0.0)
#   ./scripts/push.sh -m "commit msg" # Commits working changes, bumps version, and pushes

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

BUMP_TYPE="--patch"
COMMIT_MSG=""
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --minor)
      BUMP_TYPE="--minor"
      shift
      ;;
    --major)
      BUMP_TYPE="--major"
      shift
      ;;
    --patch)
      BUMP_TYPE="--patch"
      shift
      ;;
    -m|--message)
      COMMIT_MSG="$2"
      shift 2
      ;;
    *)
      EXTRA_ARGS+=("$1")
      shift
      ;;
  esac
done

# If there is a commit message, commit staged/unstaged changes first
if [ -n "$COMMIT_MSG" ]; then
  git add -A
  git commit -m "$COMMIT_MSG"
fi

# Run version bump
OLD_V=$(python3 scripts/bump_version.py --current)
python3 scripts/bump_version.py "$BUMP_TYPE"
NEW_V=$(python3 scripts/bump_version.py --current)

echo "🚀 Bumping version: v$OLD_V -> v$NEW_V"

# Stage and commit version bump
git add config.yaml app.py
git commit -m "chore(release): bump version to v$NEW_V"

# Push with SKIP_BUMP=1 to avoid redundant hook triggers
echo "📤 Pushing to remote..."
SKIP_BUMP=1 git push "${EXTRA_ARGS[@]}" origin HEAD

echo "✅ Successfully pushed v$NEW_V to GitHub!"
