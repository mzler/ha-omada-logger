#!/usr/bin/env bash
# Installs git hooks for ha-omada-logger
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
HOOK_DEST="$ROOT_DIR/.git/hooks/pre-push"

cat << 'EOF' > "$HOOK_DEST"
#!/usr/bin/env bash
# Git pre-push hook: ensures version in config.yaml is incremented on every push.

if [ "$SKIP_BUMP" = "1" ] || [ "$CI" = "true" ]; then
  exit 0
fi

REMOTE="$1"
URL="$2"
ROOT_DIR="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

while read local_ref local_sha remote_ref remote_sha; do
  # Ignore branch deletion (local_sha is all zeros)
  if [ "$local_sha" = "0000000000000000000000000000000000000000" ]; then
    continue
  fi

  # If remote branch exists, compare config.yaml
  if [ -n "$remote_sha" ] && [ "$remote_sha" != "0000000000000000000000000000000000000000" ]; then
    DIFF=$(git diff "$remote_sha..$local_sha" -- config.yaml 2>/dev/null || true)
    if [ -z "$DIFF" ]; then
      echo ""
      echo "⚡ [Auto-Version] Noch keine Versionserhöhung in config.yaml für diesen Push festgestellt."
      cd "$ROOT_DIR"
      OLD_V=$(python3 scripts/bump_version.py --current)
      python3 scripts/bump_version.py --patch
      NEW_V=$(python3 scripts/bump_version.py --current)
      git add config.yaml app.py
      git commit -m "chore(release): bump version to v$NEW_V"
      echo "🚀 [Auto-Version] Version v$NEW_V committet. Starte Push nach $REMOTE..."
      SKIP_BUMP=1 git push "$REMOTE" HEAD
      echo "✅ [Auto-Version] Push mit neuer Version v$NEW_V erfolgreich abgeschlossen!"
      exit 1
    fi
  fi
done

exit 0
EOF

chmod +x "$HOOK_DEST"
chmod +x "$ROOT_DIR/scripts/push.sh"
chmod +x "$ROOT_DIR/scripts/bump_version.py"

echo "✅ Git pre-push hook successfully installed in $HOOK_DEST"
