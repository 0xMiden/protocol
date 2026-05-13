#!/bin/bash
# Pre-push hook: runs `make test` before allowing push.
# Exit 0 = allow, Exit 2 = block (reason on stderr).

# Defensive command check — see pre-push-review.sh for the rationale.
# settings.json wires this under `if: Bash(*git push*)` but that matcher
# does not reliably filter, so re-check stdin for `git push` ourselves.
if [ ! -t 0 ]; then
  INPUT=$(cat)
  COMMAND=$(printf '%s' "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null || true)
  if [ -n "$COMMAND" ] && ! printf '%s' "$COMMAND" | grep -qE '(^|[[:space:]])git[[:space:]]+push([[:space:]]|$)'; then
    exit 0
  fi
fi

REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null)
if [ -z "$REPO_ROOT" ]; then
  exit 0
fi

# Only act in Rust repositories
if [ ! -f "$REPO_ROOT/Cargo.toml" ]; then
  exit 0
fi

# Check that a Makefile with a test target exists
if ! grep -q '^test' "$REPO_ROOT/Makefile" 2>/dev/null; then
  exit 0
fi

echo "Running make test..." >&2
OUTPUT=$(make -C "$REPO_ROOT" test 2>&1)
STATUS=$?

if [ $STATUS -ne 0 ]; then
  echo "make test failed - fix failing tests before pushing:" >&2
  echo "$OUTPUT" >&2
  exit 2
fi

echo "All tests passed." >&2
exit 0
