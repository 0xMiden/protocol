#!/bin/bash
# Pre-commit hook: runs `make lint` in Rust repositories before allowing git commit.
# Exit 0 = allow, Exit 2 = block (reason on stderr).

REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null)
if [ -z "$REPO_ROOT" ]; then
  exit 0
fi

# Only act in Rust repositories
if [ ! -f "$REPO_ROOT/Cargo.toml" ]; then
  exit 0
fi

# Check that a Makefile with a lint target exists
if ! grep -q '^lint' "$REPO_ROOT/Makefile" 2>/dev/null; then
  exit 0
fi

OUTPUT=$(make -C "$REPO_ROOT" lint 2>&1)
STATUS=$?

if [ $STATUS -ne 0 ]; then
  echo "make lint failed - fix issues before committing:" >&2
  echo "$OUTPUT" >&2
  exit 2
fi

exit 0