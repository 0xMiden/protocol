#!/bin/bash
# Pre-push hook: runs `make test` before allowing push.
# Exit 0 = allow, Exit 2 = block (reason on stderr).

# Only act in Rust repositories
if [ ! -f "Cargo.toml" ]; then
  exit 0
fi

echo "Running make test..." >&2
OUTPUT=$(make test 2>&1)
STATUS=$?

if [ $STATUS -ne 0 ]; then
  echo "make test failed - fix failing tests before pushing:" >&2
  echo "$OUTPUT" >&2
  exit 2
fi

echo "All tests passed." >&2
exit 0
