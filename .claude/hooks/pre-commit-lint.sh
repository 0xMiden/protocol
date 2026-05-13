#!/bin/bash
# Pre-commit hook: runs `make lint` in Rust repositories before allowing git commit.
# Exit 0 = allow, Exit 2 = block (reason on stderr).

# Claude Code wires this hook under `if: Bash(*git *commit*)` in settings.json,
# but that matcher does not reliably filter — observed in practice firing on
# unrelated Bash calls. Re-check the command from the hook's stdin (PreToolUse
# JSON contract) and exit 0 unless this is actually a `git ... commit` call.
# Permissive on intermediate args to handle `git -c user.name=... commit -m ...`.
if [ ! -t 0 ]; then
  INPUT=$(cat)
  COMMAND=$(printf '%s' "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null || true)
  if [ -n "$COMMAND" ] && ! { printf '%s' "$COMMAND" | grep -qE '(^|[[:space:]])git[[:space:]]' \
      && printf '%s' "$COMMAND" | grep -qE '(^|[[:space:]])commit([[:space:]]|$)'; }; then
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
