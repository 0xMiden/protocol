#!/bin/bash
# Pre-push hook: spawns two independent review agents before allowing push.
# Both must pass for the push to proceed.
# Exit 0 = allow, Exit 2 = block (reason on stderr).

BASE=$(git merge-base HEAD @{u} 2>/dev/null || git merge-base HEAD next)
DIFF=$(git diff "${BASE}...HEAD" 2>/dev/null)

if [ -z "$DIFF" ]; then
  exit 0
fi

PROMPT="Review the changes about to be pushed."

# Run both reviewers in parallel
CODE_RESULT_FILE=$(mktemp)
SEC_RESULT_FILE=$(mktemp)
trap 'rm -f "$CODE_RESULT_FILE" "$SEC_RESULT_FILE"' EXIT

claude --agent code-reviewer -p "$PROMPT" > "$CODE_RESULT_FILE" 2>&1 &
PID_CODE=$!

claude --agent security-reviewer -p "$PROMPT" > "$SEC_RESULT_FILE" 2>&1 &
PID_SEC=$!

wait $PID_CODE
wait $PID_SEC

CODE_RESULT=$(cat "$CODE_RESULT_FILE")
SEC_RESULT=$(cat "$SEC_RESULT_FILE")

BLOCKED=0

if echo "$CODE_RESULT" | grep -q "^BLOCK:"; then
  echo "=== CODE REVIEWER: BLOCKED ===" >&2
  echo "$CODE_RESULT" >&2
  echo "" >&2
  BLOCKED=1
fi

if echo "$SEC_RESULT" | grep -q "^BLOCK:\|^CONCERNS:"; then
  echo "=== SECURITY REVIEWER: BLOCKED ===" >&2
  echo "$SEC_RESULT" >&2
  echo "" >&2
  BLOCKED=1
fi

if [ $BLOCKED -eq 1 ]; then
  exit 2
fi

# Print approvals for visibility
echo "=== CODE REVIEWER: APPROVED ===" >&2
echo "$CODE_RESULT" >&2
echo "" >&2
echo "=== SECURITY REVIEWER: CLEAN ===" >&2
echo "$SEC_RESULT" >&2

exit 0
