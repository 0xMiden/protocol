#!/bin/bash
# Pre-push hook: spawns two independent review agents before allowing push.
# Both must pass for the push to proceed.
# Exit 0 = allow, Exit 2 = block (reason on stderr).

BASE=$(git merge-base HEAD @{u} 2>/dev/null || git merge-base HEAD next 2>/dev/null)

if [ -z "$BASE" ]; then
  echo "Review blocked: could not determine base branch." >&2
  exit 2
fi

# Skip review if there are no changes
if git diff --quiet "$BASE" HEAD; then
  exit 0
fi

PROMPT="Review the changes about to be pushed."
ALLOWED_TOOLS="Bash(git:*) Read Grep Glob"

# Run both reviewers in parallel
CODE_RESULT_FILE=$(mktemp)
SEC_RESULT_FILE=$(mktemp)
trap 'rm -f "$CODE_RESULT_FILE" "$SEC_RESULT_FILE"' EXIT

claude --agent code-reviewer --allowedTools "$ALLOWED_TOOLS" -p "$PROMPT" > "$CODE_RESULT_FILE" 2>/dev/null &
PID_CODE=$!

claude --agent security-reviewer --allowedTools "$ALLOWED_TOOLS" -p "$PROMPT" > "$SEC_RESULT_FILE" 2>/dev/null &
PID_SEC=$!

wait $PID_CODE
wait $PID_SEC

CODE_RESULT=$(cat "$CODE_RESULT_FILE")
SEC_RESULT=$(cat "$SEC_RESULT_FILE")

# Find verdict line (first line starting with BLOCK:/APPROVE:/CLEAN:)
CODE_VERDICT=$(grep -m1 -E '^(BLOCK:|APPROVE:|CLEAN:)' "$CODE_RESULT_FILE" || true)
SEC_VERDICT=$(grep -m1 -E '^(BLOCK:|APPROVE:|CLEAN:)' "$SEC_RESULT_FILE" || true)

BLOCKED=0

if [[ "$CODE_VERDICT" == BLOCK:* ]]; then
  echo "=== CODE REVIEWER: BLOCKED ===" >&2
  echo "$CODE_RESULT" >&2
  echo "" >&2
  BLOCKED=1
fi

if [[ "$SEC_VERDICT" == BLOCK:* ]]; then
  echo "=== SECURITY REVIEWER: BLOCKED ===" >&2
  echo "$SEC_RESULT" >&2
  echo "" >&2
  BLOCKED=1
fi

if [ $BLOCKED -eq 1 ]; then
  exit 2
fi

# Require explicit approval from both reviewers
if [[ "$CODE_VERDICT" != APPROVE:* ]]; then
  echo "Review blocked: code reviewer did not produce APPROVE: verdict." >&2
  echo "$CODE_RESULT" >&2
  exit 2
fi

if [[ "$SEC_VERDICT" != APPROVE:* ]] && [[ "$SEC_VERDICT" != CLEAN:* ]]; then
  echo "Review blocked: security reviewer did not produce APPROVE:/CLEAN: verdict." >&2
  echo "$SEC_RESULT" >&2
  exit 2
fi

# Print approvals for visibility
echo "=== CODE REVIEWER ===" >&2
echo "$CODE_RESULT" >&2
echo "" >&2
echo "=== SECURITY REVIEWER ===" >&2
echo "$SEC_RESULT" >&2

exit 0
