#!/bin/bash
# PreToolUse hook: deny gh pr create if --draft is missing

INPUT=$(cat)
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty')

# Only act on gh pr create commands
if ! echo "$COMMAND" | grep -q "gh pr create"; then
  exit 0
fi

# Allow if --draft is present
if echo "$COMMAND" | grep -q "\-\-draft"; then
  exit 0
fi

# Deny: missing --draft
cat <<'EOF'
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"All PRs must be created as drafts. Add --draft to the command."}}
EOF
