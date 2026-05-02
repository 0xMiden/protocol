#!/bin/bash
# Post-PR-create hook: spawns a changelog-manager agent to check whether
# a CHANGELOG.md entry or "no changelog" label is needed.
# Outputs actionable instructions to the main agent via hookSpecificOutput.

INPUT=$(cat)

# Extract PR URL from the tool response
PR_URL=$(echo "$INPUT" | jq -r '.tool_response // empty' | grep -oP 'https://github\.com/[^\s"]+/pull/\d+' | head -1)

if [ -z "$PR_URL" ]; then
  exit 0
fi

# Extract PR number
PR_NUMBER=$(echo "$PR_URL" | grep -oP '\d+$')

if [ -z "$PR_NUMBER" ]; then
  exit 0
fi

# Extract repo working directory
CWD=$(echo "$INPUT" | jq -r '.cwd // empty')

if [ -z "$CWD" ]; then
  exit 0
fi

PROMPT="Check changelog for PR #${PR_NUMBER} (${PR_URL}). Important: if the diff contains ANY changes that affect runtime behavior, a changelog entry is needed - even if the PR also contains config/tooling/docs changes."
ALLOWED_TOOLS="Bash(git:*) Bash(gh:*) Read Grep Glob"

RESULT_FILE=$(mktemp)
trap 'rm -f "$RESULT_FILE"' EXIT

cd "$CWD" && claude --agent changelog-manager --allowedTools "$ALLOWED_TOOLS" -p "$PROMPT" > "$RESULT_FILE" 2>/dev/null

VERDICT=$(grep -m1 -E '^(SKIP:|NO_CHANGELOG:|CHANGELOG:)' "$RESULT_FILE" || true)

if [[ "$VERDICT" == SKIP:* ]]; then
  exit 0
fi

if [[ "$VERDICT" == NO_CHANGELOG:* ]]; then
  cat <<ENDJSON
{"hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":"No changelog entry needed for this PR. Apply the 'no changelog' label now:\n\ngh pr edit ${PR_NUMBER} --add-label 'no changelog'"}}
ENDJSON
  exit 2
fi

if [[ "$VERDICT" == CHANGELOG:* ]]; then
  # Extract the entry (everything after "CHANGELOG: ")
  ENTRY=$(sed -n '/^CHANGELOG:/,$ { s/^CHANGELOG: //; p }' "$RESULT_FILE")
  # Escape for JSON
  ENTRY_ESCAPED=$(echo "$ENTRY" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read())[1:-1])')
  cat <<ENDJSON
{"hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":"Changelog entry needed for PR #${PR_NUMBER}. Add the following to CHANGELOG.md under the current unreleased version (v0.15.0 TBD), then commit and push:\n\n${ENTRY_ESCAPED}"}}
ENDJSON
  exit 2
fi

# No verdict found - fail open, CI will catch it
exit 0
