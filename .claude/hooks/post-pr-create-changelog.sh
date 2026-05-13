#!/bin/bash
# Post-PR-create hook: spawns a changelog-manager agent to classify the PR diff
# and decide whether a CHANGELOG.md entry or "no changelog" label is needed.
# Outputs actionable instructions to the main agent via hookSpecificOutput.
#
# Wiring (in .claude/settings.json):
#   {
#     "type": "command",
#     "if": "Bash(*gh pr create*)",
#     "command": ".claude/hooks/post-pr-create-changelog.sh"
#   }
#
# The agent is responsible for locating the correct unreleased section in
# CHANGELOG.md. This hook does not pre-resolve a version.

set -uo pipefail

INPUT=$(cat)

# Defensive: only act on actual `gh pr create` invocations. The settings.json
# `if: Bash(*gh pr create*)` matcher does not reliably filter (see
# pre-push-review.sh fix for the full rationale) — without this guard the
# hook could spawn the changelog agent on any Bash command whose output
# happens to contain a GitHub pull URL.
COMMAND=$(printf '%s' "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null || true)
if [ -n "$COMMAND" ] && ! printf '%s' "$COMMAND" | grep -qE '(^|[[:space:]])gh[[:space:]]+pr[[:space:]]+create([[:space:]]|$)'; then
  exit 0
fi

PR_URL=$(printf '%s' "$INPUT" | jq -r '.tool_response // empty' \
          | grep -oE 'https://github\.com/[^\s"]+/pull/[0-9]+' | head -1)
PR_NUMBER=$(printf '%s' "$PR_URL" | grep -oE '[0-9]+$')
CWD=$(printf '%s' "$INPUT" | jq -r '.cwd // empty')

[ -z "$PR_URL" ] || [ -z "$PR_NUMBER" ] || [ -z "$CWD" ] && exit 0

# ----------------------------------------------------------------------------
# Spawn the classifier agent.
# ----------------------------------------------------------------------------
PROMPT="Check changelog for PR #${PR_NUMBER} (${PR_URL}). Important: if the diff contains ANY changes that affect runtime behavior, a changelog entry is needed, even if the PR also contains config/tooling/docs changes."
ALLOWED_TOOLS="Bash(git:*) Bash(gh:*) Read Grep Glob"

RESULT_FILE=$(mktemp)
trap 'rm -f "$RESULT_FILE" "$RESULT_FILE.err"' EXIT

cd "$CWD" && claude --agent changelog-manager --allowedTools "$ALLOWED_TOOLS" -p "$PROMPT" > "$RESULT_FILE" 2> "$RESULT_FILE.err"

VERDICT=$(grep -m1 -E '^(SKIP:|NO_CHANGELOG:|CHANGELOG:)' "$RESULT_FILE" || true)

# ----------------------------------------------------------------------------
# Dispatch on verdict.
# ----------------------------------------------------------------------------
emit_context() {
  # Wrap a free-form message into a valid PostToolUse JSON payload.
  printf '%s' "$1" | jq -Rs '{hookSpecificOutput:{hookEventName:"PostToolUse",additionalContext:.}}'
}

if [[ "$VERDICT" == SKIP:* ]]; then
  exit 0
fi

if [[ "$VERDICT" == NO_CHANGELOG:* ]]; then
  emit_context "No changelog entry needed for this PR. Apply the 'no changelog' label now:

gh pr edit ${PR_NUMBER} --add-label 'no changelog'"
  exit 2
fi

if [[ "$VERDICT" == CHANGELOG:* ]]; then
  ENTRY=$(sed -n '/^CHANGELOG:/,$ { s/^CHANGELOG: //; p }' "$RESULT_FILE")
  emit_context "Changelog entry needed for PR #${PR_NUMBER}. Add the following to CHANGELOG.md under the appropriate unreleased section (read the file to locate it), then commit and push:

${ENTRY}"
  exit 2
fi

# No verdict line found. This usually means the classifier agent crashed,
# timed out, or returned output in an unexpected format. Surface the failure
# to the main agent instead of silently exiting so the changelog decision
# isn't skipped without a human knowing.
WARNING="WARNING: changelog-manager produced no verdict for PR #${PR_NUMBER}. Decide manually: add a CHANGELOG.md entry under the appropriate unreleased section, or apply the 'no changelog' label via: gh pr edit ${PR_NUMBER} --add-label 'no changelog'"

if [ -s "$RESULT_FILE.err" ]; then
  WARNING="${WARNING}

--- classifier stderr ---
$(cat "$RESULT_FILE.err")"
fi

if [ -s "$RESULT_FILE" ]; then
  WARNING="${WARNING}

--- classifier stdout (no verdict line recognized) ---
$(cat "$RESULT_FILE")"
fi

emit_context "$WARNING"
exit 2
