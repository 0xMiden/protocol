#!/bin/bash
# PreToolUse hook for the Bash tool: blocks `gh pr create` invocations that
# do not pass --draft. PRs must be created as drafts; a human promotes them
# to ready-for-review when appropriate.
#
# Wiring (in .claude/settings.json):
#   {
#     "type": "command",
#     "if": "Bash(*gh pr create*)",
#     "command": ".claude/hooks/pre-pr-draft.sh"
#   }
#
# Output protocol: writes JSON to stdout per the Claude Code PreToolUse hook
# contract. Exit code is always 0; the deny signal is carried in the JSON
# payload's `permissionDecision` field.

set -uo pipefail

# Read the hook input. Fail open on malformed input so the hook can never
# wedge tool use in a bad state.
INPUT=$(cat)
COMMAND=$(printf '%s' "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null || true)

if [ -z "$COMMAND" ]; then
  exit 0
fi

# Defensive: only act on actual `gh pr create` invocations. The settings.json
# `if: Bash(*gh pr create*)` matcher does not reliably filter (see
# pre-push-review.sh fix for the full rationale) — without this guard the
# hook denied unrelated Bash commands.
if ! printf '%s' "$COMMAND" | grep -qE '(^|[[:space:]])gh[[:space:]]+pr[[:space:]]+create([[:space:]]|$)'; then
  exit 0
fi

# Allow if --draft is already present.
if printf '%s' "$COMMAND" | grep -qE '(^|[[:space:]])--draft([[:space:]=]|$)'; then
  exit 0
fi

# Otherwise deny, with a corrected command.
REASON=$(printf 'PRs must be created as drafts. Re-run with --draft:\n\n  %s --draft' "$COMMAND")
REASON_JSON=$(printf '%s' "$REASON" | jq -Rs .)

printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":%s}}\n' "$REASON_JSON"

exit 0
