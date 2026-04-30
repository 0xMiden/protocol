#!/bin/bash
# PreToolUse hook for the Bash tool: blocks `gh pr create` invocations that
# would create a non-draft PR. Always create PRs as drafts; promote with
# `gh pr ready <num>` once human review is requested.
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
#
# Escape hatch: set SKIP_DRAFT_CHECK=1 in the environment to bypass.
 
set -uo pipefail
 
# Escape hatch.
if [ "${SKIP_DRAFT_CHECK:-}" = "1" ]; then
  exit 0
fi
 
# Read the hook input. Fail open on malformed input so the hook can never
# wedge tool use in a bad state.
INPUT=$(cat)
COMMAND=$(printf '%s' "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null || true)
 
if [ -z "$COMMAND" ]; then
  exit 0
fi
 
# Defensive command match. The settings.json `if` filter should already
# restrict us to `gh pr create`, but we re-check in case the hook is wired
# without a filter or invoked directly. The leading boundary excludes
# false matches like `mygh pr create`; quotes and other shell glue are
# permitted before `gh` so `bash -c "gh pr create ..."` still matches.
if ! printf '%s' "$COMMAND" | grep -qE '(^|[^a-zA-Z0-9_-])gh[[:space:]]+pr[[:space:]]+create'; then
  exit 0
fi
 
# Decision: --no-draft (anywhere) wins over --draft. This is stricter than
# gh's last-wins flag parsing, which is intentional for a deny-by-default
# hook: if the user typed --no-draft they meant it, even if --draft also
# slipped in elsewhere.
if printf '%s' "$COMMAND" | grep -qE '(^|[[:space:]])--no-draft([[:space:]=]|$)'; then
  : # explicit opt-out, fall through to deny
elif printf '%s' "$COMMAND" | grep -qE '(^|[[:space:]])--draft([[:space:]=]|$)'; then
  exit 0
fi
 
# Build a corrected command suggestion: strip any --no-draft (flag form or
# `--no-draft=value` form, but never consume the next argument), collapse
# the resulting whitespace, then append --draft if not already present.
# Best-effort only; a literal "--no-draft" inside a quoted title would be
# mangled, but the user can edit.
SUGGESTED=$(printf '%s' "$COMMAND" \
  | sed -E 's/(^|[[:space:]])--no-draft(=[^[:space:]]*)?([[:space:]]|$)/\1\3/g' \
  | sed -E 's/[[:space:]]+/ /g' \
  | sed -E 's/[[:space:]]+$//')
 
if ! printf '%s' "$SUGGESTED" | grep -qE '(^|[[:space:]])--draft([[:space:]=]|$)'; then
  SUGGESTED="${SUGGESTED} --draft"
fi
 
REASON=$(printf 'PRs must be created as drafts. Re-run with --draft:\n\n  %s\n\nPromote to ready-for-review later with: gh pr ready <num>\nBypass this hook with: SKIP_DRAFT_CHECK=1 gh pr create ...' "$SUGGESTED")
 
# JSON-encode the reason string (yields a quoted, escaped JSON string).
REASON_JSON=$(printf '%s' "$REASON" | jq -Rs .)
 
printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":%s}}\n' "$REASON_JSON"
 
exit 0