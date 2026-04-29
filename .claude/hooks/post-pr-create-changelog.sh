#!/bin/bash
# Internal guard: only fire for actual git commit invocations. Defense in depth
# against settings.json filter regressions.
COMMAND=$(jq -r '.tool_input.command // empty' 2>/dev/null)
echo "$COMMAND" | grep -qE '(^|[^a-zA-Z0-9_-])gh[[:space:]]+pr[[:space:]]+create([[:space:]]|$)' || exit 0
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null)

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
# Version resolution: the unreleased section name is read from the PR's
# milestone (or the lowest open milestone) via gh. There is no hardcoded
# fallback because guessing a version is worse than asking the user.

set -uo pipefail

INPUT=$(cat)

PR_URL=$(printf '%s' "$INPUT" | jq -r '.tool_response // empty' \
          | grep -oE 'https://github\.com/[^\s"]+/pull/[0-9]+' | head -1)
PR_NUMBER=$(printf '%s' "$PR_URL" | grep -oE '[0-9]+$')
CWD=$(printf '%s' "$INPUT" | jq -r '.cwd // empty')

[ -z "$PR_URL" ] || [ -z "$PR_NUMBER" ] || [ -z "$CWD" ] && exit 0

# ----------------------------------------------------------------------------
# Resolve the unreleased version dynamically. Strategy:
#   1. PR's own milestone title (most authoritative)
#   2. lowest open milestone with a version-like title
#   3. give up; tell the user
# ----------------------------------------------------------------------------
resolve_unreleased_version() {
  local pr_number="$1"
  local v

  if [ -n "$pr_number" ]; then
    v=$(gh pr view "$pr_number" --json milestone --jq '.milestone.title // empty' 2>/dev/null \
          | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    [ -n "$v" ] && { printf 'v%s' "$v"; return 0; }
  fi

  v=$(gh api 'repos/:owner/:repo/milestones?state=open' --jq '.[].title' 2>/dev/null \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' \
        | sort -V | head -1)
  [ -n "$v" ] && { printf 'v%s' "$v"; return 0; }

  return 1
}

# ----------------------------------------------------------------------------
# Spawn the classifier agent.
# ----------------------------------------------------------------------------
PROMPT="Check changelog for PR #${PR_NUMBER} (${PR_URL}). Important: if the diff contains ANY changes that affect runtime behavior, a changelog entry is needed - even if the PR also contains config/tooling/docs changes."
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

  if VERSION=$(cd "$CWD" && resolve_unreleased_version "$PR_NUMBER"); then
    VERSION_INSTRUCTION="Add the following to CHANGELOG.md under the ${VERSION} unreleased section (resolved from milestone)"
  else
    VERSION_INSTRUCTION="Add the following to CHANGELOG.md under the appropriate unreleased section. WARNING: I could not resolve the target version from the PR milestone or any open milestone - ask the user which version to file under before committing"
  fi

  emit_context "Changelog entry needed for PR #${PR_NUMBER}. ${VERSION_INSTRUCTION}, then commit and push:

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