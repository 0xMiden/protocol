#!/bin/bash
# Internal guard: only fire for actual git commit invocations. Defense in depth
# against settings.json filter regressions.
COMMAND=$(jq -r '.tool_input.command // empty' 2>/dev/null)
echo "$COMMAND" | grep -qE '(^|[[:space:]])git[[:space:]]+(-c[[:space:]]+[^ ]+[[:space:]]+)*push([[:space:]]|$)' || exit 0
# Pre-push hook: runs tests, then spawns code-reviewer + security-reviewer in
# parallel. Blocks the push on (a) test failure, (b) any Critical/Important/
# Warning finding from either reviewer, or (c) reviewer crash or malformed
# output. Nits and Notes are surfaced to the user but never block.
#
# This script is the single pre-push entry point. Remove the pre-push-test
# hook entry from .claude/settings.json so tests don't run twice. Wire as:
#
#   {
#     "type": "command",
#     "if": "Bash(*git push*)",
#     "command": ".claude/hooks/pre-push-review.sh"
#   }
#
# Output protocol: status and reviewer reports go to stderr (so they surface
# to Claude on exit 2 and don't pollute stdout). Exit 0 = allow push,
# Exit 2 = block push.
#
# Severity policy (single source of truth, not the agent prompts):
#   BLOCK on  ### Critical Issues | ### Critical Findings
#             ### Important Issues | ### Warnings
#   IGNORE    ### Nits | ### Notes | ### What's Done Well | ### Summary
# This intentionally diverges from the "all findings block" line in the
# reviewer prompts. If you want the agents to stop emitting BLOCK: for nits,
# update their prompts; this script doesn't depend on that.
#
# Escape hatch: SKIP_PRE_PUSH=1 bypasses everything.

set -uo pipefail

if [ "${SKIP_PRE_PUSH:-}" = "1" ]; then
  echo "SKIP_PRE_PUSH=1 set; bypassing pre-push checks." >&2
  exit 0
fi

REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || true)
if [ -z "$REPO_ROOT" ]; then
  echo "Pre-push: not inside a git worktree, skipping." >&2
  exit 0
fi

# Determine the diff base. Prefer the configured upstream; fall back to
# the repo's default branch resolved via gh; final fallback is HEAD~1.
BASE=""
if UPSTREAM=$(git rev-parse --abbrev-ref --symbolic-full-name @{u} 2>/dev/null); then
  BASE="$UPSTREAM"
elif command -v gh >/dev/null 2>&1; then
  if DEFAULT=$(gh repo view --json defaultBranchRef --jq '.defaultBranchRef.name' 2>/dev/null); then
    [ -n "$DEFAULT" ] && BASE="origin/$DEFAULT"
  fi
fi
if [ -z "$BASE" ]; then
  echo "Pre-push: cannot determine diff base; falling back to HEAD~1." >&2
  BASE="HEAD~1"
fi

MERGE_BASE=$(git merge-base HEAD "$BASE" 2>/dev/null || git rev-parse HEAD~1 2>/dev/null || true)
if [ -z "$MERGE_BASE" ]; then
  echo "Pre-push: cannot resolve merge-base against $BASE; allowing." >&2
  exit 0
fi

if git diff --quiet "$MERGE_BASE" HEAD; then
  echo "Pre-push: no changes vs $BASE; skipping." >&2
  exit 0
fi

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT
TEST_LOG="$TMPDIR/test.log"
CODE_OUT="$TMPDIR/code.out"
SEC_OUT="$TMPDIR/sec.out"

# ----------------------------------------------------------------------------
# Step 1: tests (synchronous, fail-fast). No point burning reviewer tokens
# on changes that don't compile.
# ----------------------------------------------------------------------------
if [ -f "$REPO_ROOT/Cargo.toml" ] && [ -f "$REPO_ROOT/Makefile" ] \
   && grep -qE '^test:' "$REPO_ROOT/Makefile"; then
  echo "Pre-push: running make test..." >&2
  if ! make -C "$REPO_ROOT" test > "$TEST_LOG" 2>&1; then
    echo "" >&2
    echo "=== TESTS FAILED ===" >&2
    cat "$TEST_LOG" >&2
    echo "" >&2
    echo "Pre-push: blocked because tests failed. Fix and retry." >&2
    echo "Bypass with: SKIP_PRE_PUSH=1 git push ..." >&2
    exit 2
  fi
  echo "Pre-push: tests passed." >&2
else
  echo "Pre-push: no Makefile test target found; skipping tests." >&2
fi

# ----------------------------------------------------------------------------
# Step 2: reviewers (parallel).
# ----------------------------------------------------------------------------
PROMPT="Review the changes about to be pushed (diff base: ${MERGE_BASE})."
ALLOWED_TOOLS="Bash(git:*) Read Grep Glob"

echo "Pre-push: spawning code-reviewer + security-reviewer..." >&2

claude --agent code-reviewer     --allowedTools "$ALLOWED_TOOLS" -p "$PROMPT" > "$CODE_OUT" 2> "$TMPDIR/code.err" &
PID_CODE=$!
claude --agent security-reviewer --allowedTools "$ALLOWED_TOOLS" -p "$PROMPT" > "$SEC_OUT"  2> "$TMPDIR/sec.err"  &
PID_SEC=$!

wait $PID_CODE; RC_CODE=$?
wait $PID_SEC;  RC_SEC=$?

# ----------------------------------------------------------------------------
# Step 3: parse findings. Block ONLY on Critical/Important/Warning sections.
# Nits and Notes are surfaced via the report dump but ignored for the
# blocking decision.
# ----------------------------------------------------------------------------

# Counts non-empty bullet lines (- or *) under blocking-severity section
# headers, stopping each section at the next ## or ### header. Prints the
# count to stdout.
count_blocking_findings() {
  awk '
    BEGIN { in_block = 0; count = 0 }
    /^##[^#]|^## / { in_block = 0 }
    /^### / {
      if ($0 ~ /^### (Critical|Important|Warnings)([[:space:]]|$)/) {
        in_block = 1
      } else {
        in_block = 0
      }
      next
    }
    in_block && /^[[:space:]]*[-*][[:space:]]+./ { count++ }
    END { print count }
  ' "$1"
}

# A valid review is non-empty and contains at least one ### header.
review_is_valid() {
  [ -s "$1" ] && grep -q '^### ' "$1"
}

evaluate_reviewer() {
  local name="$1" rc="$2" out="$3"
  echo "" >&2
  echo "=== ${name} ===" >&2

    if [ "$rc" -ne 0 ]; then
    echo "${name}: agent exited with status ${rc}; treating as block." >&2
    [ -s "$out" ] && cat "$out" >&2
    local err_file=""
    case "$name" in
        "CODE REVIEWER")     err_file="$TMPDIR/code.err" ;;
        "SECURITY REVIEWER") err_file="$TMPDIR/sec.err" ;;
    esac
    [ -n "$err_file" ] && [ -s "$err_file" ] && { echo "--- agent stderr ---" >&2; cat "$err_file" >&2; }
    return 1
    fi

  if ! review_is_valid "$out"; then
    echo "${name}: empty or malformed output; treating as block." >&2
    [ -s "$out" ] && cat "$out" >&2
    return 1
  fi

  cat "$out" >&2

  local n
  n=$(count_blocking_findings "$out")
  echo "" >&2
  if [ "$n" -gt 0 ]; then
    echo "${name}: ${n} blocking finding(s) (Critical/Important/Warning)." >&2
    return 1
  fi
  echo "${name}: no blocking findings (nits/notes do not block)." >&2
  return 0
}

BLOCKED=0
evaluate_reviewer "CODE REVIEWER"     "$RC_CODE" "$CODE_OUT" || BLOCKED=1
evaluate_reviewer "SECURITY REVIEWER" "$RC_SEC"  "$SEC_OUT"  || BLOCKED=1

if [ "$BLOCKED" -eq 1 ]; then
  echo "" >&2
  echo "Pre-push: push blocked. Address Critical/Important/Warning findings above and retry." >&2
  echo "Bypass with: SKIP_PRE_PUSH=1 git push ..." >&2
  exit 2
fi

echo "" >&2
echo "Pre-push: all checks passed." >&2
exit 0