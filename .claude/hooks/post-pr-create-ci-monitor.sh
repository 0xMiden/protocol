#!/bin/bash
# Post-PR-create hook: spawns a background CI monitor agent that waits 20 minutes
# then checks CI status and fixes any failures.

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

LOG_FILE="/tmp/ci-monitor-pr-${PR_NUMBER}.log"

export CI_MON_CWD="$CWD"
export CI_MON_PR="$PR_NUMBER"
export CI_MON_URL="$PR_URL"
nohup bash -c 'cd "$CI_MON_CWD" && claude --agent ci-monitor -p "Wait 20 minutes (sleep 1200), then check CI status for PR #$CI_MON_PR ($CI_MON_URL). If any checks failed, diagnose and fix them. If all checks pass, just confirm and exit."' > "$LOG_FILE" 2>&1 &

echo "CI monitor spawned for PR #${PR_NUMBER} (PID: $!, will check in ~20min, log: ${LOG_FILE})"
exit 0
