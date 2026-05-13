#!/usr/bin/env python3
"""PreToolUse hook for the Bash tool: blocks `gh pr create` invocations
that do not pass `--draft`. PRs must be created as drafts; a human
promotes them to ready-for-review when appropriate.

Output protocol: writes JSON to stdout per the Claude Code PreToolUse
hook contract. Exit code is always 0; the deny signal is carried in
the JSON payload's `permissionDecision` field.
"""

from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _classify import matches  # noqa: E402

TARGET = ("gh", ["pr", "create"])


def main() -> None:
    try:
        payload = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, ValueError):
        sys.exit(0)
    command = payload.get("tool_input", {}).get("command", "") or ""
    if not matches(command, *TARGET):
        sys.exit(0)

    if _has_draft_flag(command):
        sys.exit(0)

    # Deny, with a corrected command suggestion.
    reason = (
        "PRs must be created as drafts. Re-run with --draft:\n\n"
        f"  {command} --draft"
    )
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }
    sys.stdout.write(json.dumps(output) + "\n")
    sys.exit(0)


def _has_draft_flag(command: str) -> bool:
    """Return True if `--draft` appears as a standalone token (or as
    `--draft=value`) anywhere in `command`. Quoted occurrences inside
    arguments do not count.
    """
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return False
    return any(tok == "--draft" or tok.startswith("--draft=") for tok in tokens)


if __name__ == "__main__":
    main()
