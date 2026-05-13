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
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _classify import match_args  # noqa: E402

TARGET = ("gh", ["pr", "create"])

# `gh pr create` flags that consume a separate-token argument. Used by
# `has_draft_flag` to skip over flag/value pairs so a value that
# happens to be `--draft` (e.g. `gh pr create --title "--draft"`)
# isn't misread as the draft flag. `--flag=value` form is a single
# token and doesn't need to appear here.
#
# Mirrored from `gh pr create --help`; if `gh` grows new arg-taking
# flags we'll only miss them as edge cases (a value that's literally
# `--draft` after one of these would be misread as the flag — rare).
_FLAGS_WITH_ARG = frozenset(
    {
        "--base", "-B",
        "--body", "-b",
        "--body-file", "-F",
        "--template", "-T",
        "--head", "-H",
        "--label", "-l",
        "--assignee", "-a",
        "--reviewer", "-r",
        "--milestone", "-m",
        "--project", "-p",
        "--title", "-t",
        "--add-label",
        "--remove-label",
        "--add-assignee",
        "--remove-assignee",
        "--add-reviewer",
        "--remove-reviewer",
        "--add-project",
        "--remove-project",
    }
)


def has_draft_flag(args: list[str]) -> bool:
    """Walk `gh pr create` args left-to-right, skipping known
    flag/value pairs, and return True if `--draft` (or `--draft=<v>`)
    appears in a flag position — not as the value of another flag.
    """
    consume_next_as_value = False
    for tok in args:
        if consume_next_as_value:
            consume_next_as_value = False
            continue
        if tok == "--draft" or tok.startswith("--draft="):
            return True
        if tok in _FLAGS_WITH_ARG:
            consume_next_as_value = True
    return False


def main() -> None:
    try:
        payload = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, ValueError):
        sys.exit(0)
    command = payload.get("tool_input", {}).get("command", "") or ""

    # Only inspect the args of the actual `gh pr create` segment.
    # match_args returns None if no segment matches.
    args = match_args(command, *TARGET)
    if args is None:
        sys.exit(0)
    if has_draft_flag(args):
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


if __name__ == "__main__":
    main()
