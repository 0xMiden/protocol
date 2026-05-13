#!/usr/bin/env python3
"""Post-PR-create hook: spawns a changelog-manager agent to classify
the PR diff and decide whether a CHANGELOG.md entry or "no changelog"
label is needed. Outputs actionable instructions to the main agent via
hookSpecificOutput.

The agent is responsible for locating the correct unreleased section
in CHANGELOG.md. This hook does not pre-resolve a version.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _classify import matches  # noqa: E402
from _hookutils import command_from_payload, read_payload  # noqa: E402

TARGET = ("gh", ["pr", "create"])

_PR_URL_RE = re.compile(r"https://github\.com/[^\s\"]+/pull/(\d+)")


def main() -> None:
    payload = read_payload()
    command = command_from_payload(payload)
    if command is None or not matches(command, *TARGET):
        sys.exit(0)
    # mypy hint: command_from_payload returns None unless payload is a dict
    assert payload is not None  # nosec - guarded by command check above

    tool_response = payload.get("tool_response", "") or ""
    if not isinstance(tool_response, str):
        # PostToolUse may pass the response as a structured object; coerce
        # to text by JSON-dumping so the URL regex still works.
        tool_response = json.dumps(tool_response)
    cwd = payload.get("cwd", "") or ""
    if not isinstance(cwd, str) or not cwd:
        sys.exit(0)

    match = _PR_URL_RE.search(tool_response)
    if not match:
        sys.exit(0)
    pr_url = match.group(0)
    pr_number = match.group(1)

    prompt = (
        f"Check changelog for PR #{pr_number} ({pr_url}). Important: if the "
        "diff contains ANY changes that affect runtime behavior, a changelog "
        "entry is needed, even if the PR also contains config/tooling/docs "
        "changes."
    )
    allowed_tools = "Bash(git:*) Bash(gh:*) Read Grep Glob"

    result = subprocess.run(
        [
            "claude",
            "--agent",
            "changelog-manager",
            "--allowedTools",
            allowed_tools,
            "-p",
            prompt,
        ],
        capture_output=True,
        text=True,
        cwd=cwd,
    )
    verdict_line = _find_verdict_line(result.stdout)

    if verdict_line is None:
        _emit_warning(pr_number, result.stdout, result.stderr)
        sys.exit(2)

    if verdict_line.startswith("SKIP:"):
        sys.exit(0)

    if verdict_line.startswith("NO_CHANGELOG:"):
        _emit_context(
            "No changelog entry needed for this PR. Apply the 'no changelog' "
            f"label now:\n\ngh pr edit {pr_number} --add-label 'no changelog'"
        )
        sys.exit(2)

    if verdict_line.startswith("CHANGELOG:"):
        # Everything from `CHANGELOG:` onward (across newlines) is the
        # suggested entry body.
        entry = _extract_changelog_entry(result.stdout)
        _emit_context(
            f"Changelog entry needed for PR #{pr_number}. Add the following "
            "to CHANGELOG.md under the appropriate unreleased section (read "
            f"the file to locate it), then commit and push:\n\n{entry}"
        )
        sys.exit(2)

    # Fallthrough — shouldn't happen given _find_verdict_line, but be defensive.
    _emit_warning(pr_number, result.stdout, result.stderr)
    sys.exit(2)


def _find_verdict_line(stdout: str) -> str | None:
    for line in stdout.splitlines():
        if line.startswith(("SKIP:", "NO_CHANGELOG:", "CHANGELOG:")):
            return line
    return None


def _extract_changelog_entry(stdout: str) -> str:
    """Return the body of the `CHANGELOG:` block — i.e. everything from
    the `CHANGELOG: ` prefix onward, with that prefix stripped on the
    first line, preserving subsequent lines verbatim.
    """
    lines = stdout.splitlines()
    out: list[str] = []
    found = False
    for line in lines:
        if not found:
            if line.startswith("CHANGELOG:"):
                out.append(line[len("CHANGELOG:") :].lstrip(" "))
                found = True
            continue
        out.append(line)
    return "\n".join(out)


def _emit_context(message: str) -> None:
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": message,
        }
    }
    sys.stdout.write(json.dumps(output) + "\n")


def _emit_warning(pr_number: str, stdout: str, stderr: str) -> None:
    warning = (
        f"WARNING: changelog-manager produced no verdict for PR #{pr_number}. "
        "Decide manually: add a CHANGELOG.md entry under the appropriate "
        "unreleased section, or apply the 'no changelog' label via: gh pr "
        f"edit {pr_number} --add-label 'no changelog'"
    )
    if stderr.strip():
        warning += f"\n\n--- classifier stderr ---\n{stderr}"
    if stdout.strip():
        warning += f"\n\n--- classifier stdout (no verdict line recognized) ---\n{stdout}"
    _emit_context(warning)


if __name__ == "__main__":
    main()
