#!/usr/bin/env python3
"""Post-commit hook: reviews the commit that was just created.

Runs after `git commit` (including `-a`, `--amend`, rebase, cherry-pick)
and reviews the commit's own delta, `HEAD~1..HEAD` — the diff is always
exactly the new commit's content regardless of how it was produced, so no
base-selection logic is needed. Spawns code-reviewer + security-reviewer
via `_review.run_review`.

PostToolUse cannot un-make the commit, so on a blocking finding it exits 2:
Claude Code feeds the findings back to the agent and halts progress. The
agent fixes and `git commit --amend`s, which re-fires this hook on the
amended commit until it's clean.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _classify import matches  # noqa: E402
from _hookutils import command_from_payload, read_payload  # noqa: E402
from _review import run_review  # noqa: E402

TARGET = ("git", ["commit"])

# Substrings in the commit's output that mean no commit was created. We
# review only when the commit actually happened — otherwise HEAD~1..HEAD
# would re-review the previous (unrelated) commit.
_FAILURE_MARKERS = (
    "nothing to commit",
    "no changes added to commit",
    "nothing added to commit",
)


def main() -> None:
    payload = read_payload()
    command = command_from_payload(payload)
    if command is None or not matches(command, *TARGET):
        sys.exit(0)
    assert payload is not None  # guarded by command check above

    if _commit_failed(payload):
        sys.exit(0)

    cwd = payload.get("cwd") or None
    if cwd is not None and not isinstance(cwd, str):
        cwd = None

    # Root commit has no parent — nothing to diff against; skip.
    if not _has_parent(cwd):
        sys.exit(0)
    if _no_changes(cwd):
        sys.exit(0)

    sys.stderr.write("Post-commit: reviewing HEAD~1..HEAD (code + security)...\n")
    blocked, rendered = run_review("HEAD~1..HEAD", cwd)
    sys.stderr.write(rendered + "\n")

    if blocked:
        sys.stderr.write(
            "\nPost-commit: blocking findings above. Fix them and `git commit --amend` "
            "to re-review the amended commit.\n"
        )
        sys.exit(2)
    sys.stderr.write("\nPost-commit: no blocking findings.\n")
    sys.exit(0)


def _commit_failed(payload: dict) -> bool:
    """Return True if the commit did not create a new commit (e.g. nothing
    to commit). Inspects the tool response text for known failure markers."""
    response = payload.get("tool_response", "")
    if not isinstance(response, str):
        response = json.dumps(response)
    text = response.lower()
    return any(marker in text for marker in _FAILURE_MARKERS)


def _has_parent(cwd: str | None) -> bool:
    result = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", "HEAD~1"],
        capture_output=True,
        text=True,
        cwd=cwd,
    )
    return result.returncode == 0 and bool(result.stdout.strip())


def _no_changes(cwd: str | None) -> bool:
    result = subprocess.run(
        ["git", "diff", "--quiet", "HEAD~1", "HEAD"],
        capture_output=True,
        text=True,
        cwd=cwd,
    )
    return result.returncode == 0


if __name__ == "__main__":
    main()
