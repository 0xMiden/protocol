#!/usr/bin/env python3
"""Pre-PR-creation hook: the final whole-PR review gate.

Per-commit review (`post_commit_review`) catches issues as each commit is
made; this hook is the comprehensive backstop run before `gh pr create`. It
reviews the entire PR — `merge-base(HEAD, origin/HEAD)..HEAD` — so it can
catch cross-commit issues a single-commit view misses.

PreToolUse runs before the PR is created, so on a blocking finding it denies
the tool call (JSON `permissionDecision: deny`), and the PR is not created
until the findings are addressed.
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

TARGET = ("gh", ["pr", "create"])


def main() -> None:
    payload = read_payload()
    command = command_from_payload(payload)
    if command is None or not matches(command, *TARGET):
        sys.exit(0)
    assert payload is not None  # guarded by command check above

    cwd = payload.get("cwd") or None
    if cwd is not None and not isinstance(cwd, str):
        cwd = None

    merge_base = _merge_base(_diff_base(cwd), cwd)
    if merge_base is None:
        sys.stderr.write("Pre-PR: cannot resolve merge-base; allowing.\n")
        sys.exit(0)
    if _no_changes_vs(merge_base, cwd):
        sys.stderr.write("Pre-PR: no changes vs base; allowing.\n")
        sys.exit(0)

    sys.stderr.write("Pre-PR: reviewing the whole PR (code + security)...\n")
    blocked, rendered = run_review(f"{merge_base}..HEAD", cwd)
    sys.stderr.write(rendered + "\n")

    if blocked:
        _emit_deny(rendered)
    sys.exit(0)


def _diff_base(cwd: str | None) -> str:
    """The integration branch to review the whole PR against — the remote's
    default branch (e.g. `origin/next`)."""
    result = subprocess.run(
        ["git", "symbolic-ref", "--short", "refs/remotes/origin/HEAD"],
        capture_output=True,
        text=True,
        cwd=cwd,
    )
    if result.returncode == 0 and result.stdout.strip():
        return result.stdout.strip()
    return "origin/next"


def _merge_base(base: str, cwd: str | None) -> str | None:
    result = subprocess.run(
        ["git", "merge-base", "HEAD", base],
        capture_output=True,
        text=True,
        cwd=cwd,
    )
    if result.returncode == 0 and result.stdout.strip():
        return result.stdout.strip()
    fallback = subprocess.run(
        ["git", "rev-parse", "HEAD~1"],
        capture_output=True,
        text=True,
        cwd=cwd,
    )
    if fallback.returncode == 0 and fallback.stdout.strip():
        return fallback.stdout.strip()
    return None


def _no_changes_vs(merge_base: str, cwd: str | None) -> bool:
    result = subprocess.run(
        ["git", "diff", "--quiet", merge_base, "HEAD"],
        capture_output=True,
        text=True,
        cwd=cwd,
    )
    return result.returncode == 0


def _emit_deny(review: str) -> None:
    reason = (
        "Pre-PR review found blocking findings. Address them, then re-run "
        "`gh pr create`:\n\n" + review
    )
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }
    sys.stdout.write(json.dumps(output) + "\n")


if __name__ == "__main__":
    main()
