#!/usr/bin/env python3
"""Pre-PR-creation hook: the final whole-PR review gate.

Per-commit review (`post_commit_review`) catches issues as each commit is
made; this hook is the comprehensive backstop run before `gh pr create`. It
reviews the entire PR — `merge-base(HEAD, BASE)..HEAD` — so it can catch
cross-commit issues a single-commit view misses.

BASE is `origin/<branch>` when `gh pr create` passes `--base <branch>` (so a
PR stacked on another PR is reviewed against that PR's branch only), otherwise
the remote's default branch. When `--head <branch>` is passed, the review runs
in the worktree that has the branch checked out (so the reviewers read the
right files), or against the branch ref when no worktree has it.

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
from _classify import match_args, matches  # noqa: E402
from _hookutils import command_from_payload, read_payload, recent_user_prompts  # noqa: E402
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

    base, head, cwd = resolve_target(match_args(command, *TARGET) or [], cwd)
    merge_base = _merge_base(base, head, cwd)
    if merge_base is None:
        sys.stderr.write("Pre-PR: cannot resolve merge-base; allowing.\n")
        sys.exit(0)
    if _no_changes_vs(merge_base, head, cwd):
        sys.stderr.write("Pre-PR: no changes vs base; allowing.\n")
        sys.exit(0)

    sys.stderr.write(f"Pre-PR: reviewing the whole PR against {base} (code + security)...\n")
    intent = recent_user_prompts(payload.get("transcript_path"))
    blocked, rendered = run_review(f"{merge_base}..{head}", cwd, intent)
    sys.stderr.write(rendered + "\n")

    if blocked:
        _emit_deny(rendered)
    sys.exit(0)


def resolve_target(args: list[str], cwd: str | None) -> tuple[str, str, str | None]:
    """Resolve `(base, head, cwd)` for the review from the `gh pr create` args.

    `base` is the ref to diff against, `head` the ref under review and `cwd`
    the directory the reviewers run in.
    """
    base_branch = flag_value(args, "--base", "-B")
    base = f"origin/{base_branch}" if base_branch else _diff_base(cwd)

    head_branch = flag_value(args, "--head", "-H")
    if head_branch is None:
        return base, "HEAD", cwd
    # `gh` accepts `<owner>:<branch>` for a head in a fork.
    head_branch = head_branch.split(":", 1)[-1]
    worktree = _worktree_for(head_branch, cwd)
    if worktree is not None:
        return base, "HEAD", worktree
    return base, _branch_ref(head_branch, cwd), cwd


def flag_value(args: list[str], long: str, short: str) -> str | None:
    """Return the value of `long`/`short` in `args` (`--base x`, `--base=x`,
    `-B x`), or None when the flag is absent."""
    for i, tok in enumerate(args):
        if tok in (long, short) and i + 1 < len(args):
            return args[i + 1]
        if tok.startswith(f"{long}="):
            return tok.split("=", 1)[1]
    return None


def _worktree_for(branch: str, cwd: str | None) -> str | None:
    """The path of the worktree that has `branch` checked out, if any."""
    result = subprocess.run(
        ["git", "worktree", "list", "--porcelain"],
        capture_output=True,
        text=True,
        cwd=cwd,
    )
    if result.returncode != 0:
        return None
    path = None
    for line in result.stdout.splitlines():
        if line.startswith("worktree "):
            path = line.removeprefix("worktree ")
        elif line == f"branch refs/heads/{branch}":
            return path
    return None


def _branch_ref(branch: str, cwd: str | None) -> str:
    """The local branch when it exists, otherwise its remote-tracking ref."""
    result = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", f"refs/heads/{branch}"],
        capture_output=True,
        text=True,
        cwd=cwd,
    )
    return branch if result.returncode == 0 else f"origin/{branch}"


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


def _merge_base(base: str, head: str, cwd: str | None) -> str | None:
    result = subprocess.run(
        ["git", "merge-base", head, base],
        capture_output=True,
        text=True,
        cwd=cwd,
    )
    if result.returncode == 0 and result.stdout.strip():
        return result.stdout.strip()
    fallback = subprocess.run(
        ["git", "rev-parse", f"{head}~1"],
        capture_output=True,
        text=True,
        cwd=cwd,
    )
    if fallback.returncode == 0 and fallback.stdout.strip():
        return fallback.stdout.strip()
    return None


def _no_changes_vs(merge_base: str, head: str, cwd: str | None) -> bool:
    result = subprocess.run(
        ["git", "diff", "--quiet", merge_base, head],
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
