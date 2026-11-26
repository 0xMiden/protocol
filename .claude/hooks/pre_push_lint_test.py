#!/usr/bin/env python3
"""Pre-push hook: runs `make lint` and then `make test` in Rust
repositories before allowing `git push`. Exit 0 = allow, exit 2 = block
(with reason on stderr).

Lint runs once per push, on the final state, rather than before every
commit, because it takes minutes. `make lint` also formats and applies
fixes: if it changes the working tree, the push is blocked, since the
commits being pushed do not contain those fixes. Commit them and push
again.

The checks run in the worktree being pushed: the directory the
`git push` runs in (following the command's `cd <dir>` segments and
`git -C <dir>`), or, when the push names a single local branch that is
checked out in another worktree (`git push origin <branch>`), that
worktree. When in doubt, the directory the push runs in is used.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _classify import iter_match_args, matches  # noqa: E402
from _hookutils import (  # noqa: E402
    command_dir,
    command_from_payload,
    makefile_has_target,
    read_payload,
    repo_root,
    worktree_for,
)

TARGET = ("git", ["push"])

# `git push` options whose value can be the next token.
_PUSH_OPTIONS_WITH_ARG = frozenset(
    {"--repo", "--receive-pack", "--exec", "-o", "--push-option", "--recurse-submodules"}
)


def main() -> None:
    payload = read_payload()
    command = command_from_payload(payload)
    if command is None or not matches(command, *TARGET):
        sys.exit(0)
    assert payload is not None  # guarded by command check above

    cwd = payload.get("cwd")
    if not isinstance(cwd, str) or not cwd:
        cwd = os.getcwd()

    root = repo_root(push_dir(command, cwd))
    if root is None:
        sys.exit(0)
    if not (root / "Cargo.toml").is_file():
        sys.exit(0)

    makefile = root / "Makefile"
    if makefile_has_target(makefile, "lint"):
        before = _tree_state(root)
        _make(root, "lint")
        if _tree_state(root) != before:
            sys.stderr.write(
                f"make lint changed files in {root}. Commit those changes, then push again: "
                "the commits being pushed do not contain them.\n"
            )
            sys.exit(2)
    if makefile_has_target(makefile, "test"):
        _make(root, "test")
    sys.exit(0)


def push_dir(command: str, cwd: str) -> str:
    """Return the directory to lint and test in for the last `git push` in
    `command`: the worktree that has the pushed branch checked out when the
    push names exactly one, otherwise the directory the push runs in.
    """
    directory = command_dir(command, *TARGET, cwd) or cwd
    args = list(iter_match_args(command, *TARGET))[-1]
    source = push_source(args)
    if source is not None:
        worktree = worktree_for(source, directory)
        if worktree is not None and repo_root(worktree) is not None:
            return worktree
    return directory


def push_source(args: list[str]) -> str | None:
    """Return the source of the only refspec in the `git push` args
    (`[+]<src>[:<dst>]`, with `refs/heads/` dropped), or None when they
    name no refspec, several, or one with an empty source (a deletion).
    The first positional argument is the repository, the rest are
    refspecs.
    """
    positionals: list[str] = []
    i = 0
    while i < len(args):
        if args[i].startswith("-"):
            i += 2 if args[i] in _PUSH_OPTIONS_WITH_ARG else 1
            continue
        positionals.append(args[i])
        i += 1
    refspecs = positionals[1:]
    if len(refspecs) != 1:
        return None
    source = refspecs[0].removeprefix("+").split(":", 1)[0]
    return source.removeprefix("refs/heads/") or None


def _make(root: Path, target: str) -> None:
    """Run `make <target>` in `root`, blocking the push (exit 2) with its
    output if it fails."""
    sys.stderr.write(f"Pre-push: running make {target} in {root}...\n")
    result = subprocess.run(
        ["make", "-C", str(root), target],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        sys.stderr.write(f"make {target} failed - fix it before pushing:\n")
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        sys.exit(2)


def _tree_state(root: Path) -> str:
    """Snapshot of the working tree's changes: `git status --porcelain`
    (which files changed) plus `git diff` (their content, so further edits
    to an already modified file are seen too)."""
    status = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain"],
        capture_output=True,
        text=True,
    )
    diff = subprocess.run(
        ["git", "-C", str(root), "diff"],
        capture_output=True,
        text=True,
    )
    return status.stdout + diff.stdout


if __name__ == "__main__":
    main()
