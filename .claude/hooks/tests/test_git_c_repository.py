"""Commit/push checks must run in the repository selected by git -C."""

import json
import shlex
import subprocess
import sys
from pathlib import Path

import pytest


HOOKS = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "hook, action, check",
    [("pre_commit_lint", "commit", "lint"), ("pre_push_test", "push", "test")],
)
@pytest.mark.parametrize("outside_repo", [False, True], ids=["in-repo", "outside-repo"])
@pytest.mark.parametrize("target_fails", [False, True], ids=["target-passes", "target-fails"])
@pytest.mark.parametrize(
    "selection",
    ["absolute", "relative", "repeated", "git-dir-work-tree", "config", "other-command"],
)
def test_hooks_check_selected_repository(
    tmp_path: Path,
    hook: str,
    action: str,
    check: str,
    outside_repo: bool,
    target_fails: bool,
    selection: str,
) -> None:
    caller = tmp_path / "caller"
    target = tmp_path / "target ; repo"
    outside = tmp_path / "outside"
    outside.mkdir()
    # Opposite outcomes ensure the caller cannot decide whether to block.
    for root, fails in [(caller, not target_fails), (target, target_fails)]:
        subprocess.run(
            ["git", "init", "--quiet", str(root)],
            check=True, capture_output=True, text=True,
        )
        (root / "Cargo.toml").write_text("# Rust repository sentinel\n")
        (root / "Makefile").write_text(
            f".PHONY: {check}\n{check}:\n"
            f"\t@echo {check} > {check}.ran\n"
            + ("\t@false\n" if fails else "\t@true\n")
        )

    quoted_target = shlex.quote(str(target))
    commands = {
        "absolute": f"git -C {quoted_target} {action}",
        "relative": f"git -C {shlex.quote('../' + target.name)} {action}",
        "repeated": f"git -C .. -C '' -C {shlex.quote(target.name)} {action}",
        "git-dir-work-tree": f"git --git-dir={shlex.quote(str(target / '.git'))} "
                             f"--work-tree={quoted_target} {action}",
        "config": f"FOO=bar git -c user.name={action} -C {quoted_target} {action}",
        "other-command": f"git -C {shlex.quote(str(caller))} status && "
                         f"git -C {quoted_target} {action}",
    }
    result = subprocess.run(
        [sys.executable, "-B", str(HOOKS / f"{hook}.py")],
        cwd=outside if outside_repo else caller,
        input=json.dumps({"tool_input": {"command": commands[selection]}}),
        capture_output=True, text=True,
    )
    assert (target / f"{check}.ran").is_file(), (
        f"target repository was not checked; "
        f"caller_ran={(caller / f'{check}.ran').exists()}; stderr={result.stderr}"
    )
    assert result.returncode == (2 if target_fails else 0), result.stderr
    assert (target / f"{check}.ran").read_text().strip() == check
    assert not (caller / f"{check}.ran").exists()
    if target_fails:
        assert f"make {check} failed" in result.stderr


@pytest.mark.parametrize(
    "hook, action, check",
    [("pre_commit_lint", "commit", "lint"), ("pre_push_test", "push", "test")],
)
def test_hooks_check_each_selected_repository(
    tmp_path: Path, hook: str, action: str, check: str
) -> None:
    roots = [tmp_path / "first repo", tmp_path / "second repo"]
    for index, root in enumerate(roots):
        subprocess.run(
            ["git", "init", "--quiet", str(root)],
            check=True, capture_output=True, text=True,
        )
        (root / "Cargo.toml").write_text("# Rust repository sentinel\n")
        (root / "Makefile").write_text(
            f".PHONY: {check}\n{check}:\n"
            f"\t@echo {check} > {check}.ran\n"
            + ("\t@false\n" if index else "\t@true\n")
        )
    command = " && ".join(
        f"git -C {shlex.quote(str(root))} {action}" for root in roots
    )
    result = subprocess.run(
        [sys.executable, "-B", str(HOOKS / f"{hook}.py")],
        cwd=tmp_path,
        input=json.dumps({"tool_input": {"command": command}}),
        capture_output=True, text=True,
    )
    assert result.returncode == 2, result.stderr
    assert f"make {check} failed" in result.stderr
    assert all((root / f"{check}.ran").read_text().strip() == check for root in roots)
