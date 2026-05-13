"""Per-hook routing tests (Layer 2 of the test plan).

For each hook, parametrize over a table of `(command, should_fire)`
pairs and verify that `_classify.matches(command, *hook.TARGET)`
returns the expected boolean. pytest test IDs include the hook name
so a regression points directly at the responsible script.
"""

from __future__ import annotations

import importlib

import pytest

from _classify import matches


HOOK_NAMES = [
    "pre_commit_lint",
    "pre_pr_draft",
    "pre_push_review",
    "pre_push_test",
    "post_pr_create_changelog",
]


# Per-hook routing cases. The format is `(hook_module, command, should_fire)`.
# We rely on the cases referencing actual hook module names so a typo here
# blows up at collection time instead of silently skipping coverage.
HOOK_CASES: list[tuple[str, str, bool]] = [
    # pre_push_review — every must-run / must-not-run case for `git push`.
    ("pre_push_review", "git push", True),
    ("pre_push_review", "git push origin main", True),
    ("pre_push_review", "git -C . push", True),
    ("pre_push_review", "git -c user.name=foo push", True),
    ("pre_push_review", "git -c user.name=foo -C . push origin main", True),
    ("pre_push_review", "cd repo && git push", True),
    ("pre_push_review", "FOO=bar git push", True),
    ("pre_push_review", "echo git push", False),
    ("pre_push_review", 'echo "git push"', False),
    ("pre_push_review", "git status", False),
    ("pre_push_review", "git --version", False),
    ("pre_push_review", "git push-graph", False),
    # pre_push_test shares the same target as pre_push_review. Replay the
    # most distinctive cases so a divergence between the two hooks would
    # also fail here.
    ("pre_push_test", "git push", True),
    ("pre_push_test", "git -C . push", True),
    ("pre_push_test", "echo git push", False),
    ("pre_push_test", "git status", False),
    # pre_commit_lint — `git commit`.
    ("pre_commit_lint", "git commit -m hello", True),
    ("pre_commit_lint", 'git -c commit.gpgsign=false commit -m "x"', True),
    ("pre_commit_lint", "git -c user.name=foo commit", True),
    ("pre_commit_lint", "echo git commit", False),
    ("pre_commit_lint", "git status", False),
    ("pre_commit_lint", "git push", False),
    # pre_pr_draft — `gh pr create`.
    ("pre_pr_draft", "gh pr create", True),
    ("pre_pr_draft", "gh --repo 0xMiden/miden-base pr create", True),
    ("pre_pr_draft", "gh -R 0xMiden/miden-base pr create --draft", True),
    ("pre_pr_draft", "gh --hostname=github.com pr create", True),
    ("pre_pr_draft", "echo gh pr create", False),
    ("pre_pr_draft", 'echo "gh pr create"', False),
    ("pre_pr_draft", "gh pr list", False),
    ("pre_pr_draft", "gh issue create", False),
    # post_pr_create_changelog shares the same target as pre_pr_draft.
    ("post_pr_create_changelog", "gh pr create", True),
    ("post_pr_create_changelog", "gh -R 0xMiden/miden-base pr create", True),
    ("post_pr_create_changelog", "echo gh pr create", False),
]


@pytest.fixture(scope="module")
def hooks() -> dict[str, object]:
    """Import every hook module exactly once and return name -> module."""
    return {name: importlib.import_module(name) for name in HOOK_NAMES}


def _case_id(case: tuple[str, str, bool]) -> str:
    hook, command, expected = case
    # Pytest IDs cannot contain spaces; replace for readability.
    safe_cmd = command.replace(" ", "_").replace("\n", "\\n")
    return f"{hook}-{safe_cmd}-{expected}"


@pytest.mark.parametrize("case", HOOK_CASES, ids=_case_id)
def test_hook_routes(hooks: dict[str, object], case: tuple[str, str, bool]) -> None:
    hook_name, command, should_fire = case
    hook = hooks[hook_name]
    binary, subcommand = hook.TARGET  # type: ignore[attr-defined]
    actual = matches(command, binary, subcommand)
    assert actual is should_fire, (
        f"{hook_name}.TARGET={hook.TARGET!r} expected matches({command!r}) "  # type: ignore[attr-defined]
        f"== {should_fire}, got {actual}"
    )


def test_all_hooks_export_target(hooks: dict[str, object]) -> None:
    """Smoke test: every hook module exposes a TARGET tuple of
    (binary: str, subcommand: list[str])."""
    for name, hook in hooks.items():
        target = getattr(hook, "TARGET", None)
        assert target is not None, f"{name} is missing TARGET"
        assert isinstance(target, tuple) and len(target) == 2, f"{name}.TARGET shape wrong: {target!r}"
        binary, subcommand = target
        assert isinstance(binary, str) and binary, f"{name}.TARGET[0] must be a non-empty str"
        assert isinstance(subcommand, list) and subcommand, f"{name}.TARGET[1] must be a non-empty list"
        assert all(isinstance(x, str) and x for x in subcommand), (
            f"{name}.TARGET[1] must be a list of non-empty strings"
        )
