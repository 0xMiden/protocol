"""Per-hook routing tests (Layer 2 of the test plan).

For each hook, parametrize over a table of `(command, should_fire)`
pairs and verify that `_classify.matches(command, *hook.TARGET)`
returns the expected boolean. pytest test IDs include the hook name
so a regression points directly at the responsible script.
"""

from __future__ import annotations

import importlib
from types import SimpleNamespace

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
#
# Some hooks intentionally share a TARGET with another hook
# (see PAIRED_TARGETS below). For each pair, only ONE hook appears in
# the table; routing for the partner is guaranteed identical because
# both delegate to `_classify.matches` with the same arguments.
# `test_paired_hooks_share_target` enforces that contract — if anyone
# changes one hook's TARGET without the other, that test fails and the
# missing per-hook coverage is restored.
HOOK_CASES: list[tuple[str, str, bool]] = [
    # pre_push_review — every must-run / must-not-run case for `git push`.
    # Routing for pre_push_test (same TARGET) is covered transitively.
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
    # pre_commit_lint — `git commit`.
    ("pre_commit_lint", "git commit -m hello", True),
    ("pre_commit_lint", 'git -c commit.gpgsign=false commit -m "x"', True),
    ("pre_commit_lint", "git -c user.name=foo commit", True),
    ("pre_commit_lint", "echo git commit", False),
    ("pre_commit_lint", "git status", False),
    ("pre_commit_lint", "git push", False),
    # pre_pr_draft — `gh pr create`.
    # Routing for post_pr_create_changelog (same TARGET) is covered transitively.
    ("pre_pr_draft", "gh pr create", True),
    ("pre_pr_draft", "gh --repo 0xMiden/miden-base pr create", True),
    ("pre_pr_draft", "gh -R 0xMiden/miden-base pr create --draft", True),
    ("pre_pr_draft", "gh --hostname=github.com pr create", True),
    ("pre_pr_draft", "echo gh pr create", False),
    ("pre_pr_draft", 'echo "gh pr create"', False),
    ("pre_pr_draft", "gh pr list", False),
    ("pre_pr_draft", "gh issue create", False),
]


# Pairs of hooks that intentionally share the same TARGET. The first
# hook in each pair is the one whose routing cases appear in HOOK_CASES;
# the second's coverage rides on the assertion that the targets match.
PAIRED_TARGETS: list[tuple[str, str]] = [
    ("pre_push_review", "pre_push_test"),
    ("pre_pr_draft", "post_pr_create_changelog"),
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


@pytest.mark.parametrize("pair", PAIRED_TARGETS, ids=lambda p: f"{p[0]}_vs_{p[1]}")
def test_paired_hooks_share_target(
    hooks: dict[str, object], pair: tuple[str, str]
) -> None:
    """For documented pairs, verify both hooks export the same TARGET.

    Lets us skip replaying the parametrized routing cases for the
    second hook — its behavior is identical to the first by virtue of
    routing through `_classify.matches` with the same arguments. If
    this test ever fails, either re-align the targets or split the
    pair and add explicit per-hook cases for both.
    """
    a, b = pair
    target_a = hooks[a].TARGET  # type: ignore[attr-defined]
    target_b = hooks[b].TARGET  # type: ignore[attr-defined]
    assert target_a == target_b, (
        f"{a}.TARGET ({target_a!r}) differs from {b}.TARGET ({target_b!r}). "
        f"Either re-align or remove the entry from PAIRED_TARGETS and add "
        f"explicit per-hook routing cases for both."
    )


# pre_push_review review base selection. The review must cover only the commits
# being pushed (the branch's upstream), not the whole branch vs the integration
# branch — otherwise every push re-reviews earlier, already-reviewed commits.
def _fake_proc(returncode: int = 0, stdout: str = "", stderr: str = "") -> SimpleNamespace:
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def test_diff_base_prefers_upstream(monkeypatch: pytest.MonkeyPatch) -> None:
    """When the branch has an upstream, review against it (only the pushed commits)."""
    import pre_push_review

    def fake_run(cmd: list[str], **_kwargs: object) -> SimpleNamespace:
        assert "@{upstream}" in cmd, "upstream must be queried first"
        return _fake_proc(stdout="origin/some-feature-branch\n")

    monkeypatch.setattr(pre_push_review.subprocess, "run", fake_run)
    assert pre_push_review._diff_base() == "origin/some-feature-branch"


def test_diff_base_falls_back_to_default_branch(monkeypatch: pytest.MonkeyPatch) -> None:
    """A never-pushed branch (no upstream) falls back to the remote default branch."""
    import pre_push_review

    def fake_run(cmd: list[str], **_kwargs: object) -> SimpleNamespace:
        if "@{upstream}" in cmd:
            return _fake_proc(returncode=128, stderr="no upstream configured")
        if "symbolic-ref" in cmd:
            return _fake_proc(stdout="origin/next\n")
        return _fake_proc(returncode=1)

    monkeypatch.setattr(pre_push_review.subprocess, "run", fake_run)
    assert pre_push_review._diff_base() == "origin/next"
