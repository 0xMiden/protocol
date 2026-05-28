"""Tests for `pre_push_review._diff_base`.

The review base must be the remote's integration branch (origin's
default branch), not the branch's own upstream `@{u}`. Basing on
`@{u}` is wrong for merge commits: after merging the integration
branch in, `merge-base(HEAD, @{u})` lands on the pre-merge tip, so the
reviewed diff drags in the whole merged branch and the reviewers end
up checking already-reviewed upstream code.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

import pre_push_review


@dataclass
class _FakeProc:
    returncode: int
    stdout: str = ""
    stderr: str = ""


def test_diff_base_uses_remote_default_branch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []

    def fake_run(cmd, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        calls.append(cmd)
        return _FakeProc(returncode=0, stdout="origin/next\n")

    monkeypatch.setattr(pre_push_review.subprocess, "run", fake_run)

    assert pre_push_review._diff_base() == "origin/next"
    # It must resolve the remote default branch, never the branch's own
    # upstream `@{u}` (the source of the merge-commit inflation bug).
    assert calls == [
        ["git", "symbolic-ref", "--short", "refs/remotes/origin/HEAD"]
    ]
    assert all("@{u}" not in token for cmd in calls for token in cmd)


def test_diff_base_respects_non_next_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A repo whose default branch is `main` is reviewed against origin/main.
    def fake_run(cmd, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        return _FakeProc(returncode=0, stdout="origin/main\n")

    monkeypatch.setattr(pre_push_review.subprocess, "run", fake_run)
    assert pre_push_review._diff_base() == "origin/main"


def test_diff_base_falls_back_when_remote_head_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # When origin/HEAD isn't configured, fall back to origin/next.
    def fake_run(cmd, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        return _FakeProc(returncode=1, stdout="")

    monkeypatch.setattr(pre_push_review.subprocess, "run", fake_run)
    assert pre_push_review._diff_base() == "origin/next"
