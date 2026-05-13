"""Tests for `pre_pr_draft.has_draft_flag` — the flag-value-aware
draft-detection on the matched `gh pr create` segment.

Combined with `match_args` from `_classify` (covered separately in
test_classify.py), this gives end-to-end coverage of the draft-check
behavior. The fixture wires both together so each case reads like the
real hook flow: command string → matched segment args → draft check.
"""

from __future__ import annotations

import pytest

from _classify import match_args
from pre_pr_draft import TARGET, has_draft_flag


# Each case: (command, expected_should_allow). True means the hook
# should ALLOW the command (draft flag present); False means DENY
# (draft flag missing).
DRAFT_CASES: list[tuple[str, bool]] = [
    # Trivial allow / deny on the matched segment alone.
    ("gh pr create --draft", True),
    ("gh pr create", False),
    # `--draft=value` form is still the draft flag.
    ("gh pr create --draft=true", True),
    # Global flags between `gh` and `pr create` don't change anything.
    ("gh -R foo/bar pr create --draft", True),
    ("gh -R foo/bar pr create", False),
    # huitseeker case 1: `--draft` in a different segment doesn't count.
    ("gh pr create && echo --draft", False),
    # huitseeker case 2: `--draft` as the value of `--title` doesn't count.
    ('gh pr create --title "--draft"', False),
    # ...but a legitimate `--draft` after a complete `--title value` does.
    ('gh pr create --title hello --draft', True),
    # Other arg-taking flags also shield their value from misreads.
    ("gh pr create --body --draft", False),
    ("gh pr create --label --draft", False),
    ("gh pr create --label bug --draft", True),
    # `--title=value` is a single token, so a trailing `--draft` reads as
    # a fresh flag.
    ("gh pr create --title=hello --draft", True),
    # Short forms of arg-taking flags also shield their value.
    ("gh pr create -t --draft", False),
    ("gh pr create -t hello --draft", True),
    # No `gh pr create` in the command at all — match_args returns None;
    # the hook would exit 0 before calling has_draft_flag. Modelled here
    # by skipping the check entirely.
]


@pytest.mark.parametrize(
    "case",
    DRAFT_CASES,
    ids=lambda c: c[0].replace(" ", "_").replace('"', "'"),
)
def test_draft_flag_detection(case: tuple[str, bool]) -> None:
    command, should_allow = case
    args = match_args(command, *TARGET)
    assert args is not None, f"match_args returned None for {command!r}"
    actual = has_draft_flag(args)
    assert actual is should_allow, (
        f"command {command!r}: match_args={args!r}; "
        f"has_draft_flag returned {actual}, expected {should_allow}"
    )


def test_has_draft_flag_empty_args() -> None:
    assert has_draft_flag([]) is False


def test_has_draft_flag_only_consumed_value() -> None:
    # Only token is the consumed value of --title; --draft as a value
    # is not the flag.
    assert has_draft_flag(["--title", "--draft"]) is False


def test_has_draft_flag_chained_consumed_values() -> None:
    # --title eats hello, --body eats world, --draft is finally a flag.
    assert has_draft_flag(["--title", "hello", "--body", "world", "--draft"]) is True
