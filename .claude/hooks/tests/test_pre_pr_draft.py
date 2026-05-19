"""Tests for `pre_pr_draft` — segment-scoped, flag-value-aware
draft-detection on the matched `gh pr create` segment(s), plus
end-to-end `main()` JSON contract.

Layers:
  - `has_draft_flag(args)` unit tests covering the flag/value walker
    (truthy/falsy `=value`, known boolean shields, unknown-flag
    conservatism).
  - Wired-through cases combining `iter_match_args` + `has_draft_flag`
    against real command strings (segment scoping, multi-segment fold).
  - `main()` end-to-end with mocked stdin/stdout (deny payload shape,
    allow path, malformed payload, multi-segment fold).
"""

from __future__ import annotations

import io
import json

import pytest

from _classify import iter_match_args, match_args
from pre_pr_draft import TARGET, has_draft_flag


# ---------------------------------------------------------------------------
# has_draft_flag — unit-level cases against the walker directly.
# ---------------------------------------------------------------------------


def test_has_draft_flag_empty_args() -> None:
    assert has_draft_flag([]) is False


def test_has_draft_flag_bare_long() -> None:
    assert has_draft_flag(["--draft"]) is True


def test_has_draft_flag_bare_short() -> None:
    assert has_draft_flag(["-d"]) is True


@pytest.mark.parametrize(
    "value, expected",
    [
        ("true", True),
        ("TRUE", True),
        ("True", True),
        ("1", True),
        ("t", True),
        ("T", True),
        # pflag boolean falsy values — must NOT count as draft requested.
        ("false", False),
        ("FALSE", False),
        ("False", False),
        ("0", False),
        ("f", False),
        ("F", False),
        # Anything else also falsy (safe default).
        ("yes", False),
        ("no", False),
        ("anything", False),
        ("", False),
    ],
)
def test_has_draft_flag_long_value_parsing(value: str, expected: bool) -> None:
    assert has_draft_flag([f"--draft={value}"]) is expected


def test_has_draft_flag_short_equals_form() -> None:
    assert has_draft_flag(["-d=true"]) is True
    assert has_draft_flag(["-d=false"]) is False


def test_has_draft_flag_consumed_as_arg_to_title() -> None:
    # --title takes an arg; --draft is its value, not a flag.
    assert has_draft_flag(["--title", "--draft"]) is False


def test_has_draft_flag_chained_consumed_values() -> None:
    # --title eats hello, --body eats world, --draft is finally a flag.
    assert (
        has_draft_flag(["--title", "hello", "--body", "world", "--draft"])
        is True
    )


def test_has_draft_flag_attached_value_does_not_consume_next() -> None:
    # --title=hello is a single token; --draft that follows is a real flag.
    assert has_draft_flag(["--title=hello", "--draft"]) is True


def test_has_draft_flag_known_boolean_does_not_shield() -> None:
    # --web is a known boolean; it doesn't consume --draft as its value.
    assert has_draft_flag(["--web", "--draft"]) is True


def test_has_draft_flag_unknown_flag_consumes_next() -> None:
    # Conservative: if gh ever adds an arg-taking flag we don't know,
    # we'd rather miss a real --draft than allow a non-draft PR.
    assert has_draft_flag(["--brand-new-flag", "--draft"]) is False


def test_has_draft_flag_positional_args_dont_shield() -> None:
    # `gh pr create some-positional --draft` — positionals advance one,
    # so --draft is reachable.
    assert has_draft_flag(["some-positional", "--draft"]) is True


# ---------------------------------------------------------------------------
# Wired through iter_match_args — real command strings.
# ---------------------------------------------------------------------------


# Each case: (command, expected_should_allow). True = ALL matching
# segments are draft (or there are none); False = at least one
# matching segment is non-draft.
DRAFT_CASES: list[tuple[str, bool]] = [
    # Trivial allow / deny.
    ("gh pr create --draft", True),
    ("gh pr create", False),
    # `--draft=value` forms.
    ("gh pr create --draft=true", True),
    ("gh pr create --draft=false", False),  # huitseeker / reviewers
    ("gh pr create --draft=1", True),
    ("gh pr create --draft=0", False),
    # Global flag walk-past still works.
    ("gh -R foo/bar pr create --draft", True),
    ("gh -R foo/bar pr create", False),
    # huitseeker case 1: `--draft` in a different segment doesn't count.
    ("gh pr create && echo --draft", False),
    # huitseeker case 2: `--draft` as the value of `--title` doesn't count.
    ('gh pr create --title "--draft"', False),
    # ...but a legitimate `--draft` after a complete `--title value` does.
    ("gh pr create --title hello --draft", True),
    # Multi-segment fold (security reviewer note): if ANY matching
    # segment lacks --draft, deny.
    ("gh pr create --draft && gh pr create", False),
    ("gh pr create && gh pr create --draft", False),
    ("gh pr create --draft && gh pr create --draft", True),
    # Short-form value-consuming flag shields its value.
    ("gh pr create -t --draft", False),
    ("gh pr create -t hello --draft", True),
]


@pytest.mark.parametrize(
    "case",
    DRAFT_CASES,
    ids=lambda c: c[0].replace(" ", "_").replace('"', "'"),
)
def test_draft_flag_wired_through(case: tuple[str, str | bool]) -> None:
    command, should_allow = case
    # Mirror the main() loop: all matching segments must have --draft.
    matched_segments = list(iter_match_args(command, *TARGET))
    if not matched_segments:
        # No `gh pr create` at all — wouldn't enter this test path.
        pytest.skip(f"no matching segment in {command!r}")
    actual = all(has_draft_flag(args) for args in matched_segments)
    assert actual is should_allow, (
        f"command {command!r}: matched_segments={matched_segments!r}; "
        f"all-have-draft={actual}, expected {should_allow}"
    )


def test_match_args_skipped_when_no_gh_pr_create() -> None:
    # Smoke: commands with no `gh pr create` at all return None from
    # match_args. main() exits 0 silently in that case.
    assert match_args("echo gh pr create", "gh", ["pr", "create"]) is None
    assert match_args("git status", "gh", ["pr", "create"]) is None


# ---------------------------------------------------------------------------
# main() end-to-end with mocked stdin/stdout.
# ---------------------------------------------------------------------------


def _run_main(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    payload: dict | str,
) -> tuple[int, str, str]:
    """Invoke pre_pr_draft.main() with `payload` (a dict; serialized to
    JSON) or a raw string (passed through unchanged) on stdin. Returns
    (exit_code, captured_stdout, captured_stderr).
    """
    import pre_pr_draft  # imported fresh per-call so monkeypatched stdin sticks

    text = payload if isinstance(payload, str) else json.dumps(payload)
    monkeypatch.setattr("sys.stdin", io.StringIO(text))
    with pytest.raises(SystemExit) as exc:
        pre_pr_draft.main()
    captured = capsys.readouterr()
    code = exc.value.code if isinstance(exc.value.code, int) else 0
    return code, captured.out, captured.err


def test_main_emits_deny_payload(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, _ = _run_main(
        monkeypatch, capsys, {"tool_input": {"command": "gh pr create"}}
    )
    assert code == 0  # hook exits 0; deny is in the JSON payload
    parsed = json.loads(out)
    spec = parsed["hookSpecificOutput"]
    assert spec["hookEventName"] == "PreToolUse"
    assert spec["permissionDecision"] == "deny"
    assert "--draft" in spec["permissionDecisionReason"]


def test_main_allows_draft(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, _ = _run_main(
        monkeypatch,
        capsys,
        {"tool_input": {"command": "gh pr create --draft"}},
    )
    assert code == 0
    assert out == ""


def test_main_allows_unrelated_command(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, _ = _run_main(
        monkeypatch,
        capsys,
        {"tool_input": {"command": "echo gh pr create --draft"}},
    )
    assert code == 0
    assert out == ""


def test_main_denies_multi_segment_one_non_draft(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, _ = _run_main(
        monkeypatch,
        capsys,
        {"tool_input": {"command": "gh pr create --draft && gh pr create"}},
    )
    assert code == 0
    parsed = json.loads(out)
    assert parsed["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_main_handles_malformed_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, _ = _run_main(monkeypatch, capsys, "not json at all")
    assert code == 0
    assert out == ""


def test_main_handles_non_dict_tool_input(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, _ = _run_main(monkeypatch, capsys, {"tool_input": "string"})
    assert code == 0
    assert out == ""


def test_main_handles_missing_command_key(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, _ = _run_main(monkeypatch, capsys, {"tool_input": {}})
    assert code == 0
    assert out == ""


def test_main_handles_non_string_command(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, _ = _run_main(
        monkeypatch, capsys, {"tool_input": {"command": 123}}
    )
    assert code == 0
    assert out == ""
