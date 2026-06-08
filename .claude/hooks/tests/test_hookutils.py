"""Tests for `_hookutils.read_payload` and `command_from_payload` —
the defensive JSON-parsing layer every hook routes through.

`repo_root` and `makefile_has_target` are not unit-tested here because
they're thin wrappers around `git rev-parse --show-toplevel` and
`pathlib.Path.read_text`, exercised end-to-end by the existing hooks
running under `make hooks-test`.
"""

from __future__ import annotations

import io
import json

import pytest

from _hookutils import command_from_payload, read_command, read_payload


# ---------------------------------------------------------------------------
# read_payload — top-level safety.
# ---------------------------------------------------------------------------


def test_read_payload_returns_dict() -> None:
    text = json.dumps({"tool_input": {"command": "git push"}})
    assert read_payload(io.StringIO(text)) == {
        "tool_input": {"command": "git push"}
    }


def test_read_payload_empty_input() -> None:
    assert read_payload(io.StringIO("")) is None


def test_read_payload_malformed_json() -> None:
    assert read_payload(io.StringIO("not json")) is None


def test_read_payload_truncated_json() -> None:
    assert read_payload(io.StringIO('{"tool_input":')) is None


@pytest.mark.parametrize("non_dict", ['"a string"', "42", "[1,2,3]", "true", "null"])
def test_read_payload_non_dict_top_level(non_dict: str) -> None:
    assert read_payload(io.StringIO(non_dict)) is None


# ---------------------------------------------------------------------------
# command_from_payload — extract tool_input.command defensively.
# ---------------------------------------------------------------------------


def test_command_from_payload_happy_path() -> None:
    assert (
        command_from_payload({"tool_input": {"command": "git push"}})
        == "git push"
    )


def test_command_from_payload_empty_command() -> None:
    assert command_from_payload({"tool_input": {"command": ""}}) == ""


def test_command_from_payload_missing_command_key() -> None:
    # `tool_input.command` defaults to "" via .get, so this returns "".
    assert command_from_payload({"tool_input": {}}) == ""


def test_command_from_payload_missing_tool_input() -> None:
    assert command_from_payload({}) is None


@pytest.mark.parametrize("not_dict", [None, "string", 42, [], False])
def test_command_from_payload_non_dict_payload(not_dict: object) -> None:
    assert command_from_payload(not_dict) is None


@pytest.mark.parametrize("not_dict", [None, "string", 42, [], False])
def test_command_from_payload_non_dict_tool_input(not_dict: object) -> None:
    assert command_from_payload({"tool_input": not_dict}) is None


@pytest.mark.parametrize("not_str", [None, 42, [], {}, False])
def test_command_from_payload_non_string_command(not_str: object) -> None:
    assert command_from_payload({"tool_input": {"command": not_str}}) is None


# ---------------------------------------------------------------------------
# read_command — composition of the two.
# ---------------------------------------------------------------------------


def test_read_command_happy_path() -> None:
    text = json.dumps({"tool_input": {"command": "gh pr create --draft"}})
    assert read_command(io.StringIO(text)) == "gh pr create --draft"


def test_read_command_malformed_returns_none() -> None:
    assert read_command(io.StringIO("not json")) is None


def test_read_command_missing_tool_input_returns_none() -> None:
    assert read_command(io.StringIO("{}")) is None
