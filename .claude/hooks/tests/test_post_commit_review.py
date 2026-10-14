"""Commit-result handling must distinguish commits from later status output."""

import contextlib
import io
import json
import sys
from unittest.mock import patch

import pytest
import post_commit_review as hook


def run_hook(response):
    payload = {
        "tool_input": {"command": "git commit -m change && git status"},
        "tool_response": response,
    }
    with (
        patch.object(sys, "stdin", io.StringIO(json.dumps(payload))),
        patch.object(hook, "_has_parent", return_value=True),
        patch.object(hook, "_no_changes", return_value=False),
        patch.object(hook, "recent_user_prompts", return_value=None),
        patch.object(hook, "run_review", return_value=(False, "")) as review,
        contextlib.redirect_stderr(io.StringIO()),
    ):
        with pytest.raises(SystemExit) as exited:
            hook.main()
        assert exited.value.code == 0
        return review


@pytest.mark.parametrize("summary", [
    "[feature 1234567] Change behavior",
    "[detached HEAD 1234567] Change behavior",
    "[main (root-commit) 1234567] Change behavior",
    "[feature 1234] Change behavior",
    "[feature 1234567] Explain nothing to commit",
])
@pytest.mark.parametrize("structured", [False, True])
def test_successful_commit_is_reviewed_despite_clean_status(summary, structured):
    stdout = summary + "\n 1 file changed, 1 insertion(+)\nnothing to commit, working tree clean\n"
    response = {"stdout": stdout, "stderr": ""} if structured else stdout
    run_hook(response).assert_called_once_with("HEAD~1..HEAD", None, None)


@pytest.mark.parametrize("marker", [
    "nothing to commit, working tree clean",
    "no changes added to commit",
    "nothing added to commit but untracked files present",
])
@pytest.mark.parametrize("structured", [False, True])
def test_unsuccessful_commit_does_not_review_previous_commit(marker, structured):
    response = {"stdout": marker, "stderr": ""} if structured else marker
    assert run_hook(response).call_count == 0


def test_plain_successful_commit_remains_reviewed():
    run_hook("[feature 1234567] Change behavior\n").assert_called_once_with("HEAD~1..HEAD", None, None)
