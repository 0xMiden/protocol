"""Tests for the `_classify` module — Layer 1 (primitives) and Layer 3
(edge cases) of the test plan. Layer 2 (per-hook routing) lives in
test_hooks.py.
"""

import pytest

from _classify import (
    iter_match_args,
    match_args,
    matches,
    pipeline_segments,
    strip_assignments,
)


# ---------------------------------------------------------------------------
# pipeline_segments — top-level splitting + shlex tokenization.
# ---------------------------------------------------------------------------


def test_segments_single_command():
    assert pipeline_segments("git push") == [["git", "push"]]


def test_segments_split_on_and_and():
    assert pipeline_segments("cd repo && git push") == [
        ["cd", "repo"],
        ["git", "push"],
    ]


def test_segments_split_on_pipe():
    assert pipeline_segments("cat foo | grep bar") == [
        ["cat", "foo"],
        ["grep", "bar"],
    ]


def test_segments_split_on_or_or_semicolon_amp():
    cmd = "a || b ; c & d"
    assert pipeline_segments(cmd) == [["a"], ["b"], ["c"], ["d"]]


def test_segments_split_on_newline():
    assert pipeline_segments("git push\ngit status") == [
        ["git", "push"],
        ["git", "status"],
    ]


def test_segments_preserves_quoted_separators():
    # Separators inside quotes must not split — shlex sees them as one
    # token with the literal characters.
    assert pipeline_segments('echo "a && b"') == [["echo", "a && b"]]


def test_segments_drops_empty_segments():
    assert pipeline_segments("   ") == []
    assert pipeline_segments("") == []
    assert pipeline_segments(";;;") == []


def test_segments_drops_unbalanced_quotes():
    # An unbalanced quote means everything after the opening `"` is
    # inside a quoted region from the splitter's perspective, so we
    # never see the `&&` as a separator. The single produced segment
    # fails shlex tokenization and is dropped. This matches bash's own
    # behavior — bash would prompt for the closing quote rather than
    # treat `git push` as a separate command.
    assert pipeline_segments('echo "broken && git push') == []


# ---------------------------------------------------------------------------
# strip_assignments — leading FOO=bar removal.
# ---------------------------------------------------------------------------


def test_strip_no_assignments():
    assert strip_assignments(["git", "push"]) == ["git", "push"]


def test_strip_one_assignment():
    assert strip_assignments(["FOO=bar", "git", "push"]) == ["git", "push"]


def test_strip_multiple_assignments():
    assert strip_assignments(["FOO=bar", "BAZ=qux", "git", "push"]) == ["git", "push"]


def test_strip_does_not_eat_args_after_command():
    # `-c k=v` is an arg to git, not a leading assignment. It comes
    # after the command name, so strip_assignments shouldn't touch it.
    # (And we'd never pass it here in practice — strip_assignments only
    # runs on the leading tokens.)
    assert strip_assignments(["git", "-c", "user.name=foo", "commit"]) == [
        "git",
        "-c",
        "user.name=foo",
        "commit",
    ]


def test_strip_rejects_non_identifier_prefix():
    # `=value` alone is not a valid assignment; leave it alone.
    assert strip_assignments(["=value", "git", "push"]) == ["=value", "git", "push"]
    # Digit-leading is not a valid identifier.
    assert strip_assignments(["1FOO=bar", "git"]) == ["1FOO=bar", "git"]


# ---------------------------------------------------------------------------
# matches — the primary classifier entrypoint. The richer per-hook
# parametrized table lives in test_hooks.py; the cases here exercise
# the matcher's own semantics.
# ---------------------------------------------------------------------------


def test_matches_simple():
    assert matches("git push", "git", ["push"]) is True


def test_matches_with_args_after_subcommand():
    assert matches("git push origin main", "git", ["push"]) is True


def test_matches_multi_word_subcommand():
    assert matches("gh pr create", "gh", ["pr", "create"]) is True


def test_matches_rejects_partial_subcommand():
    assert matches("gh pr list", "gh", ["pr", "create"]) is False


def test_matches_rejects_when_binary_is_quoted_argument():
    assert matches('echo "git push"', "git", ["push"]) is False


def test_matches_rejects_bare_substring():
    assert matches("git push-graph", "git", ["push"]) is False


def test_matches_fires_when_any_segment_matches():
    # Multi-segment command, only the second is the real invocation.
    assert matches("cd repo && git push", "git", ["push"]) is True


def test_matches_handles_env_var_prefix():
    assert matches("FOO=bar git push", "git", ["push"]) is True


def test_matches_walks_past_known_git_flags():
    assert matches("git -C . push", "git", ["push"]) is True
    assert matches("git -c user.name=foo push", "git", ["push"]) is True
    assert matches("git --git-dir /tmp/x push", "git", ["push"]) is True


def test_matches_walks_past_known_gh_flags():
    assert matches("gh -R foo/bar pr create", "gh", ["pr", "create"]) is True
    assert matches("gh --repo foo/bar pr create", "gh", ["pr", "create"]) is True
    assert matches("gh --hostname=example.com pr create", "gh", ["pr", "create"]) is True


def test_matches_walks_past_unknown_flag_conservatively():
    # Unknown flag without arg: still finds subcommand.
    assert matches("git --no-pager push", "git", ["push"]) is True


def test_matches_handles_multiple_global_flags():
    assert (
        matches(
            "git -c user.name=foo -C . push origin main",
            "git",
            ["push"],
        )
        is True
    )


def test_matches_empty_command_is_false():
    assert matches("", "git", ["push"]) is False


def test_matches_empty_subcommand_is_false():
    # Asking "does this command run `git <empty>`" is meaningless; we
    # return False rather than vacuously True.
    assert matches("git", "git", []) is False


def test_matches_bare_binary_is_false():
    # `git` alone is not `git push`.
    assert matches("git", "git", ["push"]) is False


def test_matches_handles_redirection():
    # `git push > out` — shlex preserves `>` as a token; the subcommand
    # check ignores everything after `push` anyway.
    assert matches("git push > out.txt", "git", ["push"]) is True


def test_matches_quoted_substring_does_not_fire():
    # Reviewer-reported regression: `printf` with a quoted "git push"
    # is not a push.
    assert matches('printf "git push" > out.txt', "git", ["push"]) is False


# ---------------------------------------------------------------------------
# Edge cases from the test plan.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    ["", "   ", "\n\n", ";;;"],
)
def test_empty_or_whitespace_only_command_is_false(command):
    assert matches(command, "git", ["push"]) is False


def test_backslash_continuation_in_shlex():
    # shlex.split handles backslash-newline as line continuation in
    # POSIX mode. Verify the matcher copes.
    assert matches("git \\\n    push", "git", ["push"]) is True


def test_unbalanced_quotes_segment_dropped():
    # The segment with the bad quote is dropped; remaining segments
    # are still classified. Here there's no good segment, so False.
    assert matches('echo "broken', "git", ["push"]) is False


def test_pipe_with_unrelated_first_command():
    # First segment is `cat`, second is `grep`. Neither is `git push`.
    assert matches("cat file | grep foo", "git", ["push"]) is False


# ---------------------------------------------------------------------------
# match_args — used by pre_pr_draft to scope flag inspection to the
# matched `gh pr create` segment rather than the raw command string.
# ---------------------------------------------------------------------------


def test_match_args_no_args():
    assert match_args("gh pr create", "gh", ["pr", "create"]) == []


def test_match_args_with_simple_args():
    assert match_args("gh pr create --draft", "gh", ["pr", "create"]) == ["--draft"]


def test_match_args_walks_past_global_flags():
    assert match_args(
        "gh -R foo/bar pr create --title x", "gh", ["pr", "create"]
    ) == ["--title", "x"]


def test_match_args_returns_only_matched_segment():
    # The `&& echo --draft` segment must NOT pollute the args.
    assert (
        match_args("gh pr create && echo --draft", "gh", ["pr", "create"]) == []
    )


def test_match_args_no_match_returns_none():
    assert match_args("echo gh pr create --draft", "gh", ["pr", "create"]) is None
    assert match_args("git push", "gh", ["pr", "create"]) is None


def test_match_args_picks_first_matching_segment():
    # If two segments would match (unusual), return the first.
    assert match_args(
        "gh pr create --draft && gh pr create --title y",
        "gh",
        ["pr", "create"],
    ) == ["--draft"]


# ---------------------------------------------------------------------------
# iter_match_args — yields args for every matching segment, so callers
# whose invariant is per-invocation can fold over all of them.
# ---------------------------------------------------------------------------


def test_iter_match_args_no_match():
    assert list(iter_match_args("git status", "gh", ["pr", "create"])) == []


def test_iter_match_args_single_segment():
    assert list(iter_match_args("gh pr create --draft", "gh", ["pr", "create"])) == [
        ["--draft"]
    ]


def test_iter_match_args_two_matching_segments():
    # Both segments match; both args lists are yielded in order.
    assert list(
        iter_match_args(
            "gh pr create --draft && gh pr create",
            "gh",
            ["pr", "create"],
        )
    ) == [["--draft"], []]


def test_iter_match_args_mixed_segments():
    # First segment matches, second is `gh pr list` (different subcommand).
    assert list(
        iter_match_args(
            "gh pr create --draft && gh pr list",
            "gh",
            ["pr", "create"],
        )
    ) == [["--draft"]]


def test_iter_match_args_empty_subcommand():
    # An empty subcommand is meaningless; yield nothing.
    assert list(iter_match_args("gh", "gh", [])) == []
