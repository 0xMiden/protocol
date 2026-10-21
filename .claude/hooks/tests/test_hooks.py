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
    "post_commit_review",
    "pre_pr_draft",
    "pre_pr_review",
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
    # pre_push_test — every must-run / must-not-run case for `git push`.
    ("pre_push_test", "git push", True),
    ("pre_push_test", "git push origin main", True),
    ("pre_push_test", "git -C . push", True),
    ("pre_push_test", "git -c user.name=foo push", True),
    ("pre_push_test", "git -c user.name=foo -C . push origin main", True),
    ("pre_push_test", "cd repo && git push", True),
    ("pre_push_test", "FOO=bar git push", True),
    ("pre_push_test", "echo git push", False),
    ("pre_push_test", 'echo "git push"', False),
    ("pre_push_test", "git status", False),
    ("pre_push_test", "git --version", False),
    ("pre_push_test", "git push-graph", False),
    # pre_commit_lint — `git commit`.
    # Routing for post_commit_review (same TARGET) is covered transitively.
    ("pre_commit_lint", "git commit -m hello", True),
    ("pre_commit_lint", 'git -c commit.gpgsign=false commit -m "x"', True),
    ("pre_commit_lint", "git -c user.name=foo commit", True),
    ("pre_commit_lint", "git commit --amend --no-edit", True),
    ("pre_commit_lint", "echo git commit", False),
    ("pre_commit_lint", "git status", False),
    ("pre_commit_lint", "git push", False),
    # pre_pr_draft — `gh pr create`.
    # Routing for post_pr_create_changelog and pre_pr_review (same TARGET) is
    # covered transitively.
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
    ("pre_commit_lint", "post_commit_review"),
    ("pre_pr_draft", "post_pr_create_changelog"),
    ("pre_pr_draft", "pre_pr_review"),
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


# _review.run_review's severity parser is the single source of truth for what
# blocks. Verify it counts only Critical/Important/Warnings bullets and ignores
# nits, notes, and absence markers.
def test_count_blocking_findings_counts_only_blocking_sections() -> None:
    import _review

    review = "\n".join(
        [
            "## Review Summary",
            "### Critical Issues",
            "- foo.rs:10 will panic on empty input",
            "### Important Issues",
            "- bar.rs:20 missing test",
            "- baz.rs:30 wrong abstraction",
            "### Warnings",
            "- qux.rs:40 unchecked arithmetic",
            "### Nits",
            "- naming could be clearer",
            "### Notes",
            "- consider documenting this",
            "### What's Done Well",
            "- great test coverage",
        ]
    )
    assert _review._count_blocking_findings(review) == 4


def test_count_blocking_findings_ignores_absence_markers() -> None:
    import _review

    review = "\n".join(
        [
            "### Critical Issues",
            "- None.",
            "### Important Issues",
            "- N/A",
            "### Nits",
            "- a small thing",
        ]
    )
    assert _review._count_blocking_findings(review) == 0


def test_count_blocking_findings_ignores_notes_after_bare_none() -> None:
    """Reproduces the reported bug: the reviewer opens the section with a bare
    "None." line, then explains what it tried below it. Those bullets must
    not count as findings."""
    import _review

    review = "\n".join(
        [
            "### Warnings",
            "",
            "None.",
            "",
            "I specifically tried and failed to break the following:",
            "- Attachment-shadowing.",
            "- Private/malformed targets.",
            "### Notes",
            "- consider adding a regression test",
        ]
    )
    assert _review._count_blocking_findings(review) == 0


def test_count_blocking_findings_ignores_notes_after_same_line_none() -> None:
    """Reproduces the exact reported bug verbatim: "None." and the
    explanation share one line, e.g. "None. I specifically tried and failed
    to break the following:", followed by diligence bullets. Those bullets
    must not count as findings."""
    import _review

    review = "\n".join(
        [
            "### Warnings",
            "",
            "None. I specifically tried and failed to break the following:",
            "",
            "- **Attachment-shadowing.** `ensure_presence` validates every attachment.",
            "- **Private/malformed targets.** `TryFrom` terminates in `NetworkAccountTarget::new`.",
            "### Notes",
            "- consider adding a regression test",
        ]
    )
    assert _review._count_blocking_findings(review) == 0


def test_count_blocking_findings_does_not_treat_none_of_as_absence() -> None:
    """A finding starting with the word "None" (e.g. "None of the callers
    validate this") is not an absence marker - the trailing text keeps it
    off the exact-line match, so it must still be counted."""
    import _review

    review = "\n".join(
        [
            "### Important Issues",
            "- None of the new branches are covered by a test.",
        ]
    )
    assert _review._count_blocking_findings(review) == 1


def test_count_blocking_findings_treats_bold_none_as_absence_marker() -> None:
    """Reviewers habitually bold things, and the period can land inside or
    outside the closing `**` (`**None.**` or `**None**.`). Both, bare or
    bulleted, must clear the section exactly like a plain `None.` would."""
    import _review

    review = "\n".join(
        [
            "### Warnings",
            "**None.**",
            "- Attachment-shadowing details ruled out.",
            "### Critical Issues",
            "- **None.**",
            "- Private targets ruled out.",
        ]
    )
    assert _review._count_blocking_findings(review) == 0


def test_count_blocking_findings_counts_real_finding_before_trailing_none() -> None:
    """A real finding bullet followed later by a stray `- None.` bullet must
    count once, not twice - the `None.` special-case only applies when it's
    the section's first content line; elsewhere it's just skipped, not
    treated as clearing anything."""
    import _review

    review = "\n".join(
        [
            "### Important Issues",
            "- foo.rs:10 will panic on empty input",
            "- None.",
        ]
    )
    assert _review._count_blocking_findings(review) == 1


def test_count_blocking_findings_clearing_does_not_leak_into_next_section() -> None:
    """A `None.`-cleared section must not suppress a *different* blocking
    section that follows it - `section_cleared` has to reset on every new
    `### ` heading, not just stay set once tripped."""
    import _review

    review = "\n".join(
        [
            "### Warnings",
            "None. I tried the following:",
            "- attachment shadowing ruled out",
            "### Critical Issues",
            "- foo.rs:10 unchecked unwrap panics on empty input",
        ]
    )
    assert _review._count_blocking_findings(review) == 1


# _evaluate_reviewer's verdict backstop: a section can be structurally
# cleared (a "None." opener followed by content that reads as ordinary
# bullets) while genuinely containing real findings further down - the
# section-clearing logic in _count_blocking_findings can't tell diligence
# bullets from real ones once a section is cleared. The agent's own leading
# verdict token is a second, independent signal that catches this case even
# when the structured count comes back 0.
def test_evaluate_reviewer_blocks_on_self_reported_block_despite_zero_count() -> None:
    import _review

    stdout = (
        "BLOCK:\n\n"
        "## Adversarial Security Review\n\n"
        "### Warnings\n"
        "None. But actually see the Critical Findings below.\n\n"
        "### Notes\n"
        "- unrelated note\n"
    )
    result = _review.ReviewerResult(name="SECURITY REVIEWER", returncode=0, stdout=stdout, stderr="")
    cleared, rendered = _review._evaluate_reviewer(result)
    assert cleared is False
    assert "verdict says BLOCK" in rendered


@pytest.mark.parametrize("token", ["CLEAN:", "APPROVE:"])
def test_evaluate_reviewer_clears_on_zero_count_for_either_clean_token(token: str) -> None:
    """Both `CLEAN:` (security-reviewer) and `APPROVE:` (code-reviewer) must
    clear a 0-count review."""
    import _review

    stdout = f"{token}\n\n## Review Summary\n\n### Critical Issues\nNone.\n### Important Issues\nNone.\n"
    result = _review.ReviewerResult(name="REVIEWER", returncode=0, stdout=stdout, stderr="")
    cleared, _rendered = _review._evaluate_reviewer(result)
    assert cleared is True


def test_evaluate_reviewer_blocks_when_leading_token_is_missing() -> None:
    """Without the mandatory leading token, block with a diagnosable reason
    instead of silently running with the backstop disabled."""
    import _review

    stdout = "## Adversarial Security Review\n\n### Warnings\nNone.\n### Notes\n- fine\n"
    result = _review.ReviewerResult(name="SECURITY REVIEWER", returncode=0, stdout=stdout, stderr="")
    cleared, rendered = _review._evaluate_reviewer(result)
    assert cleared is False
    assert "did not open with a" in rendered


@pytest.mark.parametrize("token", ["**APPROVE:**", "**APPROVE**:"])
def test_evaluate_reviewer_clears_on_bolded_leading_token(token: str) -> None:
    """The same model that bolds diligence notes bolds its own leading
    token too - must not turn a clean review into a spurious block."""
    import _review

    stdout = f"{token}\n\n## Review Summary\n\n### Critical Issues\nNone.\n### Important Issues\nNone.\n"
    result = _review.ReviewerResult(name="CODE REVIEWER", returncode=0, stdout=stdout, stderr="")
    cleared, _rendered = _review._evaluate_reviewer(result)
    assert cleared is True


def test_evaluate_reviewer_clears_when_token_follows_a_preamble_sentence() -> None:
    """Reproduces an observed failure: the reviewer wrote a sentence or two
    (e.g. noting it couldn't run the test suite) before its own leading
    token line, instead of leading with the bare token as instructed. The
    token must still be found - not just at byte 0."""
    import _review

    stdout = (
        "I could not execute the test suite in this session, so I traced the "
        "changes by hand instead.\n\n"
        "APPROVE:\n\n"
        "## Review Summary\n\n### Critical Issues\nNone.\n### Important Issues\nNone.\n"
    )
    result = _review.ReviewerResult(name="CODE REVIEWER", returncode=0, stdout=stdout, stderr="")
    cleared, _rendered = _review._evaluate_reviewer(result)
    assert cleared is True


def test_evaluate_reviewer_ignores_token_quoted_later_in_the_review_body() -> None:
    """The preamble search must not reach past the first `##` heading - a
    token-shaped line appearing on its own line deeper in the review body
    (e.g. an illustrative example, which would match `_LEADING_VERDICT` in
    isolation) must not be mistaken for the real leading token when the real
    one is genuinely missing."""
    import _review

    stdout = (
        "## Review Summary\n\n"
        "### Nits\n"
        "- An example of what a leading token line looks like:\n"
        "CLEAN:\n"
        "- (illustrative only, not this response's own declaration)\n"
        "### Critical Issues\nNone.\n### Important Issues\nNone.\n"
    )
    result = _review.ReviewerResult(name="CODE REVIEWER", returncode=0, stdout=stdout, stderr="")
    cleared, rendered = _review._evaluate_reviewer(result)
    assert cleared is False
    assert "did not open with a" in rendered


def test_evaluate_reviewer_count_takes_precedence_over_self_reported_clean() -> None:
    """A structured finding always blocks, even if the agent's own leading
    token contradicts it (e.g. says CLEAN). The count check must run before
    the verdict-based backstop, not after."""
    import _review

    stdout = "CLEAN:\n\n## Review Summary\n\n### Critical Issues\n- foo.rs:1 real bug\n"
    result = _review.ReviewerResult(name="CODE REVIEWER", returncode=0, stdout=stdout, stderr="")
    cleared, rendered = _review._evaluate_reviewer(result)
    assert cleared is False
    assert "1 blocking finding(s)" in rendered


# pre_pr_review reviews the whole PR against the integration branch. Verify the
# base resolves to origin/HEAD when set and falls back to origin/next otherwise.
def _fake_proc(returncode: int = 0, stdout: str = "", stderr: str = "") -> SimpleNamespace:
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def test_pre_pr_diff_base_prefers_origin_head(monkeypatch: pytest.MonkeyPatch) -> None:
    import pre_pr_review

    def fake_run(cmd: list[str], **_kwargs: object) -> SimpleNamespace:
        assert "symbolic-ref" in cmd
        return _fake_proc(stdout="origin/next\n")

    monkeypatch.setattr(pre_pr_review.subprocess, "run", fake_run)
    assert pre_pr_review._diff_base(None) == "origin/next"


def test_pre_pr_diff_base_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    import pre_pr_review

    def fake_run(cmd: list[str], **_kwargs: object) -> SimpleNamespace:
        return _fake_proc(returncode=1)

    monkeypatch.setattr(pre_pr_review.subprocess, "run", fake_run)
    assert pre_pr_review._diff_base(None) == "origin/next"
