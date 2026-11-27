"""Tests for `pre_push_lint_test` — which worktree it lints and tests in,
the lint-then-test order, and when it blocks the push.

Layers:
  - `push_source(args)` unit tests for the refspec walker.
  - `main()` end-to-end with mocked stdin and a fake `subprocess.run`
    standing in for `git` and `make`, over real temporary directories that
    each hold a `Cargo.toml` and a `Makefile` with `lint` and `test`
    targets.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import pre_push_lint_test
from pre_push_lint_test import push_source


# ---------------------------------------------------------------------------
# push_source — the source of the only refspec in the `git push` args.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        # No refspec: the current branch is pushed.
        ([], None),
        (["origin"], None),
        # One refspec, in its various forms.
        (["origin", "feature"], "feature"),
        (["origin", "+feature"], "feature"),
        (["origin", "feature:other"], "feature"),
        (["origin", "refs/heads/feature"], "feature"),
        (["origin", "HEAD"], "HEAD"),
        # Options, with and without a separate value, are skipped.
        (["-u", "--force-with-lease", "origin", "feature"], "feature"),
        (["-o", "ci.skip", "origin", "feature"], "feature"),
        (["--push-option=ci.skip", "origin", "feature"], "feature"),
        # A deletion or several refspecs name no single branch.
        (["origin", ":feature"], None),
        (["origin", "feature", "main"], None),
    ],
)
def test_push_source(args: list[str], expected: str | None) -> None:
    assert push_source(args) == expected


# ---------------------------------------------------------------------------
# main() end-to-end with `git` and `make` stubbed.
# ---------------------------------------------------------------------------


def _proc(returncode: int = 0, stdout: str = "") -> SimpleNamespace:
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr="")


class FakeShell:
    """Stands in for `subprocess.run`. Answers the hook's `git` calls from
    `repos` (the directories that are git worktrees) and `branches` (branch
    name -> the worktree it is checked out in), and records each `make`
    target with the name of the directory it ran in. `lint_edits` makes
    `make lint` change the tree: "file" adds a changed file to
    `git status`, "content" changes an already modified file (`git diff`).
    """

    def __init__(
        self,
        repos: list[Path],
        branches: dict[str, Path],
        *,
        failing: tuple[str, ...] = (),
        status: str = "",
        lint_edits: str | None = None,
    ) -> None:
        self.repos = {str(repo) for repo in repos}
        self.branches = branches
        self.failing = failing
        self.status = status
        self.lint_edits = lint_edits
        self.made: list[tuple[str, str]] = []

    def __call__(self, cmd: list[str], **_kwargs: object) -> SimpleNamespace:
        linted = any(target == "lint" for target, _ in self.made)
        if cmd[0] == "make":
            _make, _flag, directory, target = cmd
            self.made.append((target, Path(directory).name))
            return _proc(1 if target in self.failing else 0, stdout=f"{target} output\n")
        if "rev-parse" in cmd:
            directory = cmd[cmd.index("-C") + 1]
            return _proc(stdout=f"{directory}\n") if directory in self.repos else _proc(128)
        if "worktree" in cmd:
            return _proc(
                stdout="".join(
                    f"worktree {path}\nHEAD abc\nbranch refs/heads/{branch}\n\n"
                    for branch, path in self.branches.items()
                )
            )
        if "status" in cmd:
            edited = linted and self.lint_edits == "file"
            return _proc(stdout=self.status + (" M src/lib.rs\n" if edited else ""))
        if "diff" in cmd:
            edited = linted and self.lint_edits == "content"
            return _proc(stdout="-unformatted\n+formatted\n" if edited else "")
        raise AssertionError(f"unexpected command {cmd}")


@pytest.fixture
def root(tmp_path: Path) -> Path:
    """Three Rust worktrees (`session`, `other`, `feature-wt`) and a plain
    directory (`not-a-repo`) under one temporary directory."""
    for name in ("session", "other", "feature-wt"):
        worktree = tmp_path / name
        worktree.mkdir()
        (worktree / "Cargo.toml").write_text("[workspace]\n")
        (worktree / "Makefile").write_text("lint:\n\ttrue\n\ntest:\n\ttrue\n")
    (tmp_path / "not-a-repo").mkdir()
    return tmp_path


def _shell(root: Path, **kwargs: object) -> FakeShell:
    return FakeShell(
        [root / "session", root / "other", root / "feature-wt"],
        {"main": root / "session", "other": root / "other", "feature": root / "feature-wt"},
        **kwargs,  # type: ignore[arg-type]
    )


def _run_main(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    shell: FakeShell,
    command: str,
    cwd: Path,
) -> tuple[int, str]:
    """Invoke main() with `command` run from `cwd`. Returns (exit_code,
    captured_stderr)."""
    monkeypatch.setattr(pre_push_lint_test.subprocess, "run", shell)
    payload = {"tool_input": {"command": command}, "cwd": str(cwd)}
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    with pytest.raises(SystemExit) as exc:
        pre_push_lint_test.main()
    code = exc.value.code if isinstance(exc.value.code, int) else 0
    return code, capsys.readouterr().err


# Each case: (command run from `session`, the worktree lint and test run in).
# `{root}` is the temporary directory holding the worktrees.
PUSH_DIR_CASES: list[tuple[str, str]] = [
    ("git push", "session"),
    ("git push origin", "session"),
    # The push runs in another worktree.
    ("cd {root}/other && git push", "other"),
    ("git -C {root}/other push", "other"),
    ("cd ../other && git push -u origin", "other"),
    ("(cd {root}/other && git push)", "other"),
    ("cd {root}/other && (git push -u origin a b > log 2>&1; echo $?)", "other"),
    # The pushed branch is checked out in another worktree.
    ("git push origin feature", "feature-wt"),
    ("git push -u origin +refs/heads/feature:feature", "feature-wt"),
    ("git -C {root}/other push origin feature", "feature-wt"),
    # When in doubt, the directory the push runs in.
    ("git push origin not-checked-out", "session"),
    ("git -C {root}/other push origin not-checked-out", "other"),
    ("git push origin feature other", "session"),
    ("git push origin HEAD", "session"),
    ("cd $WT && git push origin", "session"),
    ("cd {root}/not-a-repo && git push", "session"),
]


@pytest.mark.parametrize(("command", "expected"), PUSH_DIR_CASES)
def test_main_lints_then_tests_in_pushed_worktree(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    root: Path,
    command: str,
    expected: str,
) -> None:
    shell = _shell(root)
    code, err = _run_main(monkeypatch, capsys, shell, command.format(root=root), root / "session")
    assert code == 0
    assert shell.made == [("lint", expected), ("test", expected)]
    assert f"running make lint in {root / expected}" in err


def test_main_blocks_when_lint_fails(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], root: Path
) -> None:
    shell = _shell(root, failing=("lint",))
    code, err = _run_main(monkeypatch, capsys, shell, "git push", root / "session")
    assert code == 2
    assert shell.made == [("lint", "session")]
    assert "make lint failed" in err
    assert "lint output" in err


def test_main_blocks_when_tests_fail(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], root: Path
) -> None:
    shell = _shell(root, failing=("test",))
    code, err = _run_main(monkeypatch, capsys, shell, "git push", root / "session")
    assert code == 2
    assert shell.made == [("lint", "session"), ("test", "session")]
    assert "make test failed" in err
    assert "test output" in err


@pytest.mark.parametrize("lint_edits", ["file", "content"])
def test_main_blocks_when_lint_changes_the_tree(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    root: Path,
    lint_edits: str,
) -> None:
    """Fixes made by `make lint` are not in the commits being pushed, so the
    push is blocked until they are committed. An already modified file
    (` M` before and after) that lint edits further counts too."""
    shell = _shell(root, status=" M src/lib.rs\n", lint_edits=lint_edits)
    code, err = _run_main(monkeypatch, capsys, shell, "git push", root / "session")
    assert code == 2
    assert shell.made == [("lint", "session")]
    assert "make lint changed files" in err
    assert "Commit those changes" in err


def test_main_allows_a_dirty_tree_that_lint_leaves_alone(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], root: Path
) -> None:
    """Uncommitted changes that were there before lint do not block."""
    shell = _shell(root, status="?? notes.txt\n")
    code, _ = _run_main(monkeypatch, capsys, shell, "git push", root / "session")
    assert code == 0
    assert shell.made == [("lint", "session"), ("test", "session")]


def test_main_does_not_run_on_git_commit(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], root: Path
) -> None:
    shell = _shell(root)
    code, _ = _run_main(monkeypatch, capsys, shell, "git commit -m x", root / "session")
    assert code == 0
    assert shell.made == []
