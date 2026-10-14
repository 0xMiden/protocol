#!/usr/bin/env python3
"""Exercise the release preflight shell with real local Git repositories."""

import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path.cwd()
ACTION = ROOT / ".github/actions/workspace-release/action.yml"
TAG = "v1.0.0"


def preflight_shell():
    step = ACTION.read_text().split(
        "    - name: Verify tag matches release branch HEAD\n", 1
    )[1].split("\n    - name:", 1)[0]
    return textwrap.dedent(step.split("      run: |\n", 1)[1])


def fixture_environment():
    return {
        **os.environ,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "Release preflight test",
        "GIT_AUTHOR_EMAIL": "release-test@example.invalid",
        "GIT_COMMITTER_NAME": "Release preflight test",
        "GIT_COMMITTER_EMAIL": "release-test@example.invalid",
        "GIT_TERMINAL_PROMPT": "0",
    }


def git(cwd, *args, input_text=None):
    result = subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false",
         "-c", "tag.gpgsign=false", *args],
        cwd=cwd, env=fixture_environment(), input=input_text,
        text=True, capture_output=True, check=True,
    )
    return result.stdout.strip()


class ReleaseFixture:
    def __init__(self, parent, branch="main", advanced=False, checkout="first",
                 annotated=False, tag_commit="first", noncommit_tag=False):
        self.branch = branch
        self.seed = parent / "seed"
        self.origin = parent / "origin.git"
        self.checkout = parent / "checkout"
        git(parent, "init", "-b", branch, str(self.seed))
        (self.seed / "version").write_text("release\n")
        git(self.seed, "add", "version")
        git(self.seed, "commit", "-m", "release")
        self.first = git(self.seed, "rev-parse", "HEAD")
        (self.seed / "version").write_text("next development\n")
        git(self.seed, "commit", "-am", "advance branch")
        self.second = git(self.seed, "rev-parse", "HEAD")
        git(self.seed, "branch", "other", self.second)
        target = getattr(self, tag_commit)
        if noncommit_tag:
            target = git(self.seed, "hash-object", "-w", "--stdin", input_text="blob\n")
        if annotated:
            git(self.seed, "tag", "-a", TAG, target, "-m", "release")
        else:
            git(self.seed, "update-ref", "refs/tags/" + TAG, target)
        git(self.seed, "reset", "--hard", self.second if advanced else self.first)
        git(parent, "clone", "--bare", "--no-local", str(self.seed), str(self.origin))
        git(parent, "clone", "--no-checkout", "--no-local", str(self.origin), str(self.checkout))
        git(self.checkout, "checkout", "--detach", getattr(self, checkout))
        # Force the guard to retrieve the event's tag from origin, rather than
        # accidentally passing with a tag already present in the runner clone.
        git(self.checkout, "tag", "-d", TAG)

    def run(self, release_tag=TAG, github_ref=None, release_branch=None):
        env = {
            **fixture_environment(),
            "RELEASE_BRANCH": self.branch if release_branch is None else release_branch,
            "RELEASE_TAG": release_tag,
            "GITHUB_REF": "refs/tags/" + release_tag if github_ref is None else github_ref,
        }
        return subprocess.run(
            ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", preflight_shell()],
            cwd=self.checkout, env=env, text=True, capture_output=True,
        )


class WorkspaceReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="workspace-release-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def fixture(self, name="case", **kwargs):
        parent = self.root / name
        parent.mkdir()
        return ReleaseFixture(parent, **kwargs)

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def assert_rejected(self, result):
        self.assertNotEqual(result.returncode, 0, "Release preflight accepted wrong release commit:\n" + result.stdout)

    def test_matching_lightweight_releases(self):
        for branch in ["main", "next"]:
            with self.subTest(branch=branch):
                self.assert_success(self.fixture(branch, branch=branch).run())

    def test_matching_annotated_releases(self):
        for branch in ["main", "next"]:
            with self.subTest(branch=branch):
                fixture = self.fixture(branch, branch=branch, annotated=True)
                self.assert_success(fixture.run())
                self.assertEqual(git(fixture.checkout, "rev-parse", "refs/tags/" + TAG + "^{commit}"), fixture.first)
                self.assertNotEqual(git(fixture.checkout, "rev-parse", "refs/tags/" + TAG), fixture.first)

    def test_advanced_branch_checkout_cannot_compare_with_itself(self):
        for branch in ["main", "next"]:
            with self.subTest(branch=branch):
                fixture = self.fixture(branch, branch=branch, advanced=True, checkout="second")
                result = fixture.run()
                self.assert_rejected(result)
                self.assertIn("does not match", result.stdout)

    def test_tag_checkout_still_rejects_advanced_branch(self):
        for branch in ["main", "next"]:
            with self.subTest(branch=branch):
                result = self.fixture(branch, branch=branch, advanced=True).run()
                self.assert_rejected(result)
                self.assertIn("does not match", result.stdout)

    def test_wrong_checkout_is_rejected_when_branch_matches_tag(self):
        self.assert_rejected(self.fixture(checkout="second").run())

    def test_event_tag_at_another_commit_is_rejected(self):
        self.assert_rejected(self.fixture(tag_commit="second").run())

    def test_missing_or_invalid_release_tags_are_rejected(self):
        fixture = self.fixture()
        for tag in ["", "bad..tag", "bad tag", "../tag", "v1@{1}", "v1.lock"]:
            with self.subTest(tag=tag):
                result = fixture.run(release_tag=tag)
                self.assert_rejected(result)
                self.assertIn("Invalid release tag", result.stdout)

    def test_triggering_ref_must_match_release_tag(self):
        self.assert_rejected(self.fixture().run(github_ref="refs/heads/main"))

    def test_missing_remote_tag_is_rejected(self):
        self.assert_rejected(self.fixture().run(release_tag="v2.0.0"))

    def test_tag_must_resolve_to_a_commit(self):
        self.assert_rejected(self.fixture(noncommit_tag=True).run())

    def test_fetch_failure_is_rejected(self):
        fixture = self.fixture()
        fixture.origin.rename(fixture.origin.with_name("missing.git"))
        self.assert_rejected(fixture.run())

    def test_release_event_is_bound_to_the_guard(self):
        self.assertIn("RELEASE_TAG: ${{ github.event.release.tag_name }}", ACTION.read_text())
        publish = (ROOT / ".github/workflows/workspace-publish.yml").read_text()
        self.assertIn('verify-branch-head: "true"', publish)
        self.assertIn("release-branch: ${{ github.event.release.target_commitish }}", publish)
        dry_run = (ROOT / ".github/workflows/workspace-dry-run.yml").read_text()
        self.assertIn('verify-branch-head: "false"', dry_run)


if __name__ == "__main__":
    unittest.main(verbosity=2)
