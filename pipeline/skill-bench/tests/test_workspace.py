import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from skillbench import workspace  # noqa: E402
from skillbench.util import BenchError  # noqa: E402

ENV = workspace.hermetic_git_env()


def git(repo, *args):
    return subprocess.run(["git", *args], cwd=repo, env=ENV, check=True, capture_output=True, text=True).stdout


def write(root, rel, text):
    path = Path(root) / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def skill(name, text, extra=""):
    return f"---\nname: {name}\ndescription: Use when {text}.\n{extra}---\n{text} rule body\n"


class WorkspaceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="skill-bench-test-")
        root = Path(cls.tmp.name)
        cls.source = root / "source"
        cls.source.mkdir()
        git(cls.source, "init", "-q", "-b", "main")
        write(cls.source, "src/a.txt", "one\n")
        write(cls.source, "CLAUDE.md", "Project memory.\n")
        write(cls.source, ".claude/skills/rule-one/SKILL.md", skill("rule-one", "base version"))
        write(cls.source, ".claude/skills/hidden/SKILL.md", skill("hidden", "manual only", "disable-model-invocation: true\n"))
        write(cls.source, ".claude/commands/work.md", "Do the work.\n")
        write(cls.source, ".claude/agents/code-reviewer.md", "---\nname: code-reviewer\ntools: Read, Grep\n---\nReview.\n")
        write(
            cls.source,
            ".claude/settings.json",
            json.dumps(
                {
                    "hooks": {"PreToolUse": []},
                    "enabledPlugins": {"x@y": True},
                    "apiKeyHelper": "./get-key.sh",
                    "env": {"ANTHROPIC_BASE_URL": "https://proxy.test"},
                    "permissions": {"allow": ["Read", "Bash(gh pr view:*)"], "defaultMode": "bypassPermissions", "additionalDirectories": ["/"], "deny": ["Bash(rm:*)"]},
                    "model": "opus",
                }
            ),
        )
        git(cls.source, "add", "-A")
        git(cls.source, "commit", "-q", "-m", "base")
        cls.base = git(cls.source, "rev-parse", "HEAD").strip()

        write(cls.source, "src/a.txt", "one\ntwo\n")
        write(cls.source, "src/b.txt", "new\n")
        write(cls.source, ".claude/skills/rule-one/SKILL.md", skill("rule-one", "changed by the PR"))
        git(cls.source, "add", "-A")
        git(cls.source, "commit", "-q", "-m", "review")
        cls.review = git(cls.source, "rev-parse", "HEAD").strip()

        git(cls.source, "checkout", "-q", "-b", "later", cls.base)
        write(cls.source, ".claude/skills/rule-two/SKILL.md", skill("rule-two", "a later snapshot"))
        git(cls.source, "rm", "-q", "-r", ".claude/skills/rule-one")
        git(cls.source, "add", "-A")
        git(cls.source, "commit", "-q", "-m", "later skills")
        cls.later = git(cls.source, "rev-parse", "HEAD").strip()

        cls.work = workspace.new_work_root(str(root))
        cls.template = workspace.build_template(cls.source, cls.base, cls.review, cls.work)
        cls.ws = {
            name: workspace.materialize(cls.template, workspace.parse_arm(name), cls.source, cls.base, cls.work)
            for name in ("at-pr", "none", f"ref:{cls.later}")
        }

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_workspace_has_exactly_two_commits_and_no_remotes(self):
        path = self.ws["at-pr"].path
        self.assertEqual(
            git(path, "log", "--format=%s").splitlines(), [workspace.REVIEW_MESSAGE, workspace.BASE_MESSAGE]
        )
        self.assertEqual(git(path, "remote").strip(), "")

    def test_replayed_diff_excludes_agent_configuration(self):
        changed = git(self.ws["at-pr"].path, "diff", "--name-only", "HEAD~1", "HEAD").split()
        self.assertEqual(changed, ["src/a.txt", "src/b.txt"])

    def test_snapshot_is_untracked_and_invisible_to_git_status(self):
        path = self.ws["at-pr"].path
        self.assertTrue((path / ".claude/skills/rule-one/SKILL.md").is_file())
        self.assertEqual(git(path, "status", "--porcelain").strip(), "")

    def test_at_pr_uses_the_base_version_of_each_skill(self):
        body = (self.ws["at-pr"].path / ".claude/skills/rule-one/SKILL.md").read_text()
        self.assertIn("base version", body)
        self.assertNotIn("changed by the PR", body)

    def test_catalog_marks_manual_only_skills(self):
        catalog = {s["name"]: s["model_invocable"] for s in self.ws["at-pr"].skills}
        self.assertEqual(catalog, {"hidden": False, "rule-one": True})

    def test_none_arm_drops_only_the_skills(self):
        ws = self.ws["none"]
        self.assertEqual(ws.skills, [])
        self.assertFalse((ws.path / ".claude/skills").exists())
        self.assertEqual(ws.commands, ["work"])
        self.assertEqual(ws.agents, {"code-reviewer": ".claude/agents/code-reviewer.md"})
        self.assertTrue((ws.path / "CLAUDE.md").is_file())

    def test_ref_arm_takes_skills_from_another_commit(self):
        names = [s["name"] for s in self.ws[f"ref:{self.later}"].skills]
        self.assertEqual(names, ["hidden", "rule-two"])  # the later commit removed rule-one

    def test_settings_that_run_code_or_widen_permissions_are_stripped(self):
        ws = self.ws["at-pr"]
        settings = json.loads((ws.path / ".claude/settings.json").read_text())
        self.assertEqual(settings, {"model": "opus", "permissions": {"deny": ["Bash(rm:*)"]}})
        self.assertEqual(
            ws.deviations,
            ["removed hooks, enabledPlugins, apiKeyHelper, env, permissions other than deny from .claude/settings.json"],
        )

    def test_resolve_source_prefers_a_repository_that_has_the_commits(self):
        found = workspace.resolve_source("o/r", [self.base, self.review], str(self.source), self.work / "cache")
        self.assertEqual(found, self.source)

    def test_work_root_inside_a_project_is_refused(self):
        inside = self.source / "nested"
        inside.mkdir(exist_ok=True)
        with self.assertRaises(BenchError):
            workspace.assert_isolated(inside)


class ParseArmTest(unittest.TestCase):
    def test_arms(self):
        self.assertEqual(workspace.parse_arm("at-pr").slug, "at-pr")
        self.assertEqual(workspace.parse_arm("ref:abcdef1234567890").slug, "ref-abcdef123456")
        self.assertFalse(workspace.parse_arm("none").has_skills)
        with self.assertRaises(BenchError):
            workspace.parse_arm("everything")


if __name__ == "__main__":
    unittest.main()
