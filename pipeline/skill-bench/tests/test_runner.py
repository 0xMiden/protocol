import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from skillbench import roles, runner  # noqa: E402
from skillbench.util import BenchError  # noqa: E402
from skillbench.workspace import Workspace, parse_arm  # noqa: E402


class RolesTest(unittest.TestCase):
    def test_every_role_and_schema_loads(self):
        for path in sorted(roles.ROLES_DIR.glob("*.md")):
            role = roles.load_role(path.stem)
            self.assertEqual(role.name, path.stem)
            self.assertTrue(role.description and role.prompt)
            json.loads(roles.agents_json(role))
        for path in sorted(roles.SCHEMAS_DIR.glob("*.json")):
            self.assertEqual(json.loads(roles.load_schema(path.stem))["type"], "object")

    def test_reviewer_prompt_does_not_prime_skill_use(self):
        self.assertNotIn("skill", roles.load_role("reviewer").prompt.lower())

    def test_added_tools_are_appended_once(self):
        role = roles.Role("a", "d", "p", tools=["Read", "Skill"])
        spec = json.loads(roles.agents_json(role, name="b", add_tools=("Skill", "Grep")))
        self.assertEqual(spec, {"b": {"description": "d", "prompt": "p", "tools": ["Read", "Skill", "Grep"]}})


class ReviewCommandTest(unittest.TestCase):
    def test_isolation_flags(self):
        cmd = runner.review_command(runner.plain_reviewer(), "sid", model="opus", max_usd=2.5)
        joined = " ".join(cmd)
        self.assertEqual(cmd[:2], ["claude", "-p"])
        for flag in ("--setting-sources project", "--strict-mcp-config", "--permission-mode default", "--session-id sid", "--agent reviewer", "--model opus", "--max-budget-usd 2.50", "--output-format stream-json"):
            self.assertIn(flag, joined)
        self.assertEqual(json.loads(cmd[cmd.index("--settings") + 1]), {"syncClaudeAiSkills": False})
        self.assertEqual(cmd[cmd.index("--tools") + 1], "Read,Grep,Glob,Bash,Skill")
        for denied in ("WebFetch", "WebSearch", "Bash(gh", "Bash(curl"):
            self.assertNotIn(denied, joined)
        start = cmd.index("--allowedTools") + 1
        allowed = cmd[start : start + len(runner.ALLOWED_TOOLS)]
        self.assertEqual(allowed, runner.ALLOWED_TOOLS)
        # Pre-approving a read tool would open files outside the workspace, and a
        # prefix rule for git would also admit write forms such as --output=<file>.
        self.assertEqual(allowed, ["Skill"])

    def test_parse_stream(self):
        stdout = "\n".join(
            [
                json.dumps({"type": "system", "subtype": "init", "model": "m"}),
                "garbage",
                json.dumps({"type": "assistant"}),
                json.dumps({"type": "result", "subtype": "success", "structured_output": {"findings": []}}),
            ]
        )
        init, result = runner.parse_stream(stdout)
        self.assertEqual(init["model"], "m")
        self.assertEqual(result["subtype"], "success")


class ReviewerForTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        path = Path(self.tmp.name)
        (path / ".claude/agents").mkdir(parents=True)
        (path / ".claude/agents/code-reviewer.md").write_text("---\nname: code-reviewer\ndescription: Reviews\ntools: Read, Grep\n---\nReview it.\n")
        self.ws = Workspace(path=path, arm=parse_arm("at-pr"), agents={"code-reviewer": ".claude/agents/code-reviewer.md"})

    def tearDown(self):
        self.tmp.cleanup()

    def test_repo_agent_as_is_has_no_skill_tool(self):
        reviewer = runner.reviewer_for("repo-agent", self.ws)
        self.assertEqual((reviewer.agent, reviewer.agents_json, reviewer.has_skill_tool), ("code-reviewer", None, False))

    def test_repo_agent_with_skills_adds_the_tool(self):
        reviewer = runner.reviewer_for("repo-agent+skills", self.ws)
        spec = json.loads(reviewer.agents_json)
        self.assertEqual(spec["code-reviewer-with-skills"]["tools"], ["Read", "Grep", "Skill"])
        self.assertTrue(reviewer.has_skill_tool)

    def test_missing_repo_agent_is_an_error(self):
        with self.assertRaises(BenchError):
            runner.reviewer_for("repo-agent", self.ws, repo_agent="nope")


class RunSessionTest(unittest.TestCase):
    def test_timeout_is_recorded_not_raised(self):
        from unittest import mock

        from skillbench.util import BenchTimeout

        partial = json.dumps({"type": "system", "subtype": "init", "model": "m"}) + "\n"
        with mock.patch("skillbench.runner.run", side_effect=BenchTimeout("slow", partial, "")):
            session = runner.run_session(lambda sid: ["claude"], Path("."), "p", 5)
        self.assertEqual((session.error, session.attempts, session.init["model"]), ("timed out after 5s", 1, "m"))

    def test_cost_is_summed_over_retries(self):
        from types import SimpleNamespace
        from unittest import mock

        failed = json.dumps({"type": "result", "subtype": "error_during_execution", "is_error": True, "total_cost_usd": 0.3})
        succeeded = json.dumps({"type": "result", "subtype": "success", "is_error": False, "total_cost_usd": 0.2})
        outputs = [SimpleNamespace(stdout=s, stderr="", returncode=0) for s in (failed, succeeded)]
        with mock.patch("skillbench.runner.run", side_effect=outputs):
            session = runner.run_session(lambda sid: ["claude"], Path("."), "p", 5)
        self.assertIsNone(session.error)
        self.assertEqual(session.attempts, 2)
        self.assertAlmostEqual(session.cost_usd, 0.5)


class FinalizeTest(unittest.TestCase):
    def record(self, listed, error=None):
        return {
            "error": error,
            "has_skill_tool": True,
            "expected_listing": ["rule-a"],
            "telemetry": {"listed": listed, "read": ["rule_a_dir"], "searched": []},
        }

    def test_valid_run_maps_read_dirs_to_skill_names(self):
        record = self.record(["rule-a", "code-review"])
        runner.finalize(record, ["code-review"], {"skills": [{"dir": "rule_a_dir", "name": "rule-a"}]})
        self.assertTrue(record["valid"])
        self.assertEqual(record["telemetry"]["read"], ["rule-a"])

    def test_leak_or_error_invalidates(self):
        leak = self.record(["rule-a", "eq-design-system"])
        runner.finalize(leak, [], {"skills": []})
        self.assertFalse(leak["valid"])
        failed = self.record(["rule-a"], error="no result message")
        runner.finalize(failed, [], {"skills": []})
        self.assertEqual(failed["problems"], ["no result message"])


if __name__ == "__main__":
    unittest.main()
