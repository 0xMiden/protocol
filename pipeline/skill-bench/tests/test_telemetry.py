import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from skillbench import telemetry  # noqa: E402


def tool_use(uid, name, **params):
    return {"type": "assistant", "message": {"content": [{"type": "tool_use", "id": uid, "name": name, "input": params}]}}


def result(uid, error=False):
    return {"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": uid, "is_error": error, "content": "..."}]}}


def write_jsonl(path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(r) for r in records) + "\nnot json\n")


class ParseSessionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.ws = root / "ws"
        (self.ws / ".claude/skills/rule-a").mkdir(parents=True)
        self.transcript = root / "projects" / "p" / "sid.jsonl"
        write_jsonl(
            self.transcript,
            [
                {"type": "attachment", "attachment": {"type": "skill_listing", "names": ["rule-a", "rule-b", "code-review"], "isInitial": True}},
                {"type": "attachment", "attachment": {"type": "skill_listing", "names": ["rule-c"], "isInitial": False}},
                tool_use("u1", "Skill", skill="rule-a"),
                {"type": "user", "isMeta": True, "sourceToolUseID": "u1", "message": {"content": [{"type": "text", "text": "x" * 42}]}},
                tool_use("u2", "Skill", skill="/code-review"),
                tool_use("u3", "Read", file_path=str(self.ws / ".claude/skills/rule-b/SKILL.md")),
                tool_use("u4", "Read", file_path="src/lib.rs"),
                tool_use("u5", "Read", file_path="/etc/passwd"),
                tool_use("u6", "Bash", command="git show HEAD:.claude/skills/rule-d/SKILL.md"),  # not a read-like command
                result("u6", error=True),
                tool_use("u7", "Bash", command="cat .claude/skills/edited/SKILL.md"),  # the PR edits this file
                result("u7"),
                tool_use("u12", "Bash", command="head -20 .claude/skills/rule-g/SKILL.md"),
                result("u12"),
                tool_use("u13", "Bash", command="cat .claude/skills/rule-h/SKILL.md"),
                result("u13", error=True),  # a failed read does not count
                tool_use("u14", "Bash", command="ls .claude/skills/* | head"),
                result("u14"),
                tool_use("u15", "Bash", command="grep -rn padw .claude/skills/rule-i/"),
                result("u15"),
                tool_use("u16", "Bash", command="cat .claude/skills/edited/references/notes.md"),  # not the edited file
                result("u16"),
                tool_use("u8", "Grep", pattern="padw", path=str(self.ws / ".claude/skills/rule-e")),
                tool_use("u9", "Read", file_path=str(root / "config/projects/p/sid/tool-results/big.txt")),
                tool_use("u10", "Bash", command=f"cat /home/someone/repo/src/lib.rs 2>/dev/null; head {self.ws}/src/a.rs"),
                tool_use("u11", "Bash", command='find . -path "*/account/*" | head; git show HEAD:src/x.rs; ls crates/a/src'),
            ],
        )
        write_jsonl(
            self.transcript.with_suffix("") / "subagents" / "agent-1.jsonl",
            [tool_use("s1", "Skill", skill="rule-f")],
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_summary(self):
        tele = telemetry.parse_session(
            self.transcript,
            self.ws,
            ".claude/skills",
            ignore_files=(".claude/skills/edited/SKILL.md",),
            internal_dirs=(Path(self.tmp.name) / "config/projects",),
        )
        self.assertEqual(tele["listed"], ["rule-a", "rule-b", "code-review", "rule-c"])
        self.assertEqual(tele["invoked"], ["code-review", "rule-a", "rule-f"])
        self.assertEqual(tele["invocations"], 3)
        self.assertEqual(tele["read"], ["edited", "rule-b", "rule-g"])
        self.assertEqual(tele["searched"], ["rule-e", "rule-i"])
        self.assertEqual(tele["outside_paths"], ["/etc/passwd", "/home/someone/repo/src/lib.rs"])
        self.assertEqual(tele["body_chars"], {"rule-a": 42})
        self.assertEqual(tele["subagent_transcripts"], 1)
        self.assertEqual(tele["tool_counts"]["Read"], 4)


class CheckExposureTest(unittest.TestCase):
    BUILTINS = ["code-review", "simplify"]

    def test_expected_plus_builtins_is_valid(self):
        result = telemetry.check_exposure(["a", "b", "code-review"], self.BUILTINS, ["a", "b"], True)
        self.assertEqual((result["valid"], result["leaked"], result["missing"]), (True, [], []))

    def test_user_skill_leak_invalidates(self):
        result = telemetry.check_exposure(["a", "eq-design-system", "x:y"], self.BUILTINS, ["a"], True)
        self.assertFalse(result["valid"])
        self.assertEqual(result["leaked"], ["eq-design-system", "x:y"])

    def test_missing_expected_skill_is_reported_but_valid(self):
        result = telemetry.check_exposure(["a"], self.BUILTINS, ["a", "b"], True)
        self.assertEqual((result["valid"], result["missing"]), (True, ["b"]))

    def test_project_skill_named_like_a_builtin_counts_as_expected(self):
        result = telemetry.check_exposure(["simplify"], self.BUILTINS, ["simplify"], True)
        self.assertEqual((result["valid"], result["missing"]), (True, []))

    def test_without_skill_tool_nothing_may_be_listed(self):
        self.assertTrue(telemetry.check_exposure([], self.BUILTINS, [], False)["valid"])
        self.assertFalse(telemetry.check_exposure(["a"], self.BUILTINS, [], False)["valid"])


if __name__ == "__main__":
    unittest.main()
