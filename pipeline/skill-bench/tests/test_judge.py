import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from skillbench import judge  # noqa: E402
from skillbench.util import BenchError  # noqa: E402


def candidate(cid, body="Rename this.", source="thread"):
    return {
        "id": cid,
        "source": source,
        "url": f"https://example.test/{cid}",
        "path": "src/lib.rs",
        "line": 3,
        "reviewer": "bob",
        "diff_hunk": "\n".join(f"line {i}" for i in range(100)),
        "comments": [{"author": "bob", "body": body}, {"author": "alice", "body": "done"}],
    }


class ClassificationTest(unittest.TestCase):
    def test_payload_trims_hunks_and_keeps_replies(self):
        payload = judge.classification_payload([candidate("t1", body="x" * 5000)])
        thread = payload["threads"][0]
        self.assertEqual(len(thread["diff_hunk"].splitlines()), 40)
        self.assertEqual(len(thread["comments"][0]["body"]), 4000)
        self.assertEqual([c["author"] for c in thread["comments"]], ["bob", "alice"])

    def test_merge_splits_truth_and_exclusions(self):
        candidates = [candidate(f"t{i}") for i in range(1, 6)]
        verdicts = [
            {"id": "t1", "actionable": True, "kind": "blocking", "rule": "Check the nonce.", "resolved_in_favour": True, "codifiable": True},
            {"id": "t2", "actionable": True, "kind": "nit", "rule": "", "resolved_in_favour": True, "codifiable": False},
            {"id": "t3", "actionable": False, "kind": "question", "rule": "", "resolved_in_favour": True, "codifiable": False},
            {"id": "t4", "actionable": True, "kind": "should-fix", "rule": "Add a test.", "resolved_in_favour": False, "codifiable": True},
        ]
        truth, excluded = judge.merge_classification(candidates, verdicts)
        self.assertEqual([(t["id"], t["kind"], t["codifiable"]) for t in truth], [("t1", "blocking", True), ("t2", "nit", False)])
        self.assertEqual(truth[1]["rule"], "Rename this.")  # falls back to the comment
        self.assertEqual(
            {e["id"]: e["reason"] for e in excluded},
            {"t3": "not actionable (question)", "t4": "refuted in the thread", "t5": "no verdict from the classifier"},
        )


class MatchTest(unittest.TestCase):
    def test_filter_keeps_confident_pairs_with_real_ids(self):
        result = {
            "matches": [
                {"agent_id": "r.f1", "human_id": "t1", "confidence": 0.9, "reason": "same"},
                {"agent_id": "r.f1", "human_id": "t1", "confidence": 0.6, "reason": "dup"},
                {"agent_id": "r.f2", "human_id": "t2", "confidence": 0.3, "reason": "weak"},
                {"agent_id": "r.f9", "human_id": "t1", "confidence": 0.9, "reason": "unknown finding"},
                {"agent_id": "r.f2", "human_id": "t9", "confidence": 0.9, "reason": "unknown truth"},
                {"agent_id": "r.f2", "human_id": "t1", "confidence": 0.5, "reason": "boundary"},
            ]
        }
        kept = judge.filter_matches(result, {"t1", "t2"}, {"r.f1", "r.f2"})
        self.assertEqual([(m["agent_id"], m["human_id"], m["confidence"]) for m in kept], [("r.f1", "t1", 0.9), ("r.f2", "t1", 0.5)])


class AttributionTest(unittest.TestCase):
    def test_items_and_filter(self):
        truth = [{"id": "t1", "rule": "Keep constants in sync.", "excerpt": "MAX drifts", "path": "a.rs"}]
        unmatched = [{"id": "r.f1", "title": "Use padw", "explanation": "cheaper", "path": "b.masm"}]
        items = judge.attribution_items(truth, unmatched)
        self.assertEqual([i["source"] for i in items], ["human review", "automated review"])
        result = {"items": [
            {"id": "t1", "covering_skills": ["masm-rust-constant-parity", "made-up"], "codifiable": True},
            {"id": "zz", "covering_skills": ["x"], "codifiable": True},
        ]}
        verdicts = judge.filter_attribution(result, {"t1", "r.f1"}, {"masm-rust-constant-parity"})
        self.assertEqual(verdicts, {"t1": {"covering_skills": ["masm-rust-constant-parity"], "codifiable": True}})

    def test_payload_truncates_skill_bodies(self):
        payload = judge.attribution_payload([{"name": "s", "description": "d", "body": "b" * 9000}], [])
        self.assertEqual(len(payload["skills"][0]["text"]), 8000)


class CallRoleTest(unittest.TestCase):
    def run_with(self, outputs):
        calls = []

        def fake(cmd, **kwargs):
            calls.append((cmd, kwargs))
            return SimpleNamespace(stdout=outputs[len(calls) - 1], stderr="", returncode=0)

        with tempfile.TemporaryDirectory() as tmp:
            raw = Path(tmp) / "raw" / "x.json"
            try:
                result = judge.call_role(
                    "matcher", {"a": 1}, "matches", model="opus", max_usd=1.0, cwd=Path(tmp), raw_path=raw, timeout=10, runner=fake
                )
            finally:
                written = raw.read_text() if raw.exists() else None
        return result, calls, written

    def test_success_after_one_retry(self):
        good = json.dumps({"subtype": "success", "is_error": False, "structured_output": {"matches": []}, "total_cost_usd": 0.02})
        (output, cost), calls, written = self.run_with(["not json", good])
        self.assertEqual(output, {"matches": []})
        self.assertAlmostEqual(cost, 0.02)
        self.assertEqual(len(calls), 2)
        self.assertEqual(written, good)
        cmd = calls[0][0]
        self.assertEqual(cmd[cmd.index("--tools") + 1], "")
        self.assertIn("--no-session-persistence", cmd)
        self.assertIn('"a": 1', calls[0][1]["input"])

    def test_two_failures_raise(self):
        bad = json.dumps({"subtype": "error_during_execution", "is_error": True, "result": "boom"})
        with self.assertRaises(BenchError):
            self.run_with([bad, bad])


if __name__ == "__main__":
    unittest.main()
