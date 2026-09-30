import sys
import unittest
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from skillbench import buckets as b  # noqa: E402


class TruthBucketTest(unittest.TestCase):
    def test_rules(self):
        cases = [
            # matched, covering, codifiable, listed, loaded, control_rate -> bucket
            ((True, {"s"}, True, {"s"}, {"s"}, 0.0), b.TP_SKILL),
            ((True, {"s"}, True, {"s"}, {"s"}, 0.5), b.TP_BASE),
            ((True, {"s"}, True, {"s"}, set(), 0.0), b.TP_OTHER),
            ((True, set(), True, set(), set(), 0.0), b.TP_OTHER),
            # without a control run, a catch cannot be credited to the skills
            ((True, {"s"}, True, {"s"}, {"s"}, None), b.TP_NO_CONTROL),
            ((True, set(), True, set(), set(), None), b.TP_NO_CONTROL),
            # a covering skill decides the miss bucket, whatever the classifier said
            ((False, {"s"}, False, {"s"}, {"s"}, 0.0), b.FN_APPLICATION),
            ((False, set(), False, set(), set(), 0.0), b.FN_NOT_CODIFIABLE),
            ((False, set(), True, set(), set(), 0.0), b.FN_GAP),
            ((False, {"s"}, True, set(), set(), 0.0), b.FN_NOT_EXPOSED),
            ((False, {"s"}, True, {"s"}, set(), 0.0), b.FN_TRIGGER),
            ((False, {"s"}, True, {"s"}, {"s"}, 0.0), b.FN_APPLICATION),
        ]
        for args, expected in cases:
            with self.subTest(args=args):
                self.assertEqual(b.truth_bucket(*args), expected)

    def test_unmatched_and_modal(self):
        self.assertEqual(b.unmatched_bucket({"s"}, {"s"}), b.UF_SKILL)
        self.assertEqual(b.unmatched_bucket({"s"}, set()), b.UF_OTHER)
        self.assertEqual(b.modal(Counter({b.FN_GAP: 1, b.TP_SKILL: 1})), b.TP_SKILL)  # ties follow ORDER
        self.assertIsNone(b.modal(Counter()))


def run(rid, arm, findings=(), listed=(), invoked=(), read=()):
    return {
        "id": rid,
        "arm": arm,
        "findings": [{"id": f, "path": "a.rs", "severity": "nit", "title": f"title {f}"} for f in findings],
        "telemetry": {"listed": list(listed), "invoked": list(invoked), "read": list(read)},
    }


class EvaluateTest(unittest.TestCase):
    def setUp(self):
        self.truth = [
            {"id": "t1", "kind": "blocking", "rule": "Keep constants in sync.", "codifiable": True, "url": "u1"},
            {"id": "t2", "kind": "nit", "rule": "Name slots clearly.", "codifiable": True, "url": "u2"},
            {"id": "t3", "kind": "should-fix", "rule": "Design choice.", "codifiable": False, "url": "u3"},
        ]
        self.runs = [
            run("at-pr.1", "at-pr", findings=["at-pr.1.f1", "at-pr.1.f2"], listed=["parity", "slots"], invoked=["parity"]),
            run("at-pr.2", "at-pr", findings=["at-pr.2.f1"], listed=["parity", "slots"]),
            run("none.1", "none", findings=["none.1.f1"]),
            run("none.2", "none"),
        ]
        self.matches = {
            "at-pr.1": [{"agent_id": "at-pr.1.f1", "human_id": "t1"}],
            "at-pr.2": [],
            "none.1": [{"agent_id": "none.1.f1", "human_id": "t2"}],
            "none.2": [],
        }
        self.attributions = {
            "at-pr": {
                "t1": {"covering_skills": ["parity"]},
                "t2": {"covering_skills": ["slots"]},
                "t3": {"covering_skills": []},
                "at-pr.1.f2": {"covering_skills": ["parity"]},
                "at-pr.2.f1": {"covering_skills": []},
            }
        }
        self.snapshots = {"at-pr": {"skills": [{"name": "parity", "body_chars": 10}, {"name": "slots", "body_chars": 20}, {"name": "idle", "body_chars": 5}]}}
        self.result = b.evaluate(self.truth, self.runs, self.matches, self.attributions, self.snapshots)

    def test_recall_per_arm(self):
        self.assertEqual(self.result["arms"]["at-pr"]["recall"]["per_run"], {"at-pr.1": 1 / 3, "at-pr.2": 0.0})
        self.assertEqual(self.result["arms"]["none"]["recall"]["mean"], round(1 / 6, 4))
        self.assertEqual(list(self.result["arms"]), ["at-pr", "none"])

    def test_truth_outcomes(self):
        outcomes = self.result["truth_outcomes"]
        self.assertEqual(outcomes["t1"]["at-pr"]["buckets"], {b.FN_TRIGGER: 1, b.TP_SKILL: 1})
        self.assertEqual(outcomes["t2"]["at-pr"]["modal"], b.FN_TRIGGER)
        self.assertEqual(outcomes["t2"]["none"], {"matched_runs": 1, "runs": 2})
        self.assertEqual(outcomes["t3"]["at-pr"]["modal"], b.FN_NOT_CODIFIABLE)

    def test_bucket_counts(self):
        self.assertEqual(
            self.result["arms"]["at-pr"]["buckets"],
            {b.TP_SKILL: 1, b.FN_TRIGGER: 3, b.FN_NOT_CODIFIABLE: 2, b.UF_SKILL: 1, b.UF_OTHER: 1},
        )

    def test_skill_stats(self):
        stats = self.result["skills"]["at-pr"]
        self.assertEqual(
            {k: stats["parity"][k] for k in ("listed_runs", "loaded_runs", "relevant_findings", "tp_attributed", "trigger_misses", "unmatched_linked")},
            {"listed_runs": 2, "loaded_runs": 1, "relevant_findings": 1, "tp_attributed": 1, "trigger_misses": 1, "unmatched_linked": 1},
        )
        self.assertEqual(stats["slots"]["trigger_misses"], 2)
        self.assertEqual(stats["idle"]["listed_runs"], 0)

    def test_top_fixes_are_ranked_by_evidence(self):
        fixes = self.result["top_fixes"]
        self.assertEqual([(f["kind"], f["subject"], f["count"]) for f in fixes], [("trigger", "slots", 2), ("trigger", "parity", 1), ("stale", "parity", 1)])

    def test_unmatched_findings_are_listed(self):
        items = {f["id"]: f["bucket"] for f in self.result["unmatched"]["at-pr"]}
        self.assertEqual(items, {"at-pr.1.f2": b.UF_SKILL, "at-pr.2.f1": b.UF_OTHER})


if __name__ == "__main__":
    unittest.main()
