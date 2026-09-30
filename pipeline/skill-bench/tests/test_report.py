import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from skillbench import judge, report, stages  # noqa: E402
from skillbench.util import read_json, write_json  # noqa: E402


def make_run_dir(root: Path) -> Path:
    run_dir = root / "run"
    write_json(run_dir / "config.json", {"repo": "o/r", "number": 1, "arms": ["at-pr", "none"], "runs": 1, "reviewer": "plain", "model": None, "judge_model": "opus", "skills_dir": ".claude/skills", "tool_version": "0.1.0", "max_usd_review": 3.0, "max_usd_judge": 1.0, "round": 1, "calibration_model": "haiku"})
    write_json(run_dir / "pr.json", {"repo": "o/r", "number": 1, "title": "Change", "url": "https://example.test/1", "round": 1, "review_sha": "a" * 40, "base_sha": "b" * 40, "author": "alice", "reviewers": ["bob"], "warnings": []})
    write_json(run_dir / "truth.json", {"truth": [{"id": "t1", "url": "u1", "reviewer": "bob", "path": "a.rs", "line": 1, "kind": "nit", "rule": "Name it well.", "codifiable": True, "excerpt": "x"}], "excluded": [], "cost_usd": 0.1})
    write_json(run_dir / "builtins.json", {"names": ["code-review"], "cost_usd": 0.01})
    write_json(run_dir / "environment.json", {"claude_version": "2.1.280", "auth": {"authMethod": "claude.ai", "subscriptionType": "team", "api_key_in_environment": False}})
    write_json(run_dir / "snapshots" / "at-pr.json", {"skills": [{"name": "naming", "description": "Use when naming.", "body_chars": 3}], "deviations": ["removed hooks from .claude/settings.json"], "skill_bodies": {"naming": "abc"}})
    for rid, arm, listed in (("at-pr.1", "at-pr", ["naming", "code-review"]), ("none.1", "none", ["code-review"])):
        write_json(run_dir / "runs" / f"{rid}.json", {"id": rid, "arm": arm, "valid": True, "problems": [], "findings": [{"id": f"{rid}.f1", "path": "a.rs", "severity": "nit", "title": "t"}], "telemetry": {"listed": listed, "invoked": [], "read": [], "outside_paths": []}, "exposure": {"missing": []}, "denied": [], "cost_usd": 0.5})
        write_json(run_dir / "matches" / f"{rid}.json", {"matches": [], "cost_usd": 0.05})
    write_json(run_dir / "attribution" / "at-pr.json", {"items": {"t1": {"covering_skills": ["naming"], "codifiable": True}}, "cost_usd": 0.2})
    return run_dir


class ReportTest(unittest.TestCase):
    def test_result_is_deterministic_and_rendered(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = make_run_dir(Path(tmp))
            config = read_json(run_dir / "config.json")
            stages.stage_report(run_dir, config)
            first = (run_dir / "result.json").read_bytes()
            stages.stage_report(run_dir, config)
            self.assertEqual(first, (run_dir / "result.json").read_bytes())
            result = read_json(run_dir / "result.json")
            self.assertEqual(result["costs"], {"reviews_usd": 1.0, "judge_usd": 0.4, "calibration_usd": 0.01, "total_usd": 1.41})
            self.assertEqual(result["truth_outcomes"]["t1"]["at-pr"]["modal"], "fn-trigger-miss")
            markdown = (run_dir / "report.md").read_text()
            self.assertIn("# skill-bench: o/r#1, review round 1", markdown)
            self.assertIn("`naming` was shown to the reviewer but not loaded", markdown)
            self.assertIn("count against usage limits", markdown)

    def test_stale_judge_results_are_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = make_run_dir(Path(tmp))
            config = read_json(run_dir / "config.json")
            # the fixture's judge files carry no input digest, so everything is stale
            self.assertEqual(
                stages.stale_results(run_dir, config), ["matches for at-pr.1", "matches for none.1", "attribution for at-pr"]
            )
            truth = read_json(run_dir / "truth.json")["truth"]
            for rid in ("at-pr.1", "none.1"):
                record = read_json(run_dir / "runs" / f"{rid}.json")
                matches = read_json(run_dir / "matches" / f"{rid}.json")
                matches["input_digest"] = judge.digest(judge.match_payload(truth, record["findings"]))
                write_json(run_dir / "matches" / f"{rid}.json", matches)
            snapshot = read_json(run_dir / "snapshots" / "at-pr.json")
            unmatched = read_json(run_dir / "runs" / "at-pr.1.json")["findings"]
            attribution = read_json(run_dir / "attribution" / "at-pr.json")
            attribution["input_digest"] = stages.attribution_digest(
                stages.snapshot_skills(snapshot), judge.attribution_items(truth, unmatched)
            )
            write_json(run_dir / "attribution" / "at-pr.json", attribution)
            self.assertEqual(stages.stale_results(run_dir, config), [])
            # a new ground truth makes every judge result stale again
            changed = read_json(run_dir / "truth.json")
            changed["truth"][0]["rule"] = "Name it better."
            write_json(run_dir / "truth.json", changed)
            self.assertEqual(len(stages.stale_results(run_dir, config)), 3)

    def test_estimate_ceiling(self):
        config = {"repo": "o/r", "number": 1, "round": 1, "arms": ["at-pr", "none"], "runs": 2, "reviewer": "plain", "model": None, "max_usd_review": 3.0, "max_usd_judge": 1.0, "judge_model": "opus", "calibration_model": "haiku"}
        plan = stages.estimate_plan(config, candidates=45)
        self.assertEqual(plan["reviews"], 4)
        # classify: 45 / 20 -> 3 batches; attribute: (45 + 2 runs x 10 findings) / 25 -> 3 batches for the one skill arm
        self.assertEqual(plan["judge_calls"], {"classify": 3, "match": 4, "attribute": 3, "total": 10})
        self.assertEqual(plan["ceiling_usd"], 2 * (4 * 3.0 + 0.5 + 10 * 1.0))  # every session capped and retried once
        text = stages.describe_plan(config, plan, {"auth": {"api_key_in_environment": True}})
        self.assertIn("billed per token", text)


if __name__ == "__main__":
    unittest.main()
