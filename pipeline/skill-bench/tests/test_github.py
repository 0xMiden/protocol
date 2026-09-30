import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from skillbench import github  # noqa: E402
from skillbench.util import BenchError  # noqa: E402


def user(login):
    return {"login": login, "__typename": "User"}


def thread(tid, author, commit, created, replies=(), path="src/lib.rs", resolved=False, more=False):
    root = {
        "id": f"{tid}-c0",
        "url": f"https://example.test/{tid}",
        "body": f"comment on {tid}",
        "createdAt": created,
        "diffHunk": "@@ -1 +1 @@\n-a\n+b",
        "author": author,
        "originalCommit": {"oid": commit},
    }
    comments = [root] + [
        {"id": f"{tid}-c{i + 1}", "url": "", "body": body, "createdAt": created, "diffHunk": "", "author": user(who), "originalCommit": {"oid": commit}}
        for i, (who, body) in enumerate(replies)
    ]
    return {
        "id": tid,
        "path": path,
        "line": 10,
        "originalLine": 9,
        "isResolved": resolved,
        "isOutdated": False,
        "comments": {"pageInfo": {"hasNextPage": more}, "nodes": comments},
    }


def pr_fixture():
    return {
        "number": 7,
        "title": "Add a thing",
        "url": "https://example.test/pr/7",
        "state": "MERGED",
        "createdAt": "2026-08-01T00:00:00Z",
        "author": user("alice"),
        "baseRefName": "main",
        "baseRefOid": "b" * 40,
        "headRefOid": "h" * 40,
        "reviews": [
            {"id": "r-self", "url": "", "state": "COMMENTED", "submittedAt": "2026-08-01T01:00:00Z", "body": "self review", "author": user("alice"), "commit": {"oid": "c0"}},
            {"id": "r-bot", "url": "", "state": "COMMENTED", "submittedAt": "2026-08-01T01:30:00Z", "body": "lint", "author": {"login": "ci[bot]", "__typename": "Bot"}, "commit": {"oid": "c0"}},
            {"id": "r2", "url": "", "state": "APPROVED", "submittedAt": "2026-08-03T00:00:00Z", "body": "", "author": user("carol"), "commit": {"oid": "c2"}},
            {"id": "r1", "url": "https://example.test/r1", "state": "COMMENTED", "submittedAt": "2026-08-02T00:00:00Z", "body": "Overall: please add tests.", "author": user("bob"), "commit": {"oid": "c1"}},
        ],
        "reviewThreads": [
            thread("th-b", user("bob"), "c1", "2026-08-02T00:00:02Z", replies=[("alice", "fixed")]),
            thread("th-a", user("bob"), "c1", "2026-08-02T00:00:01Z", resolved=True),
            thread("th-self", user("alice"), "c1", "2026-08-02T00:00:03Z"),
            thread("th-bot", {"login": "ci[bot]", "__typename": "Bot"}, "c1", "2026-08-02T00:00:04Z"),
            thread("th-later", user("carol"), "c2", "2026-08-03T00:00:01Z"),
            thread("th-long", user("bob"), "c1", "2026-08-02T00:00:05Z", more=True),
        ],
        "files": [
            {"path": "src/lib.rs", "additions": 3, "deletions": 1},
            {"path": ".claude/skills/rule/SKILL.md", "additions": 1, "deletions": 0},
            {"path": ".claude/settings.json", "additions": 1, "deletions": 0},
        ],
    }


class ParsePrRefTest(unittest.TestCase):
    def test_short_form(self):
        self.assertEqual(github.parse_pr_ref("0xMiden/protocol#3713"), ("0xMiden", "protocol", 3713))

    def test_url(self):
        self.assertEqual(
            github.parse_pr_ref("https://github.com/owner/repo.name/pull/12/files"), ("owner", "repo.name", 12)
        )

    def test_bare_number_uses_default_repo(self):
        self.assertEqual(github.parse_pr_ref("5", "o/r"), ("o", "r", 5))

    def test_bare_number_without_default_repo_fails(self):
        with self.assertRaises(BenchError):
            github.parse_pr_ref("5")

    def test_garbage_fails(self):
        with self.assertRaises(BenchError):
            github.parse_pr_ref("not a pr")


class SelectReviewRoundTest(unittest.TestCase):
    def setUp(self):
        self.pr = github.select_review_round(pr_fixture())

    def test_first_human_review_defines_the_round(self):
        self.assertEqual(self.pr["review_sha"], "c1")
        self.assertEqual(self.pr["review_submitted_at"], "2026-08-02T00:00:00Z")

    def test_candidates_are_first_round_human_threads_and_review_bodies_in_time_order(self):
        sources = [(c["id"], c["source"], c["thread_id"]) for c in self.pr["candidates"]]
        self.assertEqual(
            sources,
            [
                ("t1", "review-body", "r1"),
                ("t2", "thread", "th-a"),
                ("t3", "thread", "th-b"),
                ("t4", "thread", "th-long"),
            ],
        )

    def test_replies_are_kept_with_the_thread(self):
        th_b = next(c for c in self.pr["candidates"] if c["thread_id"] == "th-b")
        self.assertEqual([c["author"] for c in th_b["comments"]], ["bob", "alice"])

    def test_exclusions_are_recorded_with_reasons(self):
        reasons = {e["thread_id"]: e["reason"] for e in self.pr["excluded_threads"]}
        self.assertEqual(
            reasons,
            {"th-self": "started by the PR author", "th-bot": "started by a bot", "th-later": "later review round"},
        )

    def test_truncated_threads_are_warned_about(self):
        self.assertEqual(len(self.pr["warnings"]), 1)
        self.assertIn("th-long", self.pr["warnings"][0])

    def test_modified_agent_config_files_are_listed(self):
        self.assertEqual(self.pr["modified_skill_files"], [".claude/skills/rule/SKILL.md"])
        self.assertEqual(self.pr["modified_claude_files"], [".claude/settings.json", ".claude/skills/rule/SKILL.md"])

    def test_rounds_are_listed_in_order_of_first_review(self):
        self.assertEqual(
            [(r["round"], r["sha"], r["reviewers"], r["threads"]) for r in self.pr["rounds"]],
            [(1, "c1", ["bob"], 3), (2, "c2", ["carol"], 1)],
        )
        self.assertEqual(self.pr["round"], 1)

    def test_a_later_round_can_be_selected(self):
        pr = github.select_review_round(pr_fixture(), round_number=2)
        self.assertEqual(pr["review_sha"], "c2")
        self.assertEqual([c["thread_id"] for c in pr["candidates"]], ["th-later"])
        self.assertIn("earlier review round", {e["reason"] for e in pr["excluded_threads"]})
        self.assertNotIn("later review round", {e["reason"] for e in pr["excluded_threads"]})

    def test_a_missing_round_is_an_error(self):
        with self.assertRaises(BenchError):
            github.select_review_round(pr_fixture(), round_number=3)

    def test_no_human_review_is_an_error(self):
        fixture = pr_fixture()
        fixture["reviews"] = [r for r in fixture["reviews"] if r["author"]["login"] in ("alice", "ci[bot]")]
        with self.assertRaises(BenchError):
            github.select_review_round(fixture)


class FetchPaginationTest(unittest.TestCase):
    def test_all_pages_of_each_connection_are_collected(self):
        full = pr_fixture()
        calls = []

        def fake_graphql(query, variables):
            calls.append(variables.get("cursor"))
            meta = {k: v for k, v in full.items() if k not in github._CONNECTIONS}
            if "pageInfo" not in query:
                return {"data": {"repository": {"pullRequest": meta}}}
            connection = next(name for name in github._CONNECTIONS if f"{name}(first:" in query)
            nodes = full[connection]
            if variables.get("cursor") is None:
                page, info = nodes[:1], {"hasNextPage": len(nodes) > 1, "endCursor": "p2"}
            else:
                page, info = nodes[1:], {"hasNextPage": False, "endCursor": None}
            return {"data": {"repository": {"pullRequest": {connection: {"pageInfo": info, "nodes": page}}}}}

        pr = github.fetch_pull_request("o", "r", 7, graphql=fake_graphql)
        for connection in github._CONNECTIONS:
            self.assertEqual(len(pr[connection]), len(full[connection]))
        self.assertIn("p2", calls)

    def test_missing_pull_request_is_an_error(self):
        with self.assertRaises(BenchError):
            github.fetch_pull_request("o", "r", 7, graphql=lambda q, v: {"data": {"repository": {"pullRequest": None}}})


if __name__ == "__main__":
    unittest.main()
