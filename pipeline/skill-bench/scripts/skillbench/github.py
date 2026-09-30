"""Fetch a pull request's human review rounds from GitHub.

A *review round* is a commit that someone other than the PR author reviewed.
Rounds are numbered by the time of their first review. The benchmark replays
one round (the first by default): the review threads started on that commit,
plus the non-empty bodies of the reviews submitted on it, become the
candidate ground truth.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

from .util import BenchError, run

SCHEMA_VERSION = 1

_REF = re.compile(r"^(?P<owner>[\w.-]+)/(?P<name>[\w.-]+)#(?P<number>\d+)$")
_URL = re.compile(r"^https?://github\.com/(?P<owner>[\w.-]+)/(?P<name>[\w.-]+)/pull/(?P<number>\d+)")

_PR_QUERY = """
query($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      number title url state createdAt
      author { login __typename }
      baseRefName baseRefOid headRefOid
    }
  }
}
"""

_PAGED_QUERY = """
query($owner: String!, $name: String!, $number: Int!, $cursor: String) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      %(connection)s(first: %(page)d, after: $cursor) {
        pageInfo { hasNextPage endCursor }
        nodes { %(fields)s }
      }
    }
  }
}
"""

_CONNECTIONS = {
    "reviews": (100, "id url state submittedAt body author { login __typename } commit { oid }"),
    "reviewThreads": (
        50,
        "id path line originalLine isResolved isOutdated "
        "comments(first: 100) { pageInfo { hasNextPage } "
        "nodes { id url body createdAt diffHunk author { login __typename } originalCommit { oid } } }",
    ),
    "files": (100, "path additions deletions"),
}

# gh api graphql <query> <variables> -> parsed JSON response
GraphQL = Callable[[str, dict[str, Any]], dict[str, Any]]


def parse_pr_ref(ref: str, default_repo: str | None = None) -> tuple[str, str, int]:
    """Parse `owner/repo#N`, a GitHub PR URL, or a bare number (needs `default_repo`)."""
    ref = ref.strip()
    for pattern in (_REF, _URL):
        match = pattern.match(ref)
        if match:
            return match["owner"], match["name"], int(match["number"])
    if ref.isdigit():
        if not default_repo or "/" not in default_repo:
            raise BenchError(f"'{ref}' is a bare PR number; pass --repo owner/name as well")
        owner, name = default_repo.split("/", 1)
        return owner, name, int(ref)
    raise BenchError(f"not a PR reference: '{ref}' (expected owner/repo#N, a PR URL or a number)")


def gh_graphql(query: str, variables: dict[str, Any]) -> dict[str, Any]:
    """Run a GraphQL query through the authenticated `gh` CLI."""
    cmd = ["gh", "api", "graphql", "-f", f"query={query}"]
    for key, value in variables.items():
        if value is None:
            cmd += ["-F", f"{key}=null"]
        elif isinstance(value, int):
            cmd += ["-F", f"{key}={value}"]
        else:
            cmd += ["-f", f"{key}={value}"]
    data = json.loads(run(cmd, timeout=120).stdout)
    if data.get("errors"):
        raise BenchError(f"GitHub GraphQL error: {data['errors'][0].get('message')}")
    return data


def default_repo_for_cwd() -> str | None:
    """The repository of the current checkout, or its parent when it is a fork."""
    proc = run(["gh", "repo", "view", "--json", "nameWithOwner,parent"], timeout=60, check=False)
    if proc.returncode != 0:
        return None
    info = json.loads(proc.stdout)
    parent = info.get("parent")
    if parent:
        owner = (parent.get("owner") or {}).get("login")
        if owner and parent.get("name"):
            return f"{owner}/{parent['name']}"
    return info.get("nameWithOwner")


def merge_base(owner: str, name: str, base: str, head: str) -> str:
    """The commit the reviewed change branched from, via GitHub's compare API."""
    proc = run(
        ["gh", "api", f"repos/{owner}/{name}/compare/{base}...{head}", "--jq", ".merge_base_commit.sha"],
        timeout=120,
    )
    sha = proc.stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise BenchError(f"could not resolve the merge base of {head[:12]} and {base[:12]}")
    return sha


def fetch_pull_request(owner: str, name: str, number: int, graphql: GraphQL = gh_graphql) -> dict[str, Any]:
    """Fetch the PR's metadata and all pages of its reviews, threads and files."""
    variables = {"owner": owner, "name": name, "number": number}
    meta = _pull_request(graphql(_PR_QUERY, variables), owner, name, number)
    pr = dict(meta)
    for connection, (page, fields) in _CONNECTIONS.items():
        query = _PAGED_QUERY % {"connection": connection, "page": page, "fields": fields}
        nodes: list[dict[str, Any]] = []
        cursor = None
        while True:
            data = _pull_request(graphql(query, {**variables, "cursor": cursor}), owner, name, number)
            conn = data[connection]
            nodes.extend(conn["nodes"])
            if not conn["pageInfo"]["hasNextPage"]:
                break
            cursor = conn["pageInfo"]["endCursor"]
        pr[connection] = nodes
    return pr


def _pull_request(data: dict[str, Any], owner: str, name: str, number: int) -> dict[str, Any]:
    pr = ((data.get("data") or {}).get("repository") or {}).get("pullRequest")
    if not pr:
        raise BenchError(f"pull request {owner}/{name}#{number} not found or not accessible")
    return pr


def _review_rounds(
    reviews: list[dict[str, Any]],
    threads: list[dict[str, Any]],
    human: Callable[[dict[str, Any] | None], bool],
) -> list[dict[str, Any]]:
    """Group human reviews by reviewed commit, ordered by each commit's first review."""
    by_sha: dict[str, dict[str, Any]] = {}
    for review in sorted(reviews, key=lambda r: (r["submittedAt"], r["id"])):
        sha = review["commit"]["oid"]
        entry = by_sha.setdefault(sha, {"sha": sha, "first_submitted_at": review["submittedAt"], "reviewers": set(), "threads": 0})
        entry["reviewers"].add(review["author"]["login"])
    for thread in threads:
        comments = thread["comments"]["nodes"]
        if comments and human(comments[0].get("author")):
            sha = (comments[0].get("originalCommit") or {}).get("oid")
            if sha in by_sha:
                by_sha[sha]["threads"] += 1
    rounds = sorted(by_sha.values(), key=lambda e: (e["first_submitted_at"], e["sha"]))
    return [
        {"round": i, "sha": e["sha"], "first_submitted_at": e["first_submitted_at"], "reviewers": sorted(e["reviewers"]), "threads": e["threads"]}
        for i, e in enumerate(rounds, start=1)
    ]


def is_bot(author: dict[str, Any] | None) -> bool:
    if not author:
        return True  # deleted ("ghost") accounts carry no reviewer signal
    return author.get("__typename") == "Bot" or author.get("login", "").endswith("[bot]")


def select_review_round(pr: dict[str, Any], skills_dir: str = ".claude/skills", round_number: int = 1) -> dict[str, Any]:
    """Pick one human review round (1-based) and build its candidate ground truth."""
    pr_author = (pr.get("author") or {}).get("login")

    def human(author: dict[str, Any] | None) -> bool:
        return not is_bot(author) and author.get("login") != pr_author

    reviews = [r for r in pr["reviews"] if human(r.get("author")) and r.get("commit") and r.get("submittedAt")]
    if not reviews:
        raise BenchError("the pull request has no review by anyone other than its author")
    rounds = _review_rounds(reviews, pr["reviewThreads"], human)
    if not 1 <= round_number <= len(rounds):
        raise BenchError(f"round {round_number} does not exist; the pull request has {len(rounds)} review round(s)")
    chosen = rounds[round_number - 1]
    review_sha = chosen["sha"]
    round_of = {r["sha"]: r["round"] for r in rounds}

    candidates: list[dict[str, Any]] = []
    excluded: list[dict[str, str]] = []
    warnings: list[str] = []
    for thread in pr["reviewThreads"]:
        comments = thread["comments"]["nodes"]
        if not comments:
            continue
        root = comments[0]
        if thread["comments"]["pageInfo"]["hasNextPage"]:
            warnings.append(f"thread {thread['id']} has more than 100 comments; later ones are omitted")
        if is_bot(root.get("author")):
            excluded.append({"thread_id": thread["id"], "url": root.get("url", ""), "reason": "started by a bot"})
            continue
        if root["author"]["login"] == pr_author:
            excluded.append({"thread_id": thread["id"], "url": root.get("url", ""), "reason": "started by the PR author"})
            continue
        commit = (root.get("originalCommit") or {}).get("oid")
        if commit != review_sha:
            other = round_of.get(commit)
            reason = "another commit" if other is None else ("earlier" if other < round_number else "later") + " review round"
            excluded.append({"thread_id": thread["id"], "url": root.get("url", ""), "reason": reason})
            continue
        candidates.append(
            {
                "source": "thread",
                "thread_id": thread["id"],
                "url": root.get("url", ""),
                "path": thread.get("path"),
                "line": thread.get("line") or thread.get("originalLine"),
                "reviewer": root["author"]["login"],
                "created_at": root.get("createdAt", ""),
                "diff_hunk": root.get("diffHunk") or "",
                "is_resolved": bool(thread.get("isResolved")),
                "comments": [
                    {"author": (c.get("author") or {}).get("login", "ghost"), "body": c.get("body", "")}
                    for c in comments
                ],
            }
        )
    for review in reviews:
        if review["commit"]["oid"] != review_sha or not (review.get("body") or "").strip():
            continue
        candidates.append(
            {
                "source": "review-body",
                "thread_id": review["id"],
                "url": review.get("url", ""),
                "path": None,
                "line": None,
                "reviewer": review["author"]["login"],
                "created_at": review["submittedAt"],
                "diff_hunk": "",
                "is_resolved": False,
                "comments": [{"author": review["author"]["login"], "body": review["body"]}],
            }
        )
    candidates.sort(key=lambda c: (c["created_at"], c["thread_id"]))
    for index, candidate in enumerate(candidates, start=1):
        candidate["id"] = f"t{index}"

    files = sorted(f["path"] for f in pr["files"])
    prefix = skills_dir.rstrip("/") + "/"
    return {
        "schema_version": SCHEMA_VERSION,
        "number": pr["number"],
        "title": pr["title"],
        "url": pr["url"],
        "state": pr["state"],
        "author": pr_author,
        "base_ref": pr["baseRefName"],
        "base_ref_oid": pr["baseRefOid"],
        "head_oid": pr["headRefOid"],
        "review_sha": review_sha,
        "review_submitted_at": chosen["first_submitted_at"],
        "round": round_number,
        "rounds": rounds,
        "reviewers": sorted({c["reviewer"] for c in candidates}),
        "files": files,
        "modified_claude_files": [f for f in files if f.startswith(".claude/")],
        "modified_skill_files": [f for f in files if f.startswith(prefix)],
        "candidates": candidates,
        "excluded_threads": excluded,
        "warnings": warnings,
    }
