#!/usr/bin/env python3
"""Pre-push hook: spawns code-reviewer + security-reviewer in parallel.
Blocks the push on (a) any Critical/Important/Warning finding from
either reviewer, or (b) reviewer crash or malformed output. Nits and
Notes are surfaced to the user but never block.

Severity policy (single source of truth, not the agent prompts):
  BLOCK on  ### Critical Issues | ### Critical Findings
            ### Important Issues | ### Warnings
  IGNORE    ### Nits | ### Notes | ### What's Done Well | ### Summary
"""

from __future__ import annotations

import concurrent.futures
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _classify import matches  # noqa: E402

TARGET = ("git", ["push"])

_ALLOWED_TOOLS = "Bash(git:*) Read Grep Glob"

# Recognized blocking-section headings (case-sensitive).
_BLOCKING_HEADINGS = re.compile(r"^### (Critical|Important|Warnings)(\s|$)")
# Any `### ` heading ends a previous section.
_ANY_THIRD_LEVEL = re.compile(r"^### ")
# Any second-level heading also ends a section.
_SECOND_LEVEL = re.compile(r"^##[^#]|^## ")
# A bullet line `-` or `*` followed by content.
_BULLET = re.compile(r"^\s*[-*]\s+\S")
# Absence markers we explicitly do NOT count as findings.
_ABSENCE = re.compile(r"^\s*[-*]\s+(None|N/A|n/a)\.?\s*$")


@dataclass
class ReviewerResult:
    name: str
    returncode: int
    stdout: str
    stderr: str


def main() -> None:
    try:
        payload = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, ValueError):
        sys.exit(0)
    command = payload.get("tool_input", {}).get("command", "") or ""
    if not matches(command, *TARGET):
        sys.exit(0)

    repo_root = _repo_root()
    if repo_root is None:
        sys.stderr.write("Pre-push: not inside a git worktree, skipping.\n")
        sys.exit(0)

    base = _diff_base()
    merge_base = _merge_base(base)
    if merge_base is None:
        sys.stderr.write(f"Pre-push: cannot resolve merge-base against {base}; allowing.\n")
        sys.exit(0)
    if _no_changes_vs(merge_base):
        sys.stderr.write(f"Pre-push: no changes vs {base}; skipping.\n")
        sys.exit(0)

    sys.stderr.write("Pre-push: spawning code-reviewer + security-reviewer...\n")
    prompt = f"Review the changes about to be pushed (diff base: {merge_base})."

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures = {
            pool.submit(_run_reviewer, "code-reviewer", prompt): "CODE REVIEWER",
            pool.submit(_run_reviewer, "security-reviewer", prompt): "SECURITY REVIEWER",
        }
        results: list[ReviewerResult] = []
        for fut, name in futures.items():
            try:
                rc, stdout, stderr = fut.result()
            except Exception as exc:  # noqa: BLE001
                results.append(ReviewerResult(name, returncode=1, stdout="", stderr=str(exc)))
                continue
            results.append(ReviewerResult(name, returncode=rc, stdout=stdout, stderr=stderr))

    blocked = False
    for result in results:
        if not _evaluate_reviewer(result):
            blocked = True

    if blocked:
        sys.stderr.write("\nPre-push: push blocked. Address Critical/Important/Warning findings above and retry.\n")
        sys.exit(2)
    sys.stderr.write("\nPre-push: all checks passed.\n")
    sys.exit(0)


def _repo_root() -> Path | None:
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    return Path(result.stdout.strip())


def _diff_base() -> str:
    """Prefer the configured upstream; fall back to origin/next."""
    result = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0 and result.stdout.strip():
        return result.stdout.strip()
    return "origin/next"


def _merge_base(base: str) -> str | None:
    result = subprocess.run(
        ["git", "merge-base", "HEAD", base],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0 and result.stdout.strip():
        return result.stdout.strip()
    # Fall back to HEAD~1.
    fallback = subprocess.run(
        ["git", "rev-parse", "HEAD~1"],
        capture_output=True,
        text=True,
    )
    if fallback.returncode == 0 and fallback.stdout.strip():
        return fallback.stdout.strip()
    return None


def _no_changes_vs(merge_base: str) -> bool:
    result = subprocess.run(
        ["git", "diff", "--quiet", merge_base, "HEAD"],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def _run_reviewer(agent: str, prompt: str) -> tuple[int, str, str]:
    result = subprocess.run(
        [
            "claude",
            "--agent",
            agent,
            "--allowedTools",
            _ALLOWED_TOOLS,
            "-p",
            prompt,
        ],
        capture_output=True,
        text=True,
    )
    return result.returncode, result.stdout, result.stderr


def _evaluate_reviewer(result: ReviewerResult) -> bool:
    """Return True if this reviewer cleared the push, False if it blocks."""
    sys.stderr.write(f"\n=== {result.name} ===\n")

    if result.returncode != 0:
        sys.stderr.write(f"{result.name}: agent exited with status {result.returncode}; treating as block.\n")
        if result.stdout:
            sys.stderr.write(result.stdout)
        if result.stderr:
            sys.stderr.write(f"--- agent stderr ---\n{result.stderr}\n")
        return False

    if not _looks_like_review(result.stdout):
        sys.stderr.write(f"{result.name}: empty or malformed output; treating as block.\n")
        if result.stdout:
            sys.stderr.write(result.stdout)
        return False

    sys.stderr.write(result.stdout)
    sys.stderr.write("\n")
    count = _count_blocking_findings(result.stdout)
    if count > 0:
        sys.stderr.write(f"{result.name}: {count} blocking finding(s) (Critical/Important/Warning).\n")
        return False
    sys.stderr.write(f"{result.name}: no blocking findings (nits/notes do not block).\n")
    return True


def _looks_like_review(text: str) -> bool:
    return bool(text.strip()) and any(line.startswith("### ") for line in text.splitlines())


def _count_blocking_findings(text: str) -> int:
    """Walk the reviewer's markdown line by line. Count bullets that
    appear under `### Critical Issues / ### Important Issues / ### Warnings`
    headings, treating any other `### ` heading or `##` heading as the end
    of the current section. Bullets matching `- None.` / `- N/A` are
    explicitly skipped — those are absence markers, not findings.
    """
    count = 0
    in_block = False
    for line in text.splitlines():
        if _SECOND_LEVEL.match(line):
            in_block = False
            continue
        if _ANY_THIRD_LEVEL.match(line):
            in_block = bool(_BLOCKING_HEADINGS.match(line))
            continue
        if not in_block:
            continue
        if _ABSENCE.match(line):
            continue
        if _BULLET.match(line):
            count += 1
    return count


if __name__ == "__main__":
    main()
