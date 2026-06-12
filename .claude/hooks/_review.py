"""Shared reviewer orchestration for the review hooks.

`run_review(diff_range)` spawns the `code-reviewer` + `security-reviewer`
agents in parallel over a given git diff range and decides whether the
change is blocked. Callers (`post_commit_review`, `pre_pr_review`) supply
the range and emit the block in their own hook protocol — this module only
runs the reviewers, renders their output, and counts blocking findings.

Severity policy (single source of truth, not the agent prompts):
  BLOCK on  ### Critical Issues | ### Critical Findings
            ### Important Issues | ### Warnings
  IGNORE    ### Nits | ### Notes | ### What's Done Well | ### Summary
"""

from __future__ import annotations

import concurrent.futures
import re
import subprocess
from dataclasses import dataclass

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


def run_review(
    diff_range: str,
    cwd: str | None = None,
    intent: str | None = None,
) -> tuple[bool, str]:
    """Run both reviewers in parallel over `diff_range`.

    `intent`, when given, is the session's user prompts — passed so the
    reviewers respect what the user explicitly asked for instead of
    second-guessing deliberate choices.

    Returns `(blocked, rendered)` where `blocked` is True if either reviewer
    reported a Critical/Important/Warning finding, crashed, or produced
    malformed output, and `rendered` is the human-readable report the caller
    should surface (per-reviewer output plus a one-line verdict each).
    """
    prompt = (
        f"Review the changes in diff range `{diff_range}`. "
        f"Run `git diff {diff_range}` to see exactly what is under review."
    )
    if intent:
        prompt += (
            "\n\n## User intent (this session, most recent first)\n"
            f"{intent}\n\n"
            "Respect this intent: treat deliberate, explicitly-requested choices as "
            "intended, not mistakes, and don't recommend reversing them. Intent never "
            "excuses a real defect - apply your severity rules to any genuine risk a "
            "requested approach introduces."
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures = {
            pool.submit(_run_reviewer, "code-reviewer", prompt, cwd): "CODE REVIEWER",
            pool.submit(_run_reviewer, "security-reviewer", prompt, cwd): "SECURITY REVIEWER",
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
    chunks: list[str] = []
    for result in results:
        cleared, rendered = _evaluate_reviewer(result)
        chunks.append(rendered)
        if not cleared:
            blocked = True
    return blocked, "\n".join(chunks)


def _run_reviewer(agent: str, prompt: str, cwd: str | None) -> tuple[int, str, str]:
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
        cwd=cwd,
    )
    return result.returncode, result.stdout, result.stderr


def _evaluate_reviewer(result: ReviewerResult) -> tuple[bool, str]:
    """Return `(cleared, rendered)` for one reviewer. `cleared` is False if
    this reviewer blocks (crash, malformed output, or a blocking finding)."""
    lines = [f"=== {result.name} ==="]

    if result.returncode != 0:
        lines.append(f"{result.name}: agent exited with status {result.returncode}; treating as block.")
        if result.stdout:
            lines.append(result.stdout)
        if result.stderr:
            lines.append(f"--- agent stderr ---\n{result.stderr}")
        return False, "\n".join(lines)

    if not _looks_like_review(result.stdout):
        lines.append(f"{result.name}: empty or malformed output; treating as block.")
        if result.stdout:
            lines.append(result.stdout)
        return False, "\n".join(lines)

    lines.append(result.stdout)
    count = _count_blocking_findings(result.stdout)
    if count > 0:
        lines.append(f"{result.name}: {count} blocking finding(s) (Critical/Important/Warning).")
        return False, "\n".join(lines)
    lines.append(f"{result.name}: no blocking findings (nits/notes do not block).")
    return True, "\n".join(lines)


def _looks_like_review(text: str) -> bool:
    return bool(text.strip()) and any(line.startswith("### ") for line in text.splitlines())


def _count_blocking_findings(text: str) -> int:
    """Walk the reviewer's markdown line by line. Count bullets that appear
    under `### Critical Issues / ### Important Issues / ### Warnings`
    headings, treating any other `### ` heading or `##` heading as the end of
    the current section. Bullets matching `- None.` / `- N/A` are explicitly
    skipped — those are absence markers, not findings.
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
