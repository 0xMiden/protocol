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

Both prompts also require the response to open with a bare `BLOCK:` /
`CLEAN:` / `APPROVE:` token. `_evaluate_reviewer` treats its absence as
malformed output (blocks), and blocks on a leading `BLOCK:` even when the
section-based count comes back 0 - a backstop for a section that opens with
`None.` but is mistakenly followed by real findings; see
`_count_blocking_findings`.
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
# A line that is just "None"/"N/A" - bare, bolded, or with a period-
# terminated explanation on the same line ("None. I tried X, Y, Z..."). No
# ":" terminator (too easy for a real finding like "None: no authz check"
# to slip through) - a real finding like "None of the callers validate X"
# never matches either way, since there's no "." or end-of-line right after
# "None".
_ABSENCE = re.compile(r"^\s*(?:[-*]\s+)?\**(none|n/a)\**(?:\.\**(?:\s.*)?|\s*)$", re.IGNORECASE)
# The mandatory leading token both prompts require, tolerating markdown bold
# around it (the same habit `_ABSENCE` above tolerates) so the same model
# bolding its own verdict doesn't turn a clean review into a spurious block.
# Matched as its own line anywhere in the text before the review body starts
# (see `_leading_verdict`) rather than strictly at byte 0, since a model
# occasionally prefaces it with a sentence or two before the formatted
# token line.
_LEADING_VERDICT = re.compile(r"^\s*\**(BLOCK|CLEAN|APPROVE)\**\s*:", re.IGNORECASE | re.MULTILINE)


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
    this reviewer blocks: a crash, malformed output (no `### ` sections, or
    no leading verdict token), a blocking finding, or a self-reported BLOCK
    verdict despite a 0 count."""
    lines = [f"=== {result.name} ==="]

    if result.returncode != 0:
        lines.append(f"{result.name}: agent exited with status {result.returncode}; treating as block.")
        if result.stdout:
            lines.append(result.stdout)
        if result.stderr:
            lines.append(f"--- agent stderr ---\n{result.stderr}")
        return False, "\n".join(lines)

    if not _looks_like_review(result.stdout):
        lines.append(f"{result.name}: empty output or no `### ` sections found; treating as block.")
        if result.stdout:
            lines.append(result.stdout)
        return False, "\n".join(lines)

    leading = _leading_verdict(result.stdout)
    if not leading:
        lines.append(
            f"{result.name}: response did not open with a `BLOCK:`/`CLEAN:`/`APPROVE:` token "
            "as its prompt requires; treating as block."
        )
        lines.append(result.stdout)
        return False, "\n".join(lines)

    lines.append(result.stdout)
    count = _count_blocking_findings(result.stdout)
    if count > 0:
        lines.append(f"{result.name}: {count} blocking finding(s) (Critical/Important/Warning).")
        return False, "\n".join(lines)

    if leading.group(1).upper() == "BLOCK":
        lines.append(
            f"{result.name}: 0 structured findings counted, but the agent's own leading "
            "verdict says BLOCK; treating as block."
        )
        return False, "\n".join(lines)

    lines.append(f"{result.name}: no blocking findings (nits/notes do not block).")
    return True, "\n".join(lines)


def _looks_like_review(text: str) -> bool:
    return bool(text.strip()) and any(line.startswith("### ") for line in text.splitlines())


def _leading_verdict(text: str) -> re.Match[str] | None:
    """Find the mandatory leading token, searching only the text before the
    first `##`/`### ` heading - i.e. the preamble the prompts require it to
    open with. A plain `.match()` at byte 0 is too strict: a model
    occasionally writes a sentence or two before the token line even though
    told to lead with it. Restricting the search to the preamble (rather
    than the whole document) keeps a quoted example of the token deeper in
    the review body from being mistaken for the real one.
    """
    preamble = text.split("\n##", 1)[0]
    return _LEADING_VERDICT.search(preamble)


def _count_blocking_findings(text: str) -> int:
    """Walk the reviewer's markdown line by line. Count bullets that appear
    under `### Critical Issues / ### Important Issues / ### Warnings`
    headings, treating any other `### ` heading or `##` heading as the end
    of the current section. A section is cleared - and the rest of its
    lines ignored - as soon as its first non-blank content line matches
    `_ABSENCE`. A stray absence marker elsewhere in the section only skips
    itself, so a real finding followed by a later `- None.` isn't
    double-counted.
    """
    count = 0
    in_block = False
    section_cleared = False
    saw_content = False
    for line in text.splitlines():
        if _SECOND_LEVEL.match(line):
            in_block = False
            continue
        if _ANY_THIRD_LEVEL.match(line):
            in_block = bool(_BLOCKING_HEADINGS.match(line))
            section_cleared = False
            saw_content = False
            continue
        if not in_block or section_cleared:
            continue
        if not line.strip():
            continue
        if _ABSENCE.match(line):
            if not saw_content:
                section_cleared = True
            continue
        saw_content = True
        if _BULLET.match(line):
            count += 1
    return count
