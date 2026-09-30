"""Run headless Claude Code review replays.

Every replay is a separate `claude -p` process started in a sealed workspace
(see `workspace.py`). The flags pin down everything the model can see:

* `--setting-sources project` and `syncClaudeAiSkills: false` keep user-level
  and account-synced skills out, so only the workspace's skills are listed;
* `--tools` offers only Read, Grep, Glob, Bash and Skill, and
  `--allowedTools` pre-approves only read-only git commands and Skill.
  Read, Grep and Glob are deliberately *not* pre-approved: Claude Code
  allows them inside the working directory anyway, and leaving them
  unapproved makes it deny reads outside the workspace (a pre-approved
  Read would open any path on the machine, including a checkout that
  contains the pull request's later commits);
* `--strict-mcp-config` starts no MCP servers, and `--permission-mode
  default` ignores any other mode (the workspace settings keep only `deny`
  permission rules, see `workspace.py`);
* `--session-id` fixes where the transcript is written, for telemetry.

Separate processes are used, not subagents, because a subagent inherits the
parent session's skill listing and working directory, which is exactly what
the replay has to control.
"""

from __future__ import annotations

import json
import os
import shutil
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import roles, telemetry
from .util import BenchError, run
from .workspace import Workspace, hermetic_git_env

REVIEW_PROMPT = "Review the change between HEAD~1 and HEAD and report your findings."
CALIBRATION_PROMPT = "Return an empty findings list. Do not use any tools."
REVIEW_TOOLS = "Read,Grep,Glob,Bash,Skill"
# Read, Grep and Glob must stay out of this list; see the module docstring.
ALLOWED_TOOLS = [
    "Skill",
    "Bash(git diff:*)",
    "Bash(git log:*)",
    "Bash(git show:*)",
    "Bash(git status:*)",
]
ISOLATION_SETTINGS = json.dumps({"syncClaudeAiSkills": False})
MODES = ("plain", "repo-agent", "repo-agent+skills")


@dataclass
class Reviewer:
    mode: str
    agent: str
    agents_json: str | None  # None: the agent is defined by the workspace itself
    has_skill_tool: bool


def plain_reviewer() -> Reviewer:
    role = roles.load_role("reviewer")
    return Reviewer("plain", role.name, roles.agents_json(role), True)


def reviewer_for(mode: str, ws: Workspace, repo_agent: str = "code-reviewer") -> Reviewer:
    """Resolve a reviewer mode for one workspace.

    * plain             - skill-bench's own generic reviewer role
    * repo-agent        - the project's agent, exactly as the project defines it
    * repo-agent+skills - the project's agent with the Skill tool added
    """
    if mode == "plain":
        return plain_reviewer()
    if mode not in MODES:
        raise BenchError(f"unknown reviewer mode '{mode}' (expected one of {', '.join(MODES)})")
    if repo_agent not in ws.agents:
        raise BenchError(f"the snapshot has no agent named '{repo_agent}' (found: {', '.join(ws.agents) or 'none'})")
    role = roles.load_agent_file(ws.path / ws.agents[repo_agent])
    if mode == "repo-agent":
        return Reviewer(mode, role.name, None, role.tools is None or "Skill" in role.tools)
    name = f"{role.name}-with-skills"
    return Reviewer(mode, name, roles.agents_json(role, name=name, add_tools=("Skill",)), True)


def review_command(reviewer: Reviewer, session_id: str, *, model: str | None, max_usd: float) -> list[str]:
    cmd = [
        "claude",
        "-p",
        "--session-id",
        session_id,
        "--setting-sources",
        "project",
        "--settings",
        ISOLATION_SETTINGS,
        "--strict-mcp-config",
        "--permission-mode",
        "default",
        "--tools",
        REVIEW_TOOLS,
        "--allowedTools",
        *ALLOWED_TOOLS,
        "--json-schema",
        roles.load_schema("review-findings"),
        "--output-format",
        "stream-json",
        "--verbose",
        "--max-budget-usd",
        f"{max_usd:.2f}",
    ]
    if reviewer.agents_json:
        cmd += ["--agents", reviewer.agents_json]
    cmd += ["--agent", reviewer.agent]
    if model:
        cmd += ["--model", model]
    return cmd


def parse_stream(stdout: str) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Return the `system/init` and final `result` messages of a stream-json run."""
    init = result = None
    for line in stdout.splitlines():
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(message, dict):
            continue
        if message.get("type") == "system" and message.get("subtype") == "init" and init is None:
            init = message
        elif message.get("type") == "result":
            result = message
    return init, result


def config_dir() -> Path:
    return Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude")


def find_transcript(session_id: str, attempts: int = 10) -> Path | None:
    for _ in range(attempts):
        found = sorted((config_dir() / "projects").glob(f"*/{session_id}.jsonl"))
        if found:
            return found[0]
        time.sleep(0.5)
    return None


def keep_raw(transcript: Path | None, stdout: str, dest: Path) -> None:
    """Copy a run's stream and transcripts into the run directory's raw area."""
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "stream.jsonl").write_text(stdout, encoding="utf-8")
    if transcript is None:
        return
    shutil.copy2(transcript, dest / "transcript.jsonl")
    subagents = transcript.with_suffix("") / "subagents"
    if subagents.is_dir():
        shutil.copytree(subagents, dest / "transcript" / "subagents", dirs_exist_ok=True)


def run_session(
    cmd_for: Any, cwd: Path, prompt: str, timeout: float, retries: int = 1
) -> tuple[str, str, dict[str, Any] | None, dict[str, Any] | None, str | None]:
    """Run one session, retrying once when it ends without a successful result."""
    last_error = None
    for _ in range(retries + 1):
        session_id = str(uuid.uuid4())
        proc = run(cmd_for(session_id), cwd=cwd, input=prompt, timeout=timeout, check=False)
        init, result = parse_stream(proc.stdout)
        if result is not None and not result.get("is_error") and result.get("subtype") == "success":
            return session_id, proc.stdout, init, result, None
        last_error = _error_text(proc, result)
        if result is not None and "budget" in (last_error or "").lower():
            break  # a budget stop will not succeed on retry
    return session_id, proc.stdout, init, result, last_error


def _error_text(proc: Any, result: dict[str, Any] | None) -> str:
    if result is None:
        return f"no result message (exit code {proc.returncode}): {proc.stderr.strip()[:500]}"
    return f"{result.get('subtype')}: {str(result.get('result') or result.get('errors') or '')[:500]}"


def finalize(record: dict[str, Any], builtins: list[str], snapshot: dict[str, Any]) -> None:
    """Map skill directories to names, run the exposure check and set `valid`."""
    tele = record.get("telemetry")
    exposure = None
    if tele is not None:
        by_dir = {s["dir"]: s["name"] for s in snapshot["skills"]}
        tele["read"] = sorted({by_dir.get(d, d) for d in tele["read"]})
        tele["searched"] = sorted({by_dir.get(d, d) for d in tele["searched"]})
        exposure = telemetry.check_exposure(tele["listed"], builtins, record["expected_listing"], record["has_skill_tool"])
    record["exposure"] = exposure
    problems = [record["error"]] if record.get("error") else []
    problems += (exposure or {}).get("problems", [])
    record["problems"] = problems
    record["valid"] = not problems and exposure is not None


def run_review(
    ws: Workspace,
    reviewer: Reviewer,
    run_id: str,
    raw_dir: Path,
    *,
    model: str | None,
    max_usd: float,
    timeout: float,
    skills_dir: str,
    ignore_files: tuple[str, ...],
) -> dict[str, Any]:
    """Replay the review once and return the run record (without the exposure check)."""
    started = time.monotonic()
    session_id, stdout, init, result, error = run_session(
        lambda sid: review_command(reviewer, sid, model=model, max_usd=max_usd), ws.path, REVIEW_PROMPT, timeout
    )
    transcript = find_transcript(session_id)
    keep_raw(transcript, stdout, raw_dir)
    findings = []
    if result is not None and error is None:
        structured = result.get("structured_output") or {}
        for n, finding in enumerate(structured.get("findings") or [], start=1):
            if isinstance(finding, dict):
                findings.append({"id": f"{run_id}.f{n}", **{k: finding.get(k) for k in ("path", "line", "severity", "title", "explanation")}})
    tele = (
        telemetry.parse_session(transcript, ws.path, skills_dir, ignore_files, (config_dir() / "projects",))
        if transcript is not None
        else None
    )
    denials = (result or {}).get("permission_denials") or []
    return {
        "id": run_id,
        "arm": ws.arm.name,
        "reviewer": reviewer.mode,
        "agent": reviewer.agent,
        "has_skill_tool": reviewer.has_skill_tool,
        "session_id": session_id,
        "workspace": str(ws.path),
        "model": (init or {}).get("model"),
        "claude_version": (init or {}).get("claude_code_version"),
        "tools": (init or {}).get("tools"),
        "error": error if error else (None if transcript else "session transcript not found"),
        "findings": findings,
        "telemetry": tele,
        "cost_usd": (result or {}).get("total_cost_usd"),
        "duration_ms": (result or {}).get("duration_ms"),
        "wall_seconds": round(time.monotonic() - started, 1),
        "num_turns": (result or {}).get("num_turns"),
        "denied": [
            {"tool": d.get("tool_name"), "input": json.dumps(d.get("tool_input"), sort_keys=True)[:300]} for d in denials
        ],
    }


def calibrate_builtins(work_root: Path, raw_dir: Path, *, model: str, timeout: float) -> dict[str, Any]:
    """Measure the skills Claude Code lists in an empty project with the replay flags.

    These built-in skills appear in every arm; the exposure check subtracts them.
    """
    empty = work_root / "calibration"
    empty.mkdir()
    run(["git", "init", "-q", str(empty)], env=hermetic_git_env(), timeout=60)
    reviewer = plain_reviewer()
    session_id, stdout, init, result, error = run_session(
        lambda sid: review_command(reviewer, sid, model=model, max_usd=0.5), empty, CALIBRATION_PROMPT, timeout
    )
    transcript = find_transcript(session_id)
    keep_raw(transcript, stdout, raw_dir)
    if transcript is None:
        raise BenchError(f"calibration session left no transcript ({error or 'unknown error'})")
    listed = telemetry.parse_session(transcript, empty)["listed"]
    return {
        "claude_version": (init or {}).get("claude_code_version"),
        "names": sorted(listed),
        "cost_usd": (result or {}).get("total_cost_usd"),
    }
