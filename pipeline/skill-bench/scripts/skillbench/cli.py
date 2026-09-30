"""Command-line interface.

Each invocation works on a *run directory*. `fetch` (or `all`) creates it and
records the options in `config.json`; every later stage reads that file, so
a stage can be re-run on stored artifacts without repeating earlier ones.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__, github, roles, runner, stages, workspace
from .util import BenchError, write_json

DEFAULT_OUT = "skill-bench-results"


def _config_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--pr", required=True, help="owner/repo#N, a GitHub PR URL, or a bare PR number")
    parser.add_argument("--repo", help="owner/name used to resolve a bare PR number (default: this checkout, or its parent if it is a fork)")
    parser.add_argument("--out", default=DEFAULT_OUT, help=f"directory that collects run directories (default: {DEFAULT_OUT})")
    parser.add_argument("--run-dir", help="use this exact run directory instead of a new timestamped one")
    parser.add_argument("--skills-dir", default=".claude/skills", help="skills directory inside the repository (default: .claude/skills)")
    parser.add_argument("--round", type=int, default=1, help="which human review round to replay, 1 = the first (default: 1)")
    parser.add_argument("--arms", default="at-pr,none", help="comma-separated arms: at-pr, none, ref:<sha> (default: at-pr,none)")
    parser.add_argument("--source-repo", help="local clone that contains the PR's commits (default: this checkout, else a cached mirror)")
    parser.add_argument("--work-dir", help="parent directory for replay workspaces; must be outside any project (default: the system temp directory)")
    parser.add_argument("--runs", type=int, default=2, help="review runs per arm (default: 2)")
    parser.add_argument("--reviewer", default="plain", choices=runner.MODES, help="who reviews: skill-bench's generic reviewer (plain), the project's own agent as-is (repo-agent), or that agent with the Skill tool added (default: plain)")
    parser.add_argument("--repo-agent", default="code-reviewer", help="project agent used by the repo-agent modes (default: code-reviewer)")
    parser.add_argument("--model", help="model for the review runs (default: the reviewer's or Claude Code's default)")
    parser.add_argument("--max-usd-per-review", type=float, default=3.0, help="per-run cost ceiling passed to --max-budget-usd (default: 3.00)")
    parser.add_argument("--timeout", type=int, default=1800, help="seconds before a single run is abandoned (default: 1800)")
    parser.add_argument("--calibration-model", default="haiku", help="model for the built-in skill calibration run (default: haiku)")
    parser.add_argument("--judge-model", default="opus", help="model for classifying threads, matching and attribution (default: opus)")
    parser.add_argument("--max-usd-per-judge", type=float, default=1.0, help="cost ceiling for one judge call (default: 1.00)")


def _resolve_arms(text: str, owner: str, name: str) -> list[str]:
    """Parse, deduplicate, and pin `ref:` arms to full SHAs so a resumed run rebuilds the same snapshot."""
    arms: list[str] = []
    for part in text.split(","):
        if not part.strip():
            continue
        arm = workspace.parse_arm(part)
        if arm.kind == "ref" and arm.ref:
            arm = workspace.parse_arm(f"ref:{github.resolve_commit(owner, name, arm.ref)}")
        if arm.name not in arms:
            arms.append(arm.name)
    if not arms:
        raise BenchError("--arms names no arm")
    return arms


def _new_config(args: argparse.Namespace) -> dict[str, Any]:
    if args.runs < 1 or args.round < 1:
        raise BenchError("--runs and --round must be at least 1")
    default_repo = args.repo
    if default_repo is None and args.pr.strip().isdigit():
        default_repo = github.default_repo_for_cwd()
    owner, name, number = github.parse_pr_ref(args.pr, default_repo)
    return {
        "tool_version": __version__,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "repo": f"{owner}/{name}",
        "number": number,
        "skills_dir": args.skills_dir.rstrip("/"),
        "round": args.round,
        "arms": _resolve_arms(args.arms, owner, name),
        "source_repo": args.source_repo,
        "work_dir": args.work_dir,
        "runs": args.runs,
        "reviewer": args.reviewer,
        "repo_agent": args.repo_agent,
        "model": args.model,
        "max_usd_review": args.max_usd_per_review,
        "timeout": args.timeout,
        "calibration_model": args.calibration_model,
        "judge_model": args.judge_model,
        "max_usd_judge": args.max_usd_per_judge,
    }


def _create_run_dir(args: argparse.Namespace, config: dict[str, Any]) -> Path:
    if args.run_dir:
        run_dir = Path(args.run_dir)
    else:
        stamp = config["created_at"].replace(":", "").replace("-", "")
        slug = config["repo"].replace("/", "-")
        run_dir = Path(args.out) / f"{slug}-{config['number']}" / stamp
    if (run_dir / "config.json").exists():
        raise BenchError(f"{run_dir} already holds a run; pass a different --run-dir")
    run_dir.mkdir(parents=True, exist_ok=True)
    write_json(run_dir / "config.json", config)
    return run_dir


def _cmd_replay(args: argparse.Namespace) -> None:
    run_dir, config = stages.load_run(args.run_dir)
    stages.stage_replay(run_dir, config, keep_workspaces=args.keep_workspaces)


def _cmd_telemetry(args: argparse.Namespace) -> None:
    run_dir, config = stages.load_run(args.run_dir)
    stages.stage_telemetry(run_dir, config)


def _stage_command(stage: Any) -> Any:
    def command(args: argparse.Namespace) -> None:
        run_dir, config = stages.load_run(args.run_dir)
        stage(run_dir, config)

    return command


def _cmd_estimate(args: argparse.Namespace) -> None:
    config = _new_config(args)
    plan = stages.estimate_plan(config, stages.count_candidates(config))
    print(stages.describe_plan(config, plan, stages.environment_info()))


def _cmd_all(args: argparse.Namespace) -> None:
    config = _new_config(args)
    run_dir = _create_run_dir(args, config)
    print(f"run directory: {run_dir}")
    stages.run_pipeline(run_dir, config, keep_workspaces=args.keep_workspaces)


def _cmd_resume(args: argparse.Namespace) -> None:
    run_dir, config = stages.load_run(args.run_dir)
    stages.run_pipeline(run_dir, config, keep_workspaces=args.keep_workspaces)


def _cmd_render_role(args: argparse.Namespace) -> None:
    print(roles.agents_json(roles.load_role(args.role)))


def _cmd_workspace(args: argparse.Namespace) -> None:
    run_dir, config = stages.load_run(args.run_dir)
    work_root, built = stages.prepare_workspaces(run_dir, config)
    summary = {name: {"path": str(ws.path), **ws.describe()} for name, ws in built.items()}
    print(json.dumps(summary, indent=2))
    print(f"workspaces are under {work_root}; delete it when done", file=sys.stderr)


def _cmd_fetch(args: argparse.Namespace) -> None:
    config = _new_config(args)
    run_dir = _create_run_dir(args, config)
    stages.stage_fetch(run_dir, config)
    print(f"run directory: {run_dir}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bench.py",
        description="Benchmark a project's Claude Code skills against the human review of a pull request.",
    )
    parser.add_argument("--version", action="version", version=f"skill-bench {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    everything = sub.add_parser("all", help="run every stage for a PR in a new run directory")
    _config_options(everything)
    everything.add_argument("--keep-workspaces", action="store_true", help="keep the replay workspaces for inspection")
    everything.set_defaults(func=_cmd_all)

    estimate = sub.add_parser("estimate", help="show how many sessions a run would start and its worst-case cost")
    _config_options(estimate)
    estimate.set_defaults(func=_cmd_estimate)

    resume = sub.add_parser("resume", help="continue an interrupted run, skipping finished work")
    resume.add_argument("--run-dir", required=True)
    resume.add_argument("--keep-workspaces", action="store_true", help="keep the replay workspaces for inspection")
    resume.set_defaults(func=_cmd_resume)

    fetch = sub.add_parser("fetch", help="create a run directory and fetch one human review round of the PR")
    _config_options(fetch)
    fetch.set_defaults(func=_cmd_fetch)

    ws = sub.add_parser("workspace", help="build the sealed replay workspaces of a run for inspection")
    ws.add_argument("--run-dir", required=True)
    ws.set_defaults(func=_cmd_workspace)

    replay = sub.add_parser("replay", help="replay the review headlessly in every arm and record skill telemetry")
    replay.add_argument("--run-dir", required=True)
    replay.add_argument("--keep-workspaces", action="store_true", help="keep the replay workspaces for inspection")
    replay.set_defaults(func=_cmd_replay)

    tele = sub.add_parser("telemetry", help="re-parse the stored transcripts of a run")
    tele.add_argument("--run-dir", required=True)
    tele.set_defaults(func=_cmd_telemetry)

    for name, stage, help_text in (
        ("classify", stages.stage_classify, "classify the human review threads into ground-truth findings"),
        ("match", stages.stage_match, "match each valid run's findings to the ground truth"),
        ("attribute", stages.stage_attribute, "decide which snapshot skills cover each finding"),
        ("report", stages.stage_report, "bucket every finding and write result.json and report.md"),
    ):
        stage_parser = sub.add_parser(name, help=help_text)
        stage_parser.add_argument("--run-dir", required=True)
        stage_parser.set_defaults(func=_stage_command(stage))

    render = sub.add_parser("render-role", help="print a role as the JSON that claude --agents expects")
    render.add_argument("role", help="role name, e.g. reviewer")
    render.set_defaults(func=_cmd_render_role)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except BenchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0
