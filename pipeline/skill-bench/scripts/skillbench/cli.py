"""Command-line interface.

Each invocation works on a *run directory*. `fetch` (or `all`) creates it and
records the options in `config.json`; every later stage reads that file, so
a stage can be re-run on stored artifacts without repeating earlier ones.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__, github, roles, runner, telemetry, workspace
from .util import BenchError, read_json, run, write_json

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


def _new_config(args: argparse.Namespace) -> dict[str, Any]:
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
        "arms": [workspace.parse_arm(a).name for a in args.arms.split(",") if a.strip()],
        "source_repo": args.source_repo,
        "work_dir": args.work_dir,
        "runs": args.runs,
        "reviewer": args.reviewer,
        "repo_agent": args.repo_agent,
        "model": args.model,
        "max_usd_review": args.max_usd_per_review,
        "timeout": args.timeout,
        "calibration_model": args.calibration_model,
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


def load_run(run_dir: str | Path) -> tuple[Path, dict[str, Any]]:
    path = Path(run_dir)
    if not (path / "config.json").is_file():
        raise BenchError(f"{path} is not a run directory (no config.json)")
    return path, read_json(path / "config.json")


def stage_fetch(run_dir: Path, config: dict[str, Any]) -> None:
    owner, name = config["repo"].split("/", 1)
    raw = github.fetch_pull_request(owner, name, config["number"])
    pr = github.select_review_round(raw, config["skills_dir"], config["round"])
    pr["repo"] = config["repo"]
    pr["base_sha"] = github.merge_base(owner, name, pr["base_ref_oid"], pr["review_sha"])
    write_json(run_dir / "pr.json", pr)
    print(
        f"{config['repo']}#{config['number']}: round {pr['round']} of {len(pr['rounds'])} at {pr['review_sha'][:12]}, "
        f"{len(pr['candidates'])} candidate findings from {len(pr['reviewers'])} reviewer(s)"
    )


def cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "skill-bench"


def prepare_workspaces(run_dir: Path, config: dict[str, Any]) -> tuple[Path, dict[str, workspace.Workspace]]:
    """Build one sealed workspace per arm under a fresh work root outside any project."""
    pr = read_json(run_dir / "pr.json")
    arms = [workspace.parse_arm(a) for a in config["arms"]]
    shas = [pr["base_sha"], pr["review_sha"]] + [a.ref for a in arms if a.ref]
    source = workspace.resolve_source(config["repo"], shas, config.get("source_repo"), cache_dir())
    work_root = workspace.new_work_root(config.get("work_dir"))
    template = workspace.build_template(source, pr["base_sha"], pr["review_sha"], work_root)
    built = {}
    for arm in arms:
        ws = workspace.materialize(template, arm, source, pr["base_sha"], work_root, config["skills_dir"])
        if pr["modified_claude_files"]:
            ws.deviations.append("the PR's own changes under .claude/ are not part of the replayed diff")
        built[arm.name] = ws
    return work_root, built


def _cmd_workspace(args: argparse.Namespace) -> None:
    run_dir, config = load_run(args.run_dir)
    work_root, built = prepare_workspaces(run_dir, config)
    summary = {name: {"path": str(ws.path), **ws.describe()} for name, ws in built.items()}
    print(json.dumps(summary, indent=2))
    print(f"workspaces are under {work_root}; delete it when done", file=sys.stderr)


def raw_dir(run_dir: Path) -> Path:
    """Bulky and sensitive artifacts (streams, transcripts); ignored by git."""
    path = run_dir / "raw"
    path.mkdir(parents=True, exist_ok=True)
    (path / ".gitignore").write_text("*\n", encoding="utf-8")
    return path


def environment_info() -> dict[str, Any]:
    """Claude Code version and login method, so cost figures can be read correctly."""
    version = run(["claude", "--version"], check=False, timeout=60).stdout.strip()
    auth: dict[str, Any] = {}
    status = run(["claude", "auth", "status"], check=False, timeout=60)
    try:
        data = json.loads(status.stdout)
        auth = {key: data.get(key) for key in ("authMethod", "subscriptionType", "apiProvider")}
    except ValueError:
        pass
    auth["api_key_in_environment"] = bool(os.environ.get("ANTHROPIC_API_KEY"))
    return {"claude_version": version, "auth": auth}


def stage_replay(run_dir: Path, config: dict[str, Any], keep_workspaces: bool = False) -> None:
    pr = read_json(run_dir / "pr.json")
    raw = raw_dir(run_dir)
    write_json(run_dir / "environment.json", environment_info())
    work_root, built = prepare_workspaces(run_dir, config)
    try:
        builtins_path = run_dir / "builtins.json"
        if not builtins_path.exists():
            calibration = runner.calibrate_builtins(
                work_root, raw / "calibration", model=config["calibration_model"], timeout=config["timeout"]
            )
            write_json(builtins_path, calibration)
        builtins = read_json(builtins_path)["names"]
        for ws in built.values():
            snapshot = {**ws.describe(), "skill_bodies": {s["name"]: s["body"] for s in ws.skills}}
            write_json(run_dir / "snapshots" / f"{ws.arm.slug}.json", snapshot)
            reviewer = runner.reviewer_for(config["reviewer"], ws, config["repo_agent"])
            expected = [s["name"] for s in ws.skills if s["model_invocable"]] + ws.commands if reviewer.has_skill_tool else []
            for index in range(1, config["runs"] + 1):
                run_id = f"{ws.arm.slug}.{index}"
                path = run_dir / "runs" / f"{run_id}.json"
                if path.exists():
                    print(f"{run_id}: already done, skipping")
                    continue
                record = runner.run_review(
                    ws,
                    reviewer,
                    run_id,
                    raw / run_id,
                    model=config["model"],
                    max_usd=config["max_usd_review"],
                    timeout=config["timeout"],
                    skills_dir=config["skills_dir"],
                    ignore_files=tuple(pr["modified_skill_files"]),
                )
                record["expected_listing"] = sorted(expected)
                runner.finalize(record, builtins, snapshot)
                write_json(path, record)
                tele = record["telemetry"] or {}
                print(
                    f"{run_id}: {'valid' if record['valid'] else 'INVALID'}, {len(record['findings'])} findings, "
                    f"skills invoked {tele.get('invoked', [])}, read {tele.get('read', [])}, "
                    f"est. ${record['cost_usd'] or 0:.2f}"
                    + (f" - {'; '.join(record['problems'])}" if record["problems"] else "")
                )
    finally:
        if keep_workspaces:
            print(f"workspaces kept under {work_root}", file=sys.stderr)
        else:
            shutil.rmtree(work_root, ignore_errors=True)


def stage_telemetry(run_dir: Path, config: dict[str, Any]) -> None:
    """Re-parse the stored transcripts of every run (for example after a parser change)."""
    pr = read_json(run_dir / "pr.json")
    builtins = read_json(run_dir / "builtins.json")["names"]
    for path in sorted((run_dir / "runs").glob("*.json")):
        record = read_json(path)
        transcript = run_dir / "raw" / record["id"] / "transcript.jsonl"
        if not transcript.is_file():
            continue
        snapshot = read_json(run_dir / "snapshots" / f"{workspace.parse_arm(record['arm']).slug}.json")
        record["telemetry"] = telemetry.parse_session(
            transcript,
            Path(record["workspace"]),
            config["skills_dir"],
            tuple(pr["modified_skill_files"]),
            (runner.config_dir() / "projects",),
        )
        runner.finalize(record, builtins, snapshot)
        write_json(path, record)
    print(f"re-parsed transcripts in {run_dir / 'runs'}")


def _cmd_replay(args: argparse.Namespace) -> None:
    run_dir, config = load_run(args.run_dir)
    stage_replay(run_dir, config, keep_workspaces=args.keep_workspaces)


def _cmd_telemetry(args: argparse.Namespace) -> None:
    run_dir, config = load_run(args.run_dir)
    stage_telemetry(run_dir, config)


def _cmd_render_role(args: argparse.Namespace) -> None:
    print(roles.agents_json(roles.load_role(args.role)))


def _cmd_fetch(args: argparse.Namespace) -> None:
    config = _new_config(args)
    run_dir = _create_run_dir(args, config)
    stage_fetch(run_dir, config)
    print(f"run directory: {run_dir}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bench.py",
        description="Benchmark a project's Claude Code skills against the human review of a pull request.",
    )
    parser.add_argument("--version", action="version", version=f"skill-bench {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

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
