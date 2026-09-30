"""Command-line interface.

Each invocation works on a *run directory*. `fetch` (or `all`) creates it and
records the options in `config.json`; every later stage reads that file, so
a stage can be re-run on stored artifacts without repeating earlier ones.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__, github
from .util import BenchError, read_json, write_json

DEFAULT_OUT = "skill-bench-results"


def _config_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--pr", required=True, help="owner/repo#N, a GitHub PR URL, or a bare PR number")
    parser.add_argument("--repo", help="owner/name used to resolve a bare PR number (default: this checkout, or its parent if it is a fork)")
    parser.add_argument("--out", default=DEFAULT_OUT, help=f"directory that collects run directories (default: {DEFAULT_OUT})")
    parser.add_argument("--run-dir", help="use this exact run directory instead of a new timestamped one")
    parser.add_argument("--skills-dir", default=".claude/skills", help="skills directory inside the repository (default: .claude/skills)")
    parser.add_argument("--round", type=int, default=1, help="which human review round to replay, 1 = the first (default: 1)")


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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except BenchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0
