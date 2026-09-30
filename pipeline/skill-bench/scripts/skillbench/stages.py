"""Pipeline stages. Each stage reads and writes files in a run directory."""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

from . import github, runner, telemetry, workspace
from .util import BenchError, read_json, run, write_json


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
