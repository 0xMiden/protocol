"""Pipeline stages. Each stage reads and writes files in a run directory."""

from __future__ import annotations

import json
import math
import os
import shutil
import sys
from pathlib import Path
from typing import Any

from . import github, judge, report, runner, telemetry, workspace
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


def run_ids(config: dict[str, Any]) -> list[str]:
    return [f"{workspace.parse_arm(a).slug}.{i}" for a in config["arms"] for i in range(1, config["runs"] + 1)]


def stage_replay(run_dir: Path, config: dict[str, Any], keep_workspaces: bool = False) -> None:
    if all((run_dir / "runs" / f"{rid}.json").exists() for rid in run_ids(config)) and (run_dir / "builtins.json").exists():
        print("all review runs already exist; nothing to replay")
        return
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


# --- judge stages --------------------------------------------------------


def _judge_cwd(config: dict[str, Any]) -> tuple[Path, Path]:
    """An empty directory outside any project for judge sessions."""
    root = workspace.new_work_root(config.get("work_dir"))
    cwd = root / "judge"
    cwd.mkdir()
    return root, cwd


def _judge_kwargs(config: dict[str, Any], cwd: Path) -> dict[str, Any]:
    return {"model": config["judge_model"], "max_usd": config["max_usd_judge"], "cwd": cwd, "timeout": config["timeout"]}


def valid_runs(run_dir: Path, arm: str | None = None) -> list[dict[str, Any]]:
    records = [read_json(p) for p in sorted((run_dir / "runs").glob("*.json"))]
    return [r for r in records if r.get("valid") and (arm is None or r["arm"] == arm)]


def stage_classify(run_dir: Path, config: dict[str, Any]) -> None:
    """Turn the candidate threads into ground-truth findings (truth.json)."""
    pr = read_json(run_dir / "pr.json")
    raw = raw_dir(run_dir) / "judge"
    verdicts: list[dict[str, Any]] = []
    cost = 0.0
    if pr["candidates"]:
        root, cwd = _judge_cwd(config)
        try:
            for n, batch in enumerate(judge.batches(pr["candidates"], judge.CLASSIFY_BATCH), start=1):
                out, spent = judge.call_role(
                    "thread-classifier",
                    judge.classification_payload(batch),
                    "thread-classes",
                    raw_path=raw / f"classify-{n}.json",
                    **_judge_kwargs(config, cwd),
                )
                verdicts += out.get("threads") or []
                cost += spent
        finally:
            shutil.rmtree(root, ignore_errors=True)
    truth, excluded = judge.merge_classification(pr["candidates"], verdicts)
    write_json(
        run_dir / "truth.json",
        {"truth": truth, "excluded": excluded, "judge_model": config["judge_model"], "cost_usd": round(cost, 4)},
    )
    print(f"classified {len(pr['candidates'])} candidates: {len(truth)} findings, {len(excluded)} excluded")


def stage_match(run_dir: Path, config: dict[str, Any]) -> None:
    """Match every valid run's findings to the ground truth (matches/<run>.json)."""
    truth = read_json(run_dir / "truth.json")["truth"]
    raw = raw_dir(run_dir) / "judge"
    root, cwd = _judge_cwd(config)
    try:
        for record in valid_runs(run_dir):
            path = run_dir / "matches" / f"{record['id']}.json"
            if path.exists():
                continue
            matches: list[dict[str, Any]] = []
            cost = 0.0
            if truth and record["findings"]:
                out, cost = judge.call_role(
                    "matcher",
                    judge.match_payload(truth, record["findings"]),
                    "matches",
                    raw_path=raw / f"match-{record['id']}.json",
                    **_judge_kwargs(config, cwd),
                )
                matches = judge.filter_matches(out, {t["id"] for t in truth}, {f["id"] for f in record["findings"]})
            write_json(path, {"run": record["id"], "matches": matches, "cost_usd": round(cost, 4)})
            matched = len({m["human_id"] for m in matches})
            print(f"{record['id']}: {matched} of {len(truth)} human findings matched by {len(record['findings'])} agent findings")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def unmatched_findings(run_dir: Path, record: dict[str, Any]) -> list[dict[str, Any]]:
    path = run_dir / "matches" / f"{record['id']}.json"
    if not path.is_file():
        raise BenchError(f"run {record['id']} has no matches yet; run the match stage first")
    matched = {m["agent_id"] for m in read_json(path)["matches"]}
    return [f for f in record["findings"] if f["id"] not in matched]


def stage_attribute(run_dir: Path, config: dict[str, Any]) -> None:
    """Ask which snapshot skills cover each finding (attribution/<arm>.json)."""
    truth = read_json(run_dir / "truth.json")["truth"]
    raw = raw_dir(run_dir) / "judge"
    for arm in (workspace.parse_arm(a) for a in config["arms"]):
        path = run_dir / "attribution" / f"{arm.slug}.json"
        if not arm.has_skills or path.exists():
            continue
        snapshot = read_json(run_dir / "snapshots" / f"{arm.slug}.json")
        skills = [
            {"name": s["name"], "description": s["description"], "body": snapshot["skill_bodies"].get(s["name"], "")}
            for s in snapshot["skills"]
        ]
        unmatched = [f for record in valid_runs(run_dir, arm.name) for f in unmatched_findings(run_dir, record)]
        items = judge.attribution_items(truth, unmatched)
        verdicts: dict[str, dict[str, Any]] = {}
        cost = 0.0
        if skills and items:
            root, cwd = _judge_cwd(config)
            try:
                for n, batch in enumerate(judge.batches(items, judge.ATTRIBUTE_BATCH), start=1):
                    out, spent = judge.call_role(
                        "attributor",
                        judge.attribution_payload(skills, batch),
                        "attribution",
                        raw_path=raw / f"attribute-{arm.slug}-{n}.json",
                        **_judge_kwargs(config, cwd),
                    )
                    verdicts.update(judge.filter_attribution(out, {i["id"] for i in batch}, {s["name"] for s in skills}))
                    cost += spent
            finally:
                shutil.rmtree(root, ignore_errors=True)
        codifiable = {t["id"]: t["codifiable"] for t in truth}
        for item in items:
            verdicts.setdefault(item["id"], {"covering_skills": [], "codifiable": codifiable.get(item["id"], True)})
        write_json(path, {"arm": arm.name, "items": verdicts, "cost_usd": round(cost, 4)})
        covered = sum(1 for t in truth if verdicts[t["id"]]["covering_skills"])
        print(f"{arm.name}: {covered} of {len(truth)} human findings are covered by a snapshot skill")


# --- report and orchestration ------------------------------------------


def stage_report(run_dir: Path, config: dict[str, Any]) -> None:
    result = report.build_result(run_dir)
    write_json(run_dir / "result.json", result)
    (run_dir / "report.md").write_text(report.render_markdown(result), encoding="utf-8")
    for arm, summary in result["arms"].items():
        recall = summary["recall"]["mean"]
        print(f"{arm}: mean recall {'n/a' if recall is None else f'{recall:.0%}'} over {len(summary['runs'])} valid run(s)")
    for fix in result["top_fixes"]:
        print(f"fix: {fix['text']}")
    print(f"report: {run_dir / 'report.md'}")


def estimate_plan(config: dict[str, Any], candidates: int | None = None) -> dict[str, Any]:
    """How many sessions a run will start, and the worst-case cost ceiling."""
    arms = [workspace.parse_arm(a) for a in config["arms"]]
    reviews = len(arms) * config["runs"]
    classify = max(1, math.ceil(candidates / judge.CLASSIFY_BATCH)) if candidates else 1
    attribute = sum(1 for a in arms if a.has_skills)
    judge_calls = classify + reviews + attribute
    calibration_cap = 0.5
    ceiling = reviews * config["max_usd_review"] + calibration_cap + judge_calls * config["max_usd_judge"]
    return {
        "reviews": reviews,
        "calibration": 1,
        "judge_calls": {"classify": classify, "match": reviews, "attribute": attribute, "total": judge_calls},
        "ceiling_usd": round(ceiling, 2),
    }


def describe_plan(config: dict[str, Any], plan: dict[str, Any], env: dict[str, Any]) -> str:
    auth = env.get("auth") or {}
    if auth.get("api_key_in_environment"):
        billing = "ANTHROPIC_API_KEY is set, so runs are billed per token to that key."
    elif auth.get("authMethod") == "claude.ai":
        billing = (
            f"You are logged in with a claude.ai {auth.get('subscriptionType') or ''} subscription, so runs count against "
            "your usage limits (the same limits as your interactive use), not per-token billing."
        )
    else:
        billing = "Could not determine the login method; check `claude auth status`."
    calls = plan["judge_calls"]
    return "\n".join(
        [
            f"Plan for {config['repo']}#{config['number']}, review round {config['round']}:",
            f"- {plan['reviews']} review run(s): arms {', '.join(config['arms'])} x {config['runs']} run(s), reviewer "
            f"{config['reviewer']}, model {config['model'] or 'default'}, each capped at ${config['max_usd_review']:.2f}",
            f"- 1 calibration run in an empty project (model {config['calibration_model']}, capped at $0.50)",
            f"- about {calls['total']} judge call(s) (classify {calls['classify']}, match {calls['match']}, attribute "
            f"{calls['attribute']}) on {config['judge_model']}, each capped at ${config['max_usd_judge']:.2f}",
            f"Worst-case ceiling: ${plan['ceiling_usd']:.2f}. Actual costs are usually far lower and are listed in the report.",
            billing,
        ]
    )


def run_pipeline(run_dir: Path, config: dict[str, Any], keep_workspaces: bool = False) -> None:
    """Run every stage in order, skipping work whose output already exists."""
    if not (run_dir / "pr.json").exists():
        stage_fetch(run_dir, config)
    stage_replay(run_dir, config, keep_workspaces)
    if not (run_dir / "truth.json").exists():
        stage_classify(run_dir, config)
    stage_match(run_dir, config)
    stage_attribute(run_dir, config)
    stage_report(run_dir, config)
