"""Assemble result.json and report.md from a run directory's artifacts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import buckets
from .util import read_json
from .workspace import parse_arm

SCHEMA_VERSION = 1


def _optional(path: Path, default: Any = None) -> Any:
    return read_json(path) if path.is_file() else default


def build_result(run_dir: Path) -> dict[str, Any]:
    config = read_json(run_dir / "config.json")
    pr = read_json(run_dir / "pr.json")
    truth_file = read_json(run_dir / "truth.json")
    truth = truth_file["truth"]
    records = [read_json(p) for p in sorted((run_dir / "runs").glob("*.json"))]
    valid = [r for r in records if r.get("valid")]
    matches = {r["id"]: _optional(run_dir / "matches" / f"{r['id']}.json", {"matches": []})["matches"] for r in valid}
    snapshots, attributions = {}, {}
    for name in config["arms"]:
        arm = parse_arm(name)
        if arm.has_skills and (run_dir / "snapshots" / f"{arm.slug}.json").is_file():
            snapshots[name] = read_json(run_dir / "snapshots" / f"{arm.slug}.json")
            attributions[name] = _optional(run_dir / "attribution" / f"{arm.slug}.json", {"items": {}})["items"]
    evaluation = buckets.evaluate(truth, valid, matches, attributions, snapshots)

    review_cost = sum(r.get("cost_usd") or 0 for r in records)
    judge_cost = (truth_file.get("cost_usd") or 0) + sum(
        (_optional(p, {}) or {}).get("cost_usd") or 0
        for p in sorted((run_dir / "matches").glob("*.json")) + sorted((run_dir / "attribution").glob("*.json"))
    )
    calibration = _optional(run_dir / "builtins.json", {})
    calibration_cost = calibration.get("cost_usd") or 0
    notes = []
    for name, snapshot in sorted(snapshots.items()):
        notes += [f"{name}: {d}" for d in snapshot.get("deviations", [])]
    notes += pr.get("warnings", [])
    if not any(r["arm"] == "none" for r in valid):
        notes.append(
            f"No valid run of the no-skills control arm: catches are bucketed {buckets.TP_NO_CONTROL}, "
            "and no skill gets credit for them."
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "pr": {k: pr.get(k) for k in ("repo", "number", "title", "url", "round", "review_sha", "base_sha", "author", "reviewers")},
        "config": {k: config.get(k) for k in ("arms", "runs", "reviewer", "repo_agent", "model", "judge_model", "skills_dir", "tool_version")},
        "environment": _optional(run_dir / "environment.json", {}),
        "builtin_skills": calibration.get("names", []),
        "truth": truth,
        "excluded": truth_file["excluded"],
        "runs": [
            {
                "id": r["id"],
                "arm": r["arm"],
                "valid": r.get("valid"),
                "problems": r.get("problems", []),
                "model": r.get("model"),
                "findings": len(r.get("findings", [])),
                "invoked": (r.get("telemetry") or {}).get("invoked", []),
                "read": (r.get("telemetry") or {}).get("read", []),
                "not_listed": (r.get("exposure") or {}).get("missing", []),
                "outside_paths": (r.get("telemetry") or {}).get("outside_paths", []),
                "denied": [d["tool"] for d in r.get("denied", [])],
                "cost_usd": r.get("cost_usd"),
            }
            for r in records
        ],
        **evaluation,
        "costs": {
            "reviews_usd": round(review_cost, 4),
            "judge_usd": round(judge_cost, 4),
            "calibration_usd": round(calibration_cost, 4),
            "total_usd": round(review_cost + judge_cost + calibration_cost, 4),
        },
        "notes": notes,
    }


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.0f}%"


def render_markdown(result: dict[str, Any]) -> str:
    pr = result["pr"]
    truth = result["truth"]
    lines = [
        f"# skill-bench: {pr['repo']}#{pr['number']}, review round {pr['round']}",
        "",
        f"[{pr['title']}]({pr['url']}). Replayed the review of commit `{pr['review_sha'][:12]}` "
        f"(base `{pr['base_sha'][:12]}`). Ground truth: {len(truth)} actionable finding(s) from "
        f"{', '.join(pr.get('reviewers') or []) or 'no reviewers'}; {len(result['excluded'])} thread(s) excluded.",
        "",
        "## Recall",
        "",
    ]
    for arm, summary in result["arms"].items():
        recall = summary["recall"]
        lines.append(
            f"- `{arm}`: {_pct(recall['mean'])} of human findings matched on average "
            f"(min {_pct(recall['min'])}, max {_pct(recall['max'])}) over {len(summary['runs'])} valid run(s); "
            f"{sum(summary['findings_per_run'].values())} agent findings in total."
        )
    invalid = [r for r in result["runs"] if not r["valid"]]
    if invalid:
        lines.append(f"- {len(invalid)} run(s) were invalid and left out: " + "; ".join(f"{r['id']} ({'; '.join(r['problems'])})" for r in invalid))

    lines += ["", "## Most actionable fixes", ""]
    if result["top_fixes"]:
        lines += [f"{i}. {fix['text']}" for i, fix in enumerate(result["top_fixes"], start=1)]
    else:
        lines.append("Nothing stood out: no missed finding points at a skill or a coverage gap.")

    lines += ["", "## Human findings", ""]
    for t in truth:
        outcome = result["truth_outcomes"].get(t["id"], {})
        parts = []
        for arm, o in outcome.items():
            detail = f"`{arm}` matched {o['matched_runs']}/{o['runs']}"
            if o.get("modal"):
                detail += f", mostly {o['modal']}"
            parts.append(detail)
        covering = next((o.get("covering_skills") for o in outcome.values() if o.get("covering_skills")), [])
        lines.append(
            f"- [{t['id']}]({t['url']}) {t['kind']}: {t['rule']} "
            f"({'; '.join(parts) or 'no valid runs'}; covered by {', '.join(f'`{s}`' for s in covering) or 'no skill'})"
        )

    for arm, stats in result["skills"].items():
        active = {n: s for n, s in stats.items() if s["loaded_runs"] or s["relevant_findings"] or s["unmatched_linked"]}
        lines += ["", f"## Skills in `{arm}`", ""]
        if not active:
            lines.append(f"None of the {len(stats)} skills was loaded or relevant to a finding.")
            continue
        lines += [
            "| skill | listed | loaded | relevant | caught with it | trigger misses | application misses | agent-only findings |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
        for name, s in sorted(active.items()):
            lines.append(
                f"| `{name}` | {s['listed_runs']} | {s['loaded_runs']} | {s['relevant_findings']} | {s['tp_attributed']} | "
                f"{s['trigger_misses']} | {s['application_misses']} | {s['unmatched_linked']} |"
            )
        lines.append("")
        lines.append(f"{len(stats) - len(active)} other skill(s) were neither loaded nor relevant. Counts are over runs.")

    for arm, items in result["unmatched"].items():
        if items:
            lines += ["", f"## Agent-only findings in `{arm}`", ""]
            lines += [f"- {f['id']} ({f['bucket']}): {f['title']} ({f['path']})" for f in items]

    env = result.get("environment") or {}
    auth = env.get("auth") or {}
    costs = result["costs"]
    billing = (
        "per-token API charges"
        if auth.get("api_key_in_environment")
        else f"estimates at API list price; on a {auth.get('subscriptionType') or 'subscription'} login they count against usage limits, not a bill"
    )
    lines += [
        "",
        "## Cost",
        "",
        f"About ${costs['total_usd']:.2f} in total (reviews ${costs['reviews_usd']:.2f}, judge ${costs['judge_usd']:.2f}, "
        f"calibration ${costs['calibration_usd']:.2f}). These are {billing}.",
    ]

    notes = list(result["notes"])
    for r in result["runs"]:
        if r["not_listed"]:
            notes.append(f"{r['id']}: expected skills missing from the listing: {', '.join(r['not_listed'])}")
        if r["outside_paths"]:
            notes.append(f"{r['id']}: touched paths outside the workspace: {', '.join(r['outside_paths'])}")
    if notes:
        lines += ["", "## Notes", ""] + [f"- {n}" for n in notes]

    lines += ["", "## How to read the buckets", ""]
    lines += [f"- `{name}`: {meaning}." for name, meaning in buckets.MEANING.items()]
    lines += [
        "",
        f"Environment: {env.get('claude_version', 'unknown Claude Code version')}; reviewer `{result['config']['reviewer']}`, "
        f"review model {result['config']['model'] or 'default'}, judge model {result['config']['judge_model']}.",
    ]
    return "\n".join(lines) + "\n"
