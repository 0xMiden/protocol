"""The judge steps: classify human threads, match findings, attribute skills.

Each step is a headless `claude -p` session running one role from `roles/`
with no tools, in an empty directory outside any project, so the judge sees
no skill listing and no repository. Only the answers to semantic questions
come from the model; which bucket a finding lands in is decided by code
(see `buckets.py`).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import roles
from .runner import ISOLATION_SETTINGS
from .util import BenchError, run

CLASSIFY_BATCH = 20
ATTRIBUTE_BATCH = 25
MATCH_THRESHOLD = 0.5
_ACTIONABLE_KINDS = ("blocking", "should-fix", "nit")

Runner = Callable[..., Any]


def call_role(
    role_name: str,
    payload: dict[str, Any],
    schema_name: str,
    *,
    model: str | None,
    max_usd: float,
    cwd: Path,
    raw_path: Path,
    timeout: float,
    runner: Runner = run,
) -> tuple[dict[str, Any], float]:
    """Run one judge role on a JSON payload; return (structured output, estimated cost)."""
    role = roles.load_role(role_name)
    cmd = [
        "claude",
        "-p",
        "--output-format",
        "json",
        "--tools",
        "",
        "--setting-sources",
        "project",
        "--settings",
        ISOLATION_SETTINGS,
        "--strict-mcp-config",
        "--no-session-persistence",
        "--json-schema",
        roles.load_schema(schema_name),
        "--agents",
        roles.agents_json(role),
        "--agent",
        role.name,
        "--max-budget-usd",
        f"{max_usd:.2f}",
    ] + (["--model", model] if model else [])
    prompt = "Input:\n```json\n" + json.dumps(payload, indent=1, ensure_ascii=False) + "\n```"
    cost = 0.0
    detail = ""
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    for _ in range(2):
        proc = runner(cmd, cwd=cwd, input=prompt, timeout=timeout, check=False)
        raw_path.write_text(proc.stdout, encoding="utf-8")
        try:
            out = json.loads(proc.stdout)
        except json.JSONDecodeError:
            detail = f"unreadable output (exit code {proc.returncode}): {proc.stderr.strip()[:300]}"
            continue
        cost += float(out.get("total_cost_usd") or 0)
        structured = out.get("structured_output")
        if out.get("subtype") == "success" and not out.get("is_error") and isinstance(structured, dict):
            return structured, cost
        detail = f"{out.get('subtype')}: {str(out.get('result'))[:300]}"
    raise BenchError(f"the {role_name} judge failed twice: {detail}")


def batches(items: list[Any], size: int) -> list[list[Any]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


# --- classify ------------------------------------------------------------


def classification_payload(candidates: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "threads": [
            {
                "id": c["id"],
                "kind": c["source"],
                "path": c.get("path"),
                "line": c.get("line"),
                "diff_hunk": "\n".join((c.get("diff_hunk") or "").splitlines()[-40:]),
                "comments": [{"author": m["author"], "body": m["body"][:4000]} for m in c["comments"]],
            }
            for c in candidates
        ]
    }


def merge_classification(
    candidates: list[dict[str, Any]], verdicts: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split candidates into ground-truth findings and excluded threads, with reasons."""
    by_id = {v.get("id"): v for v in verdicts if isinstance(v, dict)}
    truth, excluded = [], []
    for c in candidates:
        verdict = by_id.get(c["id"])
        base = {"id": c["id"], "url": c.get("url", ""), "reviewer": c.get("reviewer")}
        if verdict is None:
            excluded.append({**base, "reason": "no verdict from the classifier"})
        elif not verdict.get("actionable") or verdict.get("kind") not in _ACTIONABLE_KINDS:
            excluded.append({**base, "reason": f"not actionable ({verdict.get('kind')})"})
        elif not verdict.get("resolved_in_favour", True):
            excluded.append({**base, "reason": "refuted in the thread"})
        else:
            truth.append(
                {
                    **base,
                    "path": c.get("path"),
                    "line": c.get("line"),
                    "kind": verdict["kind"],
                    "rule": (verdict.get("rule") or "").strip() or c["comments"][0]["body"][:300],
                    "codifiable": bool(verdict.get("codifiable")),
                    "excerpt": c["comments"][0]["body"][:500],
                }
            )
    return truth, excluded


# --- match ---------------------------------------------------------------


def match_payload(truth: list[dict[str, Any]], findings: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "human_findings": [
            {k: t.get(k) for k in ("id", "path", "line", "kind", "rule", "excerpt")} for t in truth
        ],
        "agent_findings": [
            {k: f.get(k) for k in ("id", "path", "line", "severity", "title", "explanation")} for f in findings
        ],
    }


def filter_matches(
    result: dict[str, Any], truth_ids: set[str], finding_ids: set[str], threshold: float = MATCH_THRESHOLD
) -> list[dict[str, Any]]:
    """Keep confident pairs that refer to real ids, deduplicated and sorted."""
    kept = {}
    for m in result.get("matches") or []:
        if not isinstance(m, dict):
            continue
        pair = (m.get("agent_id"), m.get("human_id"))
        if pair[0] not in finding_ids or pair[1] not in truth_ids:
            continue
        confidence = float(m.get("confidence") or 0)
        if confidence < threshold:
            continue
        if pair not in kept or confidence > kept[pair]["confidence"]:
            kept[pair] = {"agent_id": pair[0], "human_id": pair[1], "confidence": confidence, "reason": m.get("reason", "")}
    return [kept[p] for p in sorted(kept)]


# --- attribute -----------------------------------------------------------


def attribution_payload(skills: list[dict[str, Any]], items: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "skills": [{"name": s["name"], "description": s["description"], "text": s["body"][:8000]} for s in skills],
        "items": items,
    }


def attribution_items(truth: list[dict[str, Any]], unmatched: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items = [
        {"id": t["id"], "source": "human review", "path": t.get("path"), "text": f"{t['rule']}\n\n{t['excerpt']}"}
        for t in truth
    ]
    items += [
        {"id": f["id"], "source": "automated review", "path": f.get("path"), "text": f"{f.get('title')}\n\n{f.get('explanation')}"}
        for f in unmatched
    ]
    return items


def filter_attribution(
    result: dict[str, Any], item_ids: set[str], skill_names: set[str]
) -> dict[str, dict[str, Any]]:
    """Keep verdicts for known items, naming only skills that exist in the snapshot."""
    out = {}
    for entry in result.get("items") or []:
        if not isinstance(entry, dict) or entry.get("id") not in item_ids:
            continue
        covering = sorted({s for s in entry.get("covering_skills") or [] if s in skill_names})
        out[entry["id"]] = {"covering_skills": covering, "codifiable": bool(entry.get("codifiable"))}
    return out
