"""Deterministic attribution of findings to skills.

Every human finding gets one bucket per run of an arm with skills, and
every agent finding that matched nothing gets one too. The rules only
combine facts recorded earlier: whether the finding was matched, which
snapshot skills cover it, which skills the run listed and loaded, and how
often the no-skills control arm matched it.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

TP_SKILL = "tp-skill-attributable"
TP_BASE = "tp-base-model"
TP_OTHER = "tp-other-context"
TP_NO_CONTROL = "tp-no-control"
FN_NOT_EXPOSED = "fn-not-exposed"
FN_TRIGGER = "fn-trigger-miss"
FN_APPLICATION = "fn-application-miss"
FN_GAP = "fn-coverage-gap"
FN_NOT_CODIFIABLE = "fn-not-codifiable"
UF_SKILL = "unmatched-skill-linked"
UF_OTHER = "unmatched-other"

ORDER = [TP_SKILL, TP_BASE, TP_OTHER, TP_NO_CONTROL, FN_NOT_EXPOSED, FN_TRIGGER, FN_APPLICATION, FN_GAP, FN_NOT_CODIFIABLE, UF_SKILL, UF_OTHER]

MEANING = {
    TP_SKILL: "caught, with a covering skill loaded, and the no-skills control mostly missed it",
    TP_BASE: "caught, but the no-skills control caught it in at least half its runs too",
    TP_OTHER: "caught without a covering skill loaded, and the control mostly missed it",
    TP_NO_CONTROL: "caught, but no no-skills control run was valid, so the skills' part is unknown",
    FN_NOT_EXPOSED: "missed; a skill covers it but was never shown to the reviewer",
    FN_TRIGGER: "missed; a covering skill was shown but not loaded",
    FN_APPLICATION: "missed although a covering skill was loaded",
    FN_GAP: "missed; no skill covers it, though it could be written down as a rule",
    FN_NOT_CODIFIABLE: "missed; a design judgement no skill could reasonably state",
    UF_SKILL: "raised by the agent only, with a covering skill loaded (check the skill for a stale or over-broad rule)",
    UF_OTHER: "raised by the agent only, without a covering skill",
}


def truth_bucket(
    matched: bool,
    covering: set[str],
    codifiable: bool,
    listed: set[str],
    loaded: set[str],
    control_rate: float | None,
) -> str:
    """`control_rate` is the share of no-skills runs that matched; None when none ran."""
    if matched:
        if control_rate is None:
            return TP_NO_CONTROL
        if control_rate >= 0.5:
            return TP_BASE
        return TP_SKILL if covering & loaded else TP_OTHER
    if covering:  # a skill states the rule, whatever the classifier thought of it
        if not covering & listed:
            return FN_NOT_EXPOSED
        if not covering & loaded:
            return FN_TRIGGER
        return FN_APPLICATION
    return FN_GAP if codifiable else FN_NOT_CODIFIABLE


def unmatched_bucket(covering: set[str], loaded: set[str]) -> str:
    return UF_SKILL if covering & loaded else UF_OTHER


def modal(counter: Counter[str]) -> str | None:
    if not counter:
        return None
    return min(counter, key=lambda b: (-counter[b], ORDER.index(b)))


def evaluate(
    truth: list[dict[str, Any]],
    runs: list[dict[str, Any]],
    matches: dict[str, list[dict[str, Any]]],
    attributions: dict[str, dict[str, dict[str, Any]]],
    snapshots: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Bucket every finding and aggregate per arm, per human finding and per skill.

    `runs` are valid run records, `matches` maps run id to its kept pairs,
    `attributions` and `snapshots` are keyed by arm name (arms with skills).
    """
    truth_ids = [t["id"] for t in truth]
    matched_by_run = {r["id"]: {m["human_id"] for m in matches.get(r["id"], [])} for r in runs}
    control = [r for r in runs if r["arm"] == "none"]
    control_rate = {
        t: (sum(t in matched_by_run[r["id"]] for r in control) / len(control)) if control else None for t in truth_ids
    }

    arms: dict[str, dict[str, Any]] = {}
    outcomes: dict[str, dict[str, Any]] = {t: {} for t in truth_ids}
    unmatched: dict[str, list[dict[str, Any]]] = {}
    skills: dict[str, dict[str, dict[str, Any]]] = {}

    for arm in sorted({r["arm"] for r in runs}, key=lambda a: (a == "none", a)):
        arm_runs = [r for r in runs if r["arm"] == arm]
        recall = {r["id"]: (len(matched_by_run[r["id"]]) / len(truth_ids)) if truth_ids else None for r in arm_runs}
        values = [v for v in recall.values() if v is not None]
        summary = {
            "runs": [r["id"] for r in arm_runs],
            "recall": {
                "per_run": recall,
                "mean": round(sum(values) / len(values), 4) if values else None,
                "min": min(values) if values else None,
                "max": max(values) if values else None,
            },
            "findings_per_run": {r["id"]: len(r["findings"]) for r in arm_runs},
            "buckets": {},
        }
        for t in truth_ids:
            outcomes[t][arm] = {"matched_runs": sum(t in matched_by_run[r["id"]] for r in arm_runs), "runs": len(arm_runs)}

        if arm in snapshots:
            attribution = attributions.get(arm, {})
            names = {s["name"] for s in snapshots[arm]["skills"]}
            stats = {s["name"]: _empty_stats(s) for s in snapshots[arm]["skills"]}
            counts: Counter[str] = Counter()
            per_truth: dict[str, Counter[str]] = {t: Counter() for t in truth_ids}
            arm_unmatched = []
            for r in arm_runs:
                tele = r.get("telemetry") or {}
                listed = set(tele.get("listed") or []) & names
                loaded = (set(tele.get("invoked") or []) | set(tele.get("read") or [])) & names
                for name in listed:
                    stats[name]["listed_runs"] += 1
                for name in loaded:
                    stats[name]["loaded_runs"] += 1
                for t in truth:
                    verdict = attribution.get(t["id"], {})
                    covering = set(verdict.get("covering_skills") or []) & names
                    bucket = truth_bucket(
                        t["id"] in matched_by_run[r["id"]], covering, t["codifiable"], listed, loaded, control_rate[t["id"]]
                    )
                    counts[bucket] += 1
                    per_truth[t["id"]][bucket] += 1
                    _count_skill_stats(stats, bucket, covering, listed, loaded)
                matched_findings = {m["agent_id"] for m in matches.get(r["id"], [])}
                for f in r["findings"]:
                    if f["id"] in matched_findings:
                        continue
                    covering = set((attribution.get(f["id"]) or {}).get("covering_skills") or []) & names
                    bucket = unmatched_bucket(covering, loaded)
                    counts[bucket] += 1
                    if bucket == UF_SKILL:
                        for name in covering & loaded:
                            stats[name]["unmatched_linked"] += 1
                    arm_unmatched.append(
                        {"id": f["id"], "path": f.get("path"), "severity": f.get("severity"), "title": f.get("title"), "bucket": bucket, "covering_skills": sorted(covering)}
                    )
            for t in truth:
                covering = sorted(set((attribution.get(t["id"]) or {}).get("covering_skills") or []) & names)
                for name in covering:
                    stats[name]["relevant_findings"] += 1
                outcomes[t["id"]][arm].update(
                    {"buckets": dict(sorted(per_truth[t["id"]].items())), "modal": modal(per_truth[t["id"]]), "covering_skills": covering}
                )
            summary["buckets"] = {b: counts[b] for b in ORDER if counts[b]}
            unmatched[arm] = arm_unmatched
            skills[arm] = stats
        arms[arm] = summary

    return {
        "arms": arms,
        "truth_outcomes": outcomes,
        "unmatched": unmatched,
        "skills": skills,
        "top_fixes": top_fixes(truth, outcomes, skills),
    }


def _empty_stats(skill: dict[str, Any]) -> dict[str, Any]:
    return {
        "listed_runs": 0,
        "loaded_runs": 0,
        "relevant_findings": 0,
        "tp_attributed": 0,
        "trigger_misses": 0,
        "application_misses": 0,
        "not_exposed": 0,
        "unmatched_linked": 0,
        "body_chars": skill.get("body_chars", 0),
        "model_invocable": skill.get("model_invocable", True),
    }


def _count_skill_stats(stats: dict[str, dict[str, Any]], bucket: str, covering: set[str], listed: set[str], loaded: set[str]) -> None:
    if bucket == TP_SKILL:
        for name in covering & loaded:
            stats[name]["tp_attributed"] += 1
    elif bucket == FN_TRIGGER:
        for name in (covering & listed) - loaded:
            stats[name]["trigger_misses"] += 1
    elif bucket == FN_APPLICATION:
        for name in covering & loaded:
            stats[name]["application_misses"] += 1
    elif bucket == FN_NOT_EXPOSED:
        for name in covering:
            stats[name]["not_exposed"] += 1


_FIX_ORDER = ["trigger", "application", "gap", "stale", "exposure"]


def top_fixes(
    truth: list[dict[str, Any]], outcomes: dict[str, dict[str, Any]], skills: dict[str, dict[str, dict[str, Any]]], limit: int = 3
) -> list[dict[str, Any]]:
    """The most actionable changes, ranked by how often the evidence occurred."""
    candidates = []
    arm = "at-pr" if "at-pr" in skills else (sorted(skills)[0] if skills else None)
    if arm is None:
        return []
    for name, s in skills[arm].items():
        if s["trigger_misses"]:
            candidates.append(("trigger", s["trigger_misses"], name, f"`{name}` was shown to the reviewer but not loaded when it applied ({s['trigger_misses']}x): make its description say when to use it in a review, not only when writing code."))
        if s["application_misses"]:
            candidates.append(("application", s["application_misses"], name, f"`{name}` was loaded but the issue it covers was still missed ({s['application_misses']}x): state the rule more concretely, with a check the reviewer can apply to a diff."))
        if s["unmatched_linked"]:
            candidates.append(("stale", s["unmatched_linked"], name, f"`{name}` was loaded when the reviewer raised {s['unmatched_linked']} finding(s) that no human raised: check whether its rule is out of date or too broad."))
        if s["not_exposed"]:
            candidates.append(("exposure", s["not_exposed"], name, f"`{name}` covers missed findings but was never shown to the reviewer ({s['not_exposed']}x): check the reviewer's tools and the skill listing."))
    for t in truth:
        outcome = outcomes[t["id"]].get(arm) or {}
        if outcome.get("modal") == FN_GAP:
            count = (outcome.get("buckets") or {}).get(FN_GAP, 0)
            candidates.append(("gap", count, t["id"], f"No skill covers this {t['kind']} finding: \"{t['rule']}\" ({t['url']})"))
    candidates.sort(key=lambda c: (-c[1], _FIX_ORDER.index(c[0]), c[2]))
    return [{"kind": kind, "count": count, "subject": subject, "text": text} for kind, count, subject, text in candidates[:limit]]
