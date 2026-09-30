---
name: bench-pr
description: Benchmark this project's Claude Code skills against the human review of one pull request. Replays the review headlessly with and without the skills, matches the findings to the reviewers' comments, and reports which skills helped, which were missed, and where no skill exists. Use only when the user asks to benchmark or evaluate skills against a PR.
disable-model-invocation: true
argument-hint: "<owner/repo#N | PR URL | N> [--round N] [--runs N] [--reviewer plain|repo-agent|repo-agent+skills]"
---

# Benchmark skills against a pull request

The script sits next to this skill: `python3 <base directory of this skill>/../../scripts/bench.py`. The base directory is given when the skill loads. Run the script from the root of the project checkout, so that a bare PR number resolves to this repository (or its upstream, for a fork) and the checkout can supply the commits.

1. Parse the arguments. The first is the PR; pass the others through unchanged. If no PR was given, ask for one.
2. Estimate first. Run `bench.py estimate --pr <PR> [options]` and show the user its output: the number of review runs and judge calls, the worst-case cost ceiling, and what their login means for billing. On a subscription login, the runs count against the same usage limits as their interactive work; with an API key they are billed per token. Ask for an explicit yes before continuing.
3. Run `bench.py all --pr <PR> [options]`. It starts several headless Claude Code sessions and usually takes 10 to 40 minutes, so run it in the background and tell the user it has started. Note the run directory it prints. If it stops early, `bench.py resume --run-dir <dir>` continues without repeating finished work.
4. Read `<run dir>/report.md`, and `result.json` for detail. Summarise in a few lines:
   - recall per arm, and what the gap between `at-pr` (the skills as they were at the PR's base) and `none` (no skills) suggests; with few runs, say that it is indicative only;
   - the most actionable fixes, with their links;
   - any invalid runs or notes that change how the numbers should be read.

   Explain a bucket name only when you use it. Say that agent-only findings are unverified: only a person can tell whether they are real problems the reviewers missed.
5. Offer follow-ups, and do only what the user picks:
   - draft a sharper description for a skill with trigger misses, or a more concrete rule for a skill with application misses;
   - draft a new skill for a coverage gap;
   - run again with `--reviewer repo-agent` and with `--reviewer repo-agent+skills`, to see what the project's own review agent gains from being allowed to load skills;
   - benchmark another review round (`--round`) or another PR.

   Present drafts as proposals. Never change the project's skills without explicit approval.

Notes:
- Each replay runs in a sealed temporary workspace: two commits and no remotes, read-only tools, no web access, and only the skills of the chosen snapshot. The plugin's README describes the guarantees and their limits.
- Results go to `skill-bench-results/` in the current directory unless `--out` is given. Session transcripts are kept under the run directory's `raw/` folder, which git ignores.
