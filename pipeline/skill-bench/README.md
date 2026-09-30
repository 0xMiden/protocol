# skill-bench

skill-bench measures how well a project's Claude Code skills serve a real code review. It takes a pull request that people have already reviewed, and replays that review headlessly: with the project's skills as they were at the time, and without any skills. It then matches the agent's findings to the comments the human reviewers left, and works out, finding by finding, whether a skill helped, was missed, or does not exist yet.

The result is a per-PR report that answers practical questions:

- Did the reviewer find what the maintainers found, and did the skills make a difference compared with no skills?
- Which skills were shown to the model but never loaded when they applied? (Their descriptions probably do not say when to use them in a review.)
- Which skills were loaded, yet the issue they cover was still missed? (Their rules are probably too vague.)
- Which findings does no skill cover? (Candidates for new skills.)
- Which skills were loaded when the agent raised findings that no human raised? (Their rules may be out of date or too broad.)

It is packaged as a Claude Code plugin with one skill, `/skill-bench:bench-pr`, and a command-line tool, `scripts/bench.py`, that does the work and also runs without a Claude session.

## How a run works

A run replays one *review round* of one PR. A round is a commit that someone other than the author reviewed; rounds are numbered by the time of their first review (`--round`, default 1). Each stage writes files into a run directory and can be re-run on its own:

1. `fetch` reads the PR's reviews, review threads and changed files from GitHub. The threads started on the round's commit, and the non-empty bodies of the reviews submitted on it, become candidate findings. Threads by the PR author and by bots are left out, with the reason recorded.
2. `replay` builds a sealed workspace for every *arm*, then runs the review there `--runs` times per arm. Each run is a separate headless `claude -p` session.
3. `classify` has a judge model keep the actionable threads whose point was not refuted in the thread. These are the ground truth. Each gets a severity, a one-sentence general rule, and whether that rule could be written down for other changes.
4. `match` has a judge decide which agent findings of each run raise the same issue as a human finding.
5. `attribute` has a judge decide which of the arm's skills state the rule behind each human finding and each unmatched agent finding.
6. `report` puts every finding into a bucket using fixed rules, and writes `result.json` and `report.md`.

Only the semantic questions in steps 3 to 5 go to a model. The bucket a finding lands in is decided by code, from recorded facts.

The match and attribute stages store a digest of each judge call's input, and redo only the calls whose input changed. After `classify` or `telemetry` is run again, running `match` and `attribute` refreshes exactly the results that depend on it. The report flags any judge result that is out of date.

### Arms

- `at-pr`: the project's `.claude/` as it was at the base commit of the change, including its skills.
- `none`: the same, without the skills directory. This is the control arm: everything else is identical.
- `ref:<sha>`: the base `.claude/`, with the skills directory taken from another commit. Use it to compare skill snapshots, for example today's skills against those at the time of the PR.

### Reviewer modes

- `plain` (default): skill-bench's own generic reviewer, `roles/reviewer.md`. It asks for a senior maintainer's review with at most 10 structured findings, and deliberately does not mention skills.
- `repo-agent`: the project's own review agent (`--repo-agent`, default `code-reviewer`), exactly as the project defines it. If that agent's `tools:` list leaves out the Skill tool, it is shown no skills at all, and the report shows what that costs.
- `repo-agent+skills`: the same agent with the Skill tool added.

## Isolation guarantees

A replay must see the code under review and the chosen skills, and nothing else. In particular, it must not see how the pull request continued. For that reason:

- The workspace is a fresh git repository with exactly two commits, the base of the change and the reviewed state, and no remotes. `.claude/` is left out of both commits and placed back, untracked, as the arm's snapshot. Changes the PR itself made under `.claude/` are therefore not part of the replayed diff; this is recorded as a deviation.
- Workspaces are created in a directory outside any project (the system temp directory by default). The tool refuses a location with `CLAUDE.md`, `.claude/` or `.git` in a parent directory, because Claude Code would pick up context from there.
- Each run is its own `claude -p` process with:
  - `--setting-sources project` and `syncClaudeAiSkills: false`, so user-level and account-synced skills are not loaded;
  - `--strict-mcp-config`, so no MCP servers start;
  - tools limited to `Read`, `Grep`, `Glob`, `Skill` and Bash, with only `Skill` pre-approved. Claude Code's own checks allow file reads and read-only shell and git commands (such as `ls`, `head`, `git diff HEAD~1 HEAD`, `git log`, `git show` or `git status`) inside the working directory, and a headless session denies everything that needs approval. That includes reads of any path outside the workspace, whether by the file tools, by shell commands, or by `git -C` and `git diff --no-index`, and git's write options such as `--output=<file>`. Nothing else is pre-approved on purpose: a pre-approved `Read` opens any path on the machine, and a prefix rule such as `Bash(git log:*)` would also match write forms of the command. Web tools are not available at all.
- Hooks and project-enabled plugins are removed from the workspace settings, so a replay runs no project code.
- Runs are separate processes rather than subagents, because a subagent inherits its parent session's skill listing and working directory.

Each run is also checked, not just configured:

- An *exposure check* compares the skills listed to the model, read from the session transcript, with the arm's snapshot. First, a calibration run in an empty project measures the skills that Claude Code itself lists (bundled skills such as `code-review`), because those appear in every arm. Any other skill from outside the snapshot makes the run invalid, and invalid runs are excluded from the results. Snapshot skills missing from the listing are reported.
- Absolute paths outside the workspace that the reviewer read or named in a shell command are listed in the report.

Pull request content is untrusted input. The reviewed code and the review comments can contain text that tries to steer a model. The reviewer is confined as described above. The judge sessions run with no tools at all, in an empty directory, and their answers are checked against a schema, with unknown ids and skill names dropped. Injected text can therefore bias the numbers of the run it appears in, but it cannot read or change anything. Tree extraction uses tarfile's safe filter, so a hostile repository cannot plant links that point outside the workspace.

Limits: the isolation relies on Claude Code's permission checks, verified against Claude Code 2.1.280. A later version could behave differently, which is why every run also records attempted outside paths and denied tool calls. Replays use today's model and today's Claude Code, so they show how the historical skills perform now, not how an agent behaved at the time.

## Buckets

For each run of an arm with skills:

- `tp-skill-attributable`: caught, with a covering skill loaded, and the no-skills control missed it in most of its runs.
- `tp-base-model`: caught, but the control caught it in at least half its runs too, so the skills get no credit.
- `tp-other-context`: caught without a covering skill loaded, and the control mostly missed it.
- `tp-no-control`: caught, but no run of the no-skills control arm was valid, so what the skills contributed is unknown. The report says so, and no skill gets credit.
- `fn-not-exposed`: missed; a skill covers it, but the reviewer was never shown that skill.
- `fn-trigger-miss`: missed; a covering skill was shown but not loaded.
- `fn-application-miss`: missed, although a covering skill was loaded.
- `fn-coverage-gap`: missed; no skill covers it, though it could be written down as a rule.
- `fn-not-codifiable`: missed; no skill covers it, and it is a design judgement that no skill could reasonably state.

When a skill covers a missed finding, the first three miss buckets apply, even if the classifier judged the rule not codifiable.
- `unmatched-skill-linked`: raised by the agent only, with a covering skill loaded.
- `unmatched-other`: raised by the agent only, without a covering skill.

"Loaded" means the skill was invoked through the Skill tool, or its files were read. Reads of skill files that the PR itself modifies do not count. The report also ranks the three most actionable fixes, by how often the evidence occurred.

## Usage

Requirements: Python 3.12, or 3.10.12 / 3.11.4 or newer (standard library only, with tarfile's safe extraction filter), git 2.28 or newer, the GitHub CLI `gh` (logged in), and Claude Code (developed against 2.1.280).

### From Claude Code

Load the plugin and invoke the skill from the root of the project checkout:

```
claude --plugin-dir pipeline/skill-bench
> /skill-bench:bench-pr 0xMiden/protocol#3713 --round 3
```

The skill shows the estimate, asks for confirmation, runs the pipeline in the background, and then summarises the report.

### From the command line

```
python3 pipeline/skill-bench/scripts/bench.py estimate --pr 0xMiden/protocol#3713 --round 3
python3 pipeline/skill-bench/scripts/bench.py all --pr 0xMiden/protocol#3713 --round 3
python3 pipeline/skill-bench/scripts/bench.py resume --run-dir skill-bench-results/0xMiden-protocol-3713/<stamp>
```

A PR can be given as `owner/repo#N`, as a PR URL, or as a bare number. A bare number resolves to the current checkout's repository, or to its parent if the checkout is a fork. Useful options, all recorded in the run's `config.json`:

- `--round N`: the review round to replay (default 1). `fetch` lists every round, with its reviewers and thread count, in `pr.json`.
- `--arms at-pr,none`: the arms to run. Add `ref:<commit, branch or tag>` to compare another skill snapshot; it is pinned to a full SHA when the run is created, so a resumed run uses the same snapshot.
- `--runs N`: runs per arm (default 2). Agent output varies from run to run, so more runs give steadier numbers.
- `--reviewer plain|repo-agent|repo-agent+skills`, and `--repo-agent NAME`.
- `--model M` for the reviews, and `--judge-model M` for the judge (default `opus`).
- `--max-usd-per-review X` (default 3.00) and `--max-usd-per-judge X` (default 1.00): per-session cost ceilings.
- `--source-repo PATH`: a local clone that has the PR's commits. By default the current checkout is used when it has them; otherwise the needed commits are fetched into a bare mirror under `~/.cache/skill-bench/`.
- `--work-dir PATH`: where workspaces are built; it must be outside any project.

Every stage is also a command of its own (`fetch`, `replay`, `classify`, `match`, `attribute`, `report`, `telemetry`). `workspace --run-dir DIR` builds the replay workspaces and leaves them in place, so you can inspect exactly what a reviewer sees. `render-role NAME` prints a role in the form passed to Claude Code.

## Output

A run directory (by default `skill-bench-results/<owner>-<repo>-<pr>/<UTC stamp>/`) holds:

- `config.json`: the options of the run;
- `pr.json`: PR metadata, review rounds, candidate findings, and excluded threads;
- `environment.json`: the Claude Code version, and the login method (authentication kind and subscription type only);
- `builtins.json`: the skills Claude Code lists in an empty project;
- `snapshots/<arm>.json`: the skills, commands and agents of each arm's snapshot, and the deviations;
- `runs/<arm>.<n>.json`: findings, skill telemetry, exposure check, denied tool calls, cost and duration for each run;
- `truth.json`, `matches/<run>.json` and `attribution/<arm>.json`: the judge results;
- `result.json` and `report.md`: the outcome;
- `raw/`: session streams, transcripts and raw judge output. The directory carries its own `.gitignore`, so it is never committed by accident.

Claude Code also keeps its own copy of every replay session in its session history (`~/.claude/projects/`, in directories named after the temporary workspaces). Delete those directories if you do not want the replays in your history.

## Cost and authentication

Every run and judge call is a Claude Code session on your current login.

- On a claude.ai subscription, sessions count against the same usage limits as your interactive use, not per-token billing.
- With `ANTHROPIC_API_KEY` set, they are billed per token to that key.

`estimate` prints the number of sessions and a worst-case ceiling (each session is capped with `--max-budget-usd`). The report lists the estimated cost that Claude Code reports, which is an API-list-price estimate on a subscription. For large batches or CI, use an API key with its own spending limit, so that benchmarks do not use up anyone's interactive quota.

## Limitations

- The ground truth is what reviewers wrote down. Reviewers miss things, so recall is a lower bound, and agent-only findings need a person to judge whether they are real.
- A skill that works at coding time prevents a defect, and a prevented defect leaves no review comment. A review replay cannot credit that prevention. Use it to judge how well skills support reviewing, and to find gaps and stale rules.
- Matching and attribution come from a judge model. Their raw output is kept under `raw/` so it can be audited.
- A single PR gives few findings, so treat per-PR numbers as indicative, and look at several PRs before drawing conclusions about a skill.
- Session transcripts are an internal Claude Code format and can change between versions. The version is recorded with every run, and `telemetry` re-parses stored transcripts after a parser change.

## Development

```
cd pipeline/skill-bench
python3 -m unittest discover -s tests
```

The unit tests need `git`, but no network or model access. The modules are in `scripts/skillbench/`, the model roles in `roles/`, and their output schemas in `schemas/`.
