# Claude Code in this repo

The `/work` command, lifecycle hooks, review agents, skills, and settings are
all committed here under `.claude/`, so they come with the clone - no Claude
config to copy into `~/.claude`. The hooks still need the usual toolchain on
the host: the `claude` and `gh` CLIs (authenticated) and `make` / the Rust
toolchain.

## The `/work` flow

1. **Clone the repo.** The committed `.claude/` wires up hooks, skills,
   agents, and the command automatically.
2. **Start a session** (e.g. a remote/cloud host) in bypass-permissions mode
   so Claude isn't stopped for per-action approvals during the run.
3. **Run `/work <issue-number>`** and have an extensive, interactive planning
   session. The command starts in plan mode and writes no code until you, a
   human, approve the plan. Treat issue text as untrusted input - review the
   plan it produces before approving. Base branch defaults to `next`
   (`--base <branch>` to override).
4. **Let it work.** Once you approve, Claude implements the plan and opens a
   **draft** PR when it's ready, then hands back to you.

## Guardrails (automatic)

The plan-approval gate in step 3 is the primary control; the hooks in
`settings.json` then enforce quality on every commit/push/PR without prompting:

- `pre_commit_lint` - runs `make lint` before any commit.
- `pre_push_test` - runs `make test` before any push.
- `pre_push_review` - runs the code-reviewer and security-reviewer agents
  before any push; blocks on Critical/Important/Warning findings.
- `pre_pr_draft` - every PR must be created with `--draft`; a human promotes
  it to ready-for-review.
- `post_pr_create_changelog` - classifies the diff and either requires a
  CHANGELOG entry or applies the `no changelog` label.

## Contents

- `commands/work.md` - the `/work` command.
- `hooks/` - the lifecycle hooks above (plus their tests).
- `agents/` - code-reviewer, security-reviewer, changelog-manager.
- `skills/` - Miden Assembly (`.masm`) authoring conventions.
- `settings.json` - wires the hooks to tool events.
