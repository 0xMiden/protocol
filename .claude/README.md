# Claude Code in this repo

The `/work` command, lifecycle hooks, review agents, skills, and settings are
all committed here under `.claude/`, so they come with the clone - no Claude
config to copy in. The hooks need the usual toolchain on the host: Python 3,
the `claude` and `gh` CLIs (authenticated), and `make` / the Rust toolchain.

## The `/work` flow

1. **Clone the repo.** The committed `.claude/` wires up hooks, skills,
   agents, and the command automatically.
2. **Start a session** (e.g. a remote/cloud host) in bypass-permissions mode
   so Claude isn't stopped for per-action approvals.
3. **Run `/work <issue-number>`** and plan it out together. The command starts
   in plan mode and writes no code until you approve. Base defaults to `next`
   (`--base <branch>` to override).
4. **Let it work.** Claude implements the plan and opens a **draft** PR when
   it's ready.

## Guardrails

Hooks in `settings.json` enforce quality at the commit, push, and PR boundaries:

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
