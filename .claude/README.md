# Claude Code in this repo

Everything Claude needs is committed here under `.claude/` - the `/work`
command, lifecycle hooks, review agents, skills, and settings. Cloning the
repo is all the setup required; no per-machine configuration.

## The `/work` flow

1. **Clone & go.** Setup is automatic - hooks, skills, agents, and commands
   are versioned in this folder.
2. **Start a remote session** (cloud) in bypass-permissions mode, so Claude
   can run autonomously.
3. **Run `/work <issue-number>`** and have an extensive planning session.
   The command starts in plan mode and won't touch code until you approve the
   plan. Base branch defaults to `next` (`--base <branch>` to override).
4. **Let it work.** Claude implements the plan and opens a **draft** PR when
   it's ready, then hands back to you.

## Guardrails (automatic)

Hooks in `settings.json` enforce quality without prompting, so the autonomous
run stays safe:

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
