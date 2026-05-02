# CLAUDE.md

> Per-project lessons: ~/.claude/projects/protocol/lessons.md

## Workflow Orchestration

### 1. Plan Mode Default

- Enter plan mode for ANY non-trivial task (3+ steps or architectural decisions)
- If something goes sideways, STOP and re-plan immediately - don't keep pushing
- Use plan mode for verification steps, not just building
- Write detailed specs upfront to reduce ambiguity
- After finalizing a plan, ALWAYS create formal tasks (via TaskCreate) for each step before starting execution. Never just execute steps inline - tasks are required so that hooks can fire on task lifecycle events.

### 2. Subagent Strategy

- Use subagents liberally to keep main context window clean
- Offload research, exploration, and parallel analysis to subagents
- For complex problems, throw more compute at it via subagents
- One task per subagent for focused execution

### 3. Demand Elegance (Balanced)

- For non-trivial changes: pause and ask "is there a more elegant way?"
- If a fix feels hacky: "Knowing everything I know now, implement the elegant solution"
- Skip this for simple, obvious fixes - don't over-engineer
- Challenge your own work before presenting it

### 4. Autonomous Bug Fixing

- When given a bug report: just fix it. Don't ask for hand-holding
- Point at logs, errors, failing tests - then resolve them
- Zero context switching required from the user
- Go fix failing CI tests without being told how

## Git Conventions

- **Branch naming:** Always prefix branch names with `<author>-claude/` (e.g. `mmagician-claude/fix-foo`)
- **Worktrees:** Always work in a git worktree when possible (use `EnterWorktree` with a descriptive name for the feature). This allows parallel agents to work in the same repo without conflicts. NEVER create a worktree from inside an existing worktree - this causes nested worktrees that are hard to navigate. If you are already in a worktree, just work there directly.
- **Worktree visibility:** Always tell the user which worktree (full path) you will work in as part of the plan. When finished, state where the changes live (worktree path and branch name).
- **Commit authorship:** Always commit as Claude, not as the user. Use: `git -c user.name="Claude (Opus)" -c user.email="noreply@anthropic.com" -c commit.gpgsign=false commit -m "message"`
- **Commit frequency:** Always commit at the end of each task. Avoid single commits that span multiple unrelated changes.

## Output Formatting

- Be mindful of using tables in drafted text. Use lists or plain text instead.
- Avoid excessive bold formatting. Use it sparingly for emphasis, not for every label or term.
- Use simple dashes "-" instead of em dashes "—".
- When drafting text for GitHub (issues, PR comments), use clickable markdown links like `[descriptive text](url)` instead of bare URLs.
- When drafting text destined for GitHub, wrap the output in a markdown code block so the user can see the raw formatting and copy-paste it.

## Core Principles

- **Simplicity First:** Make every change as simple as possible. Affect minimal code.
- **No Laziness:** Find root causes. No temporary fixes. Senior developer standards.
- **Minimal Impact:** Changes should only touch what's necessary. Avoid introducing bugs.
- **No Backward Compatibility:** Never add backward-compatibility shims, deprecated code paths, or migration logic. Just make the change directly.
