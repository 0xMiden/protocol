---
description: Plan and implement a GitHub issue, then open a draft PR (base defaults to next)
argument-hint: <issue-number> [--base <branch>]
allowed-tools: Bash, Read, Edit, Write, Grep, Glob, Task
---

Work on a GitHub issue and open a **draft** PR.

`$ARGUMENTS`: an issue number, plus optional `--base <branch>` (defaults to `next`).

1. Read the issue: `gh issue view <number>`.
2. **Check for existing overlapping work**, per the "Check for duplicate work first" convention in `.claude/CLAUDE.md`. If an open PR already covers part or all of the issue, report it and confirm how to proceed before planning.
3. **Start in plan mode.** Produce an implementation plan and wait for approval before writing any code.
4. After approval: implement per `.claude/CLAUDE.md` (worktree, branch, commit conventions).
5. Open the draft PR against the base branch: `gh pr create --draft --base <branch> --body "Closes #<number> ..."`. Report the PR URL.
