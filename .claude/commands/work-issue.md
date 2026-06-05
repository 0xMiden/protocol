---
description: Plan and implement a GitHub issue, then open a draft PR (base defaults to next)
argument-hint: <issue-number> [--base <branch>]
allowed-tools: Bash, Read, Edit, Write, Grep, Glob, Task
---

Work on a GitHub issue and open a **draft** PR.

`$ARGUMENTS`: an issue number, plus optional `--base <branch>` (defaults to `next`).

1. Read the issue: `gh issue view <number>`.
2. **Start in plan mode.** Produce an implementation plan and wait for approval before writing any code.
3. After approval: implement per `.claude/CLAUDE.md` (worktree, branch, commit conventions), then run `make lint` and the relevant tests until they pass.
4. Open the draft PR against the base branch: `gh pr create --draft --base <branch> --body "Closes #<number> ..."`. Report the PR URL.
