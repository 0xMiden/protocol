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
6. **Set up base auto-sync.** Create a scheduled cloud routine (via the `schedule` skill) named
   `sync-pr-<number>-base`, running **every 2 hours** against this repository, with this prompt
   (substitute the PR number, head branch, and base branch):

   > Check PR #<number> in this repository (head `<head-branch>`, base `<base>`). If the PR is
   > merged or closed, or was opened more than 48 hours ago, delete this routine and stop. If
   > the PR has no merge conflicts with its base (`mergeable` is not CONFLICTING), do nothing.
   > Otherwise merge the base into the PR branch and resolve the conflicts, run `make lint`
   > and the test suites relevant to the changed crates, and push the merge only if everything
   > passes. If a conflict or failure cannot be resolved confidently, push nothing and comment
   > on the PR describing what blocked the sync.

   Report the routine name alongside the PR URL so the user can find it at
   claude.ai/code/routines. If routine creation fails (e.g. no scheduling available in this
   environment), say so and continue - the PR itself is the deliverable.
