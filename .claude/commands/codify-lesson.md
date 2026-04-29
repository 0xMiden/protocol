---
description: Append a lesson learned from a PR review to .claude/lessons.md and propose a promotion path.
argument-hint: <one-line description of the lesson>
allowed-tools: Read, Edit, Bash(git:*), Bash(gh:*), Bash(date:*)
---

You are codifying a lesson from a recent code review or production incident so that future sessions on this project do not repeat the mistake. Be precise and brief. Lessons that take more than six lines to express probably belong in a hook or in CLAUDE.md, not here.

User input: $ARGUMENTS

If $ARGUMENTS is empty, ask the user for the lesson and stop. Do not invent one.

## Steps

### 1. Determine source

Run, in this order:

    git rev-parse --short HEAD
    git branch --show-current

If `gh` is available, also run:

    gh pr view --json number,url --jq '"#" + (.number|tostring) + " " + .url' 2>/dev/null

Use the PR link if one is returned. Otherwise use the short commit SHA. Get the date with `date -u +%Y-%m-%d`.

### 2. Classify

Pick exactly one category. Re-read the section headers in `.claude/lessons.md`:

- **Conventions** — naming, formatting, vocabulary, file layout, doc style
- **Architecture** — module boundaries, abstraction choices, API design
- **Testing** — what to test, fixtures, regression patterns, coverage gaps
- **Security & Safety** — validation, auth, data handling, error paths, panics, resource limits
- **Process** — workflow, commits, PRs, CI, review etiquette, branch naming

If the lesson genuinely spans two categories, split it into two lessons. Do not file under multiple sections.

### 3. Format the entry

Use exactly this template. Each field is one sentence. No em dashes; use `-` instead.

    ### YYYY-MM-DD: <short imperative title>
    - **Trigger:** <one sentence: when does this situation come up?>
    - **Rule:** <one sentence: imperative form, "Do X" or "Never do Y">
    - **Why:** <one sentence: what breaks if you ignore it?>
    - **Source:** <PR link or commit SHA>

### 4. Append to lessons.md

Read `.claude/lessons.md`. Find the matching `## ` section. Append the entry at the end of that section, immediately before the next `## ` header (or at end of file if it is the last section). If the section currently contains the placeholder `_(no entries yet)_`, replace it with the entry; otherwise add a blank line before the new entry.

Do not edit any other section.

### 5. Propose a promotion path

After the edit, output a recommendation. Pick exactly one and justify in one sentence:

- **Keep as lesson** — when the rule needs human judgment to apply (e.g., "prefer composition over inheritance for new domain types"). No further action.
- **Promote to hook** — when the rule can be mechanically checked from a script (e.g., "all migrations must include a down.sql"). Draft the hook. If the hook is under 30 lines of bash, write it to `.claude/hooks/<descriptive-name>.sh` and print the matching `.claude/settings.json` entry as a code block for the user to paste. Do NOT modify settings.json yourself.
- **Promote to CLAUDE.md** — when the rule is a global, always-on instruction (e.g., "never use em dashes"). Print the exact line and the section it belongs in as a unified diff against the current CLAUDE.md. Do NOT apply the edit yourself.

If you propose promotion to a hook or CLAUDE.md, also note that the lesson should be removed from `lessons.md` once the promotion lands, with a one-line marker like `(promoted to .claude/hooks/foo.sh on YYYY-MM-DD)` left in place.

### 6. Hand off

Show the user:
1. The exact text appended to lessons.md
2. The promotion recommendation and any draft hook or CLAUDE.md diff
3. A reminder to commit the change (do not auto-commit; the user may want to bundle it with related work)

## Constraints

- Touch only `.claude/lessons.md` without explicit user confirmation. Hooks and CLAUDE.md edits are proposals, not actions.
- Keep entries to the four-bullet template. If the rule needs more nuance, that is the signal to promote it.
- If a near-duplicate of the proposed lesson already exists in lessons.md, point it out and ask whether to merge, supersede, or skip rather than appending a redundant entry.
