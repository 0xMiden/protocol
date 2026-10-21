---
name: respect-manual-pr-edits
description: Use when editing or updating a GitHub pull request or issue body, or a PR title, that a person may have rewritten - fetch the live text first and preserve the manual changes.
---

# Respect Manual Edits to PR and Issue Text

## Rule

Once a person has edited a PR or issue description on GitHub, that live text is the source of
truth. Later edits build on it and keep the person's structure, wording, headings and
omissions. Never re-amend from the draft you originally wrote, restore a section they removed,
or re-expand text they trimmed.

## Procedure

1. Fetch the live body immediately before editing:
   `gh pr view <n> --json body --jq .body` (or `gh issue view <n> --json body --jq .body`).
2. Diff it against what you last wrote. Treat every difference as a deliberate human edit.
3. Make only the targeted edits the situation requires, such as a fact the code no longer
   matches or a link that moved. Fix the specific sentence rather than replacing the body.
4. Apply the same discipline to PR titles.

## Why

A reviewer who rewrites a description has already decided what the reader needs. Overwriting
it discards that decision and forces them to redo the work after every push.

## Example

**Avoid** (the person cut the body to a summary and a notes list; the update replaces it with
the original draft):

```markdown
## Summary
...
## Changes
- five bullets restored from the first draft
## Open questions
- section the person had removed
```

**Good** (same live body, one sentence corrected because the code changed):

```markdown
## Summary
...
## Notes
- The zero-price test now also covers three network notes.
```
