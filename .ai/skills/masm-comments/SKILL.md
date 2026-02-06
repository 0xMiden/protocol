---
name: masm-comments
description: Enforce commenting conventions for Miden Assembly (.masm) files. Use when editing, reviewing, or creating .masm files.
---

# MASM Commenting Conventions

## Rules

### 1. Inline comments start lowercase

Inline comments (single `#`) should begin with a lowercase letter.

```masm
# good: lowercase start
exec.native_account::remove_asset
# => [ASSET, note_idx, pad(11)]

# Bad: uppercase start (avoid)
# Remove the asset from the account
```

### 2. Don't over-comment obvious operations

Only add comments that provide value. Skip comments for self-explanatory operations.

**Skip comments for:**
- Simple arithmetic: `add`, `sub`, `mul`, `div`
- Basic stack ops when context is clear: `drop`, `swap`, `dup`
- Standard control flow: `if.true`, `while.true`, `end`

**Do comment:**
- Stack state after complex operations: `# => [ptr, ASSET, end_ptr]`
- Purpose of a code block: `# compute the pointer at which we should stop iterating`
- Non-obvious logic or business rules
- TODO items and references to external specs

## Examples

**Good:**

```masm
# remove the asset from the account
exec.native_account::remove_asset
# => [ASSET, note_idx, pad(11)]

dupw dup.8 movdn.4
# => [ASSET, note_idx, ASSET, note_idx, pad(11)]

exec.output_note::add_asset
# => [ASSET, note_idx, pad(11)]
```

**Avoid:**

```masm
# Swap the top two elements
swap  # swap

# Drop the word
dropw  # drops 4 elements
```

## Doc comments

Procedure documentation uses `#!` prefix (this rule only applies to inline `#` comments):

```masm
#! Adds the provided asset to the active account.
#!
#! Inputs:  [ASSET, pad(12)]
#! Outputs: [pad(16)]
pub proc receive_asset
    ...
end
```
