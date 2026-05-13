---
name: masm-named-literals
description: Use when writing or editing MASM procedures or Rust modules that contain numeric literals for memory offsets, slot indices, sizes, tag/type/protocol values, or domain constants — promote them to named constants in a single source-of-truth location.
---

# Replace Magic Numbers with Named Constants

## Rule

Numeric literals embedded inline in MASM and Rust code must be promoted to named constants when they represent:

- Memory offsets, slot indices, or layout sizes
- Protocol/tag/type/version discriminants
- Domain values reused in more than one place

Define each constant exactly once. In MASM, declare it in the file's `CONSTANTS` section (see `masm-constants` skill). In Rust, define it as an associated constant on the type it describes (`Type::CAPACITY`, not a free-floating `const CAPACITY`).

## Why

A bare `47` or `0x1234` in code is invisible to grep, indistinguishable from coincidental same-valued numbers, and risks drift when one occurrence is updated and another is missed. Naming the literal documents intent and gives refactors a single source of truth.

## Examples

```masm
# Good
const ACCOUNT_DATA_PTR = 4
mem_load.ACCOUNT_DATA_PTR

# Bad
mem_load.4   # what is at offset 4?
```

```rust
// Good
impl AccountStorage {
    pub const MAX_NUM_STORAGE_SLOTS: usize = 255;
}

// Bad
if slots.len() > 255 { ... }   // 255 also appears unrelated elsewhere
```

## Evidence

- PR #2390 (PhilippGackstatter): "Replace magic numbers in MASM with named constants."
- PR #2257 (bobbinth): "Define recurring magic numbers (protocol/tag/type values) as named constants in a single central location, not inline literals."
- PR #2871 (PhilippGackstatter): "We should use a named constant here rather than the literal."
- PR #2730 (bobbinth): "It would be good to have a constant for this value."
- PR #2670 (PhilippGackstatter): "Let's name this rather than using the literal."
