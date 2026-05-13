---
name: checked-arithmetic
description: Use when writing Rust arithmetic on amounts, balances, supplies, or other quantities derived from external/user input — use `checked_*` or `overflowing_*` operations and handle the overflow flag explicitly; do not rely on wrapping semantics for untrusted values.
---

# Checked Arithmetic on User-Supplied Values

## Rule

Any arithmetic where one or more operands originates from external input (transaction body, advice provider, user RPC, deserialized payload) must use checked or overflowing arithmetic and surface the overflow:

- Prefer `checked_add` / `checked_sub` / `checked_mul` and return an error on `None`.
- Use `overflowing_add` / `widening_mul` when you need the wrapping value *and* the overflow flag; then `assert!(!overflow)` (or branch) before using the result.
- Do not use the default `+`, `-`, `*` operators on untrusted values in release builds — debug-only overflow checks are not enough.

## Why

Default arithmetic on `u64`/`u128` wraps in release. Two amounts that fit individually can multiply to overflow, producing a fungible-asset amount that is silently far smaller than the user intended. Checked arithmetic forces the caller to acknowledge the overflow path; wrapping arithmetic hides it.

## Examples

```rust
// Good: checked
let total = balance.checked_add(amount).ok_or(Error::Overflow)?;

// Good: overflowing with explicit flag check
let (product, overflow) = a.widening_mul(b);
if overflow { return Err(Error::Overflow); }

// Bad: wraps on overflow in release
let total = balance + amount;
```

## Evidence

- PR #2636 (PhilippGackstatter): "Use checked or overflowing arithmetic (overflowing_add, widening_mul) on user-supplied amounts and assert the overflow flag rather than relying on wrapping semantics."
- PR #2712 (PhilippGackstatter): "This addition can overflow on user input — use checked_add and handle the None case."
- PR #1654 (bobbinth): "We should use checked arithmetic here."
