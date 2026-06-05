---
name: checked-arithmetic
description: Use when writing Rust arithmetic on amounts, balances, supplies, or other quantities derived from external/user input — use `checked_*` or `overflowing_*` operations and handle the overflow flag explicitly.
---

# Checked Arithmetic on User-Supplied Values

## Rule

Any arithmetic where one or more operands originates from external input (transaction body, advice provider, user RPC, deserialized payload) must use checked or overflowing arithmetic and surface the overflow:

- Prefer `checked_add` / `checked_sub` / `checked_mul` and return an error on `None`.
- Use `overflowing_add` / `widening_mul` when you need the wrapping value *and* the overflow flag; then `assert!(!overflow)` (or branch) before using the result.
- Do not use the default `+`, `-`, `*` operators on untrusted values in release builds — debug-only overflow checks are not enough.

## Why

The default `+`, `-`, `*` operators wrap silently in release builds. An overflow on a balance or asset amount then yields a wrong value with no error — a sum or product that wraps to a number the caller never intended. Checked and overflowing operations surface the overflow so it can be rejected.

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
