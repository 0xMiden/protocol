---
name: felt-construction
description: Use when constructing a `Felt` from a numeric value in Rust — never call `Felt::new(value)` on values that may exceed the field modulus; use `Felt::from(u32)` (infallible) or `Felt::try_from(u64)` (checked) instead.
---

# Felt Construction From Untrusted Numeric Inputs

## Rule

Do not call `Felt::new(x)` when `x` could exceed the field modulus. `Felt::new` silently truncates oversized values, which produces a valid-looking `Felt` that no longer equals the original input — a classic source of hard-to-attribute bugs.

Use one of:

- `Felt::from(x)` where `x` is a `u32` or smaller (infallible).
- `Felt::try_from(x)` for `u64`-and-larger inputs, returning `Result`.
- An explicit `assert!(x < Felt::MODULUS)` before `Felt::new(x)` if you have already proven the bound.

## Why

The field modulus is just below `2^64`, so the truncation only kicks in for a narrow band of large values. Most tests pass; production hits one of the bad inputs and the symptom is a value mismatch many layers away from the truncating call.

`Felt::from(u32)` cannot truncate. `Felt::try_from(u64)` makes the bound check explicit and forces the caller to handle the error.

## Examples

```rust
// Good: u32 input, infallible conversion
let f = Felt::from(slot_index as u32);

// Good: untrusted u64 input, checked conversion
let f = Felt::try_from(user_value).map_err(|_| Error::FeltOverflow)?;

// Bad: silent truncation on any value >= MODULUS
let f = Felt::new(user_value);
```

## Evidence

- PR #2546 (PhilippGackstatter): "Avoid Felt::new on values that may exceed the field modulus; silent truncation can introduce hard-to-find bugs."
- PR #2439 (PhilippGackstatter): "Use Felt::from on u32 inputs instead of Felt::new."
- PR #2636 (PhilippGackstatter): "Use Felt::try_from for u64 inputs so we surface modulus overflow."
- PR #2712 (PhilippGackstatter): "Felt::new on a user value is unsafe — switch to try_from."
- PR #1925 (PhilippGackstatter): "Felt::new can truncate here; use the checked variant."
