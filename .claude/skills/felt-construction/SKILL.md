---
name: felt-construction
description: Use when constructing a `Felt` from a numeric value in Rust — use checked construction unless the canonical bound is already proved.
---

# Felt Construction From Untrusted Numeric Inputs

## Rule

`Felt::new(x)` is checked and returns `Result`, rejecting values greater than or equal to `Felt::ORDER`. Use it when a `u64` input may exceed the field modulus.

Use one of:

- `Felt::from(x)` where `x` is a `u32` or smaller (infallible).
- `Felt::new(x)` or `Felt::try_from(x)` for `u64` inputs; both return `Result` and check the bound.
- `Felt::new_unchecked(x)` only when `x < Felt::ORDER` has already been proved.

## Why

The field modulus sits just below `2^64`, so out-of-range inputs occupy a narrow band that tests can miss. Checked construction makes those inputs explicit errors; `new_unchecked` skips that protection.

## Examples

```rust
// Good: u32 input, infallible conversion
let f = Felt::from(slot_index as u32);

// Good: untrusted u64 input, checked conversion returning Result
let f = Felt::new(user_value).map_err(|_| Error::FeltOverflow)?;

// Good: unchecked construction only after proving the canonical bound
assert!(bounded_value < Felt::ORDER);
let f = Felt::new_unchecked(bounded_value);

// Bad: unchecked construction on an untrusted value
let f = Felt::new_unchecked(user_value);
```
