---
name: assert-specific-error-in-tests
description: Use when writing a Rust test that exercises a failure path or a MASM test that expects a `panic` / `assert` — assert on the specific expected error variant or error code.
---

# Negative Tests Must Pin the Expected Error

## Rule

A test that exercises an error path must assert on the specific error returned:

- In Rust: use `assert_matches!(result, Err(MyError::SpecificVariant { .. }))` or destructure the error and assert on its fields. Don't accept "any `Err`" via `assert!(result.is_err())`.
- In MASM: assert that the trapping error code matches the expected `ERR_*` constant, not just that the transaction failed.

If multiple error conditions could plausibly fire on the same input, assert on the one this test is actually exercising.

## Why

A test that only checks `is_err()` passes even when an unrelated bug breaks the function, so it no longer validates the failure mode it claims to. Pinning the exact variant also catches reorderings where one error path starts firing instead of another.

## Examples

```rust
// Good
use assert_matches::assert_matches;

let result = AccountId::try_from(&bytes);
assert_matches!(result, Err(AccountError::InvalidLength { expected: 32, got: 5 }));

// Bad
let result = AccountId::try_from(&bytes);
assert!(result.is_err());
```

```rust
// Good (MASM test)
let err = run_kernel(...).unwrap_err();
assert_eq!(err.code(), ERR_NOTE_NOT_FOUND);

// Bad
assert!(run_kernel(...).is_err());
```
