---
name: masm-error-constants
description: Use when adding or editing MASM `assert*` / `panic` instructions — define an `ERR_<NAME>` constant with a descriptive string message and use it via `assert.err=ERR_NAME`.
---

# MASM Error Constants

## Rule

Every MASM assertion must carry a descriptive error code:

```masm
assert.err=ERR_NOTE_NOT_FOUND
assert_eqw.err=ERR_COMMITMENT_MISMATCH
```

The error constant must:

- Use the `ERR_` prefix.
- Live in the file's dedicated errors section (see `masm-constants` skill).
- Have a descriptive string value, not a bare numeric code: `const ERR_NOTE_NOT_FOUND = "note not found"`.
- Be unique per distinct failure condition — do not share one `ERR_` across two unrelated asserts.

## Why

Bare `assert` instructions trap with the generic "assertion failed" message, giving the debugger no signal about which check failed. A descriptive `ERR_` constant ties each trap site to a specific failure mode, so a developer reading a transaction's trap output can attribute the failure without disassembling the procedure.

Distinct constants per failure condition also let tests pin the expected error (see `assert-specific-error-in-tests`).

## Examples

```masm
# Good
const ERR_NOTE_NOT_FOUND = "note not found"
const ERR_COMMITMENT_MISMATCH = "stored commitment does not match recomputed value"

proc verify_note
    # ...
    assert.err=ERR_NOTE_NOT_FOUND
    # ...
    assert_eqw.err=ERR_COMMITMENT_MISMATCH
end

# Bad: bare assertion
proc verify_note
    assert
end

# Bad: shared generic constant for unrelated cases
const ERR_INVALID = "invalid"
assert.err=ERR_INVALID   # used in 6 places, each meaning something different
```
