---
name: u32-assert-before-u32-ops
description: Use when writing MASM that uses `u32*` instructions (`u32add`, `u32lt`, `u32div`, etc.) on values that originate from user input or untrusted sources — assert the operands are valid u32s with `u32assert*` before the operation.
---

# Validate u32 Operands Before u32 Instructions

## Rule

MASM's `u32*` instructions assume their operands are valid `u32` values (i.e. fit in 32 bits). Operating on a non-u32 value silently produces garbage or traps with a generic message.

Before applying any `u32*` instruction to a value that is not already known to be a valid u32 (e.g. it came from the stack as input, was read from memory, or arose from a non-u32 arithmetic op), assert the bound:

```masm
u32assert            # one value
u32assert2           # two top values
u32assert4           # four top values
```

If the operand is already known-valid (just produced by another `u32*` op, or a value loaded from a slot whose layout is u32 by construction), skip the assert.

## Why

`u32*` instructions are tuned for performance under the precondition that their inputs fit in 32 bits. The VM does not implicitly check the precondition — it's the procedure's job. Skipping `u32assert*` lets a non-u32 input produce a wrong result or trap with an uninformative message; the explicit assert gives the bug a named failure mode (see `masm-error-constants`).

## Examples

```masm
# Good: assert u32 before the u32 op
u32assert.err=ERR_VALUE_NOT_U32
u32add

# Good: both operands at once
u32assert2.err=ERR_VALUES_NOT_U32
u32lt

# Bad: u32 op on untrusted input
u32add   # one operand could be >2^32; silently wraps or traps
```
