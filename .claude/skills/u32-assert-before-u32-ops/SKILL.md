---
name: u32-assert-before-u32-ops
description: Use when writing MASM `u32*` instructions on values from user input or untrusted sources — ensure the operands are valid u32s first.
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

`u32*` instructions are tuned for the precondition that operands fit in 32 bits, and the VM does not check it for you. Skipping `u32assert*` lets a non-u32 input silently produce a wrong result or trap uninformatively; the assert gives the bug a named failure mode.

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
