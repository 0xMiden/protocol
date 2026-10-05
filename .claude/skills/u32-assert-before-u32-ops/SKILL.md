---
name: u32-assert-before-u32-ops
description: Use when writing MASM `u32*` instructions whose operands must already fit in 32 bits, especially for user input or untrusted values.
---

# Validate Required u32 Operands

## Rule

Most MASM `u32*` arithmetic instructions require operands that fit in 32 bits. Their behavior on an out-of-range operand is undefined, so the executor may trap and the resulting proof is not valid.

Before applying a `u32*` instruction whose documented precondition requires valid u32 operands, assert the bound of any operand that is not already known-valid (e.g. it came from the stack as input, was read from memory, or arose from a non-u32 arithmetic op):

```masm
u32assert            # one value
u32assert2           # two top values
u32assertw           # one word (four values)
```

If the operand is already known-valid (just produced as a valid-u32 output of another operation, or loaded from a slot whose layout is u32 by construction), skip the assert.

`u32test`, `u32testw`, `u32cast`, and `u32split` accept arbitrary field values, so they do not require a prior u32 assertion.

## Why

Arithmetic instructions do not check the u32 precondition for you. An explicit assertion prevents undefined behavior and gives an out-of-range input a clear failure mode.

## Examples

```masm
# Good: assert both operands before producing one wrapping sum
u32assert2.err=ERR_VALUES_NOT_U32
u32wrapping_add

# Good: both operands at once
u32assert2.err=ERR_VALUES_NOT_U32
u32lt

# Bad: u32 op on untrusted input
u32wrapping_add   # either operand could be greater than or equal to 2^32
```
