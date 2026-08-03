---
name: cheap-masm-equivalents
description: Use when writing or reviewing MASM hot paths or loops — prefer the cheaper equivalent: loop counters and pointers on the operand stack instead of procedure locals, `neq.0` over `gt.0` for non-zero checks, `cdrop` over an `if/else` selecting between two values, `dup.N` over `loc_load` for a value still on the stack, `eqw` over element-wise word comparison, `u32gt`/`u32lt` over generic `gt`/`lt` on known-u32 operands.
---

# Prefer Cheap MASM Equivalents

## Rule

Several MASM idioms have a cheap and an expensive form. Use the cheap one when both produce the same result on the inputs the procedure can see:

- Loop variables (counters, pointers, indices): keep them on the operand stack across iterations instead of in procedure locals. See below.
- Non-zero check: `neq.0` (3 cycles) over `gt.0` (16 cycles).
- Selecting between two values on a flag: `cdrop` over an `if.true ... else ... end` branch with the same effect.
- Re-fetch a recently-pushed value: `dup.N` over `loc_load.N` when the value is still on the stack.
- Whole-word equality: `eqw` over element-wise comparisons.
- u32-known operands: `u32gt`/`u32lt` over generic `gt`/`lt`.

Don't apply the cheap form when the operands violate its precondition (e.g. `u32gt` on a value that might exceed `u32::MAX`).

## Why

MASM cycle costs are not uniform — `gt.0` does signed-comparison work that `neq.0` skips, so a hot path using the expensive form pays for it on every call. The swaps are semantically equivalent under their preconditions, so the saving is free.

## Examples

```masm
# Good
push.0 neq          # non-zero check, 3 cycles
# or simply
neq.0

# Bad
push.0 gt           # same answer, 16 cycles
```

```masm
# Good: cdrop for ternary selection
# stack: [b, a, cond]
cdrop
# stack: [a if cond else b]

# Bad: branchy equivalent
if.true
    drop      # drop b, keep a
else
    swap drop # drop a, keep b
end
```

## Loop Variables Belong on the Stack

A procedure local is not a register: `loc_load.i` costs 5 cycles and `loc_store.i` costs 6. Reaching the same value on the stack
with `dup.n`, `swap`, `movup.n` or `movdn.n` (usually) costs 1 cycle. So a loop that keeps its counter and pointer in locals pays 5-11 cycles per access, per iteration, for data the stack could hold for 1.

Read once, mutate in place:

```masm
# Good: item_ptr lives on the stack next to the loop counter
# => [items_left, item_ptr, ...]
# 1 cycle: read the pointer
dup.1
# ... use it ...
# 4 cycles: advance it
swap add.ITEM_NUM_ELEMENTS swap
sub.1 dup neq.0

# Bad: same loop through a local
# 5 cycles
loc_load.ITEM_PTR_LOC
# ... use it ...
# 13 cycles
loc_load.ITEM_PTR_LOC add.ITEM_NUM_ELEMENTS loc_store.ITEM_PTR_LOC
sub.1 dup neq.0
```

### Working around `call`

The reason to reach for a local is a `call`: the callee takes the top 16 elements, so while those 16 slots are being filled, nothing below them is addressable by `dup.n`. Values that only have to *survive* the call are fine on the stack - they sit in the overflow and come back untouched. Only a value that must be re-read *while* the frame is being built has to live in a local, and even then it is one local, not one per loop variable.
