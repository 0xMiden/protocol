---
name: cheap-masm-equivalents
description: Use when writing or reviewing MASM hot paths — prefer the cheaper equivalent instruction: `neq.0` over `gt.0` for non-zero checks, `cdrop` over an `if/else` selecting between two values, `dup.N` over `loc_load` for a value still on the stack, `eqw` over element-wise word comparison, `u32gt`/`u32lt` over generic `gt`/`lt` on known-u32 operands.
---

# Prefer Cheap MASM Equivalents

## Rule

Several MASM idioms have a cheap and an expensive form. Use the cheap one when both produce the same result on the inputs the procedure can see:

- Non-zero check: `neq.0` (3 cycles) over `gt.0` (16 cycles).
- Selecting between two values on a flag: `cdrop` over an `if.true ... else ... end` branch with the same effect.
- Re-fetch a recently-pushed value: `dup.N` over `loc_load.N` when the value is still on the stack.
- Whole-word equality: `eqw` over element-wise comparisons.
- u32-known operands: `u32gt`/`u32lt` over generic `gt`/`lt`.

Don't apply the cheap form when the operands violate its precondition (e.g. `u32gt` on a value that might exceed `u32::MAX`).

## Why

MASM cycle costs are not uniform. `gt.0` does signed-comparison work that `neq.0` skips entirely; both produce the same boolean for the typical "is it non-zero?" question on non-negative inputs. A hot kernel path that uses `gt.0` everywhere pays the full 16-cycle cost on each call for a check `neq.0` would do in 3.

These swaps are also free of risk in most cases — the semantics are equivalent under typical preconditions.

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
