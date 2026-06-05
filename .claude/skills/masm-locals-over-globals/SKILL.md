---
name: masm-locals-over-globals
description: Use when writing a MASM procedure that needs temporary scratch storage — prefer procedure-local memory (`loc_store` / `loc_load`) over global memory regions when both achieve the same result.
---

# Prefer Procedure Locals for MASM Scratch Storage

## Rule

When a MASM procedure needs scratch storage that lives only for the duration of one invocation, use procedure-local memory (`loc_store`, `loc_load`, `loc_storew`, `loc_loadw`) rather than allocating in a shared global memory region.

Global memory regions are reserved for state that crosses procedure boundaries (kernel inputs, account data, advice-keyed state). Stashing per-call scratch there leaks an implementation detail into a shared namespace and ties the procedure to a fixed address.

## Why

Procedure locals are automatically allocated and freed by the VM. Two callers of the same procedure on the same kernel run cannot collide. By contrast, a hard-coded scratch slot in global memory:

- Risks colliding with another procedure that uses the same slot.
- Forces every caller to know the slot exists (don't clobber it).
- Locks the layout — moving the slot is a cross-cutting change.

Use globals only for data that must persist across procedure boundaries by design.

## Examples

```masm
# Good
proc compute_hash
    # allocate two local slots
    loc_store.0
    loc_store.1
    # ...
    loc_load.0
    loc_load.1
end

# Bad: scratch in a shared region
const SCRATCH_PTR = 0x4000
proc compute_hash
    mem_store.SCRATCH_PTR        # collides with anyone else using SCRATCH_PTR
end
```
