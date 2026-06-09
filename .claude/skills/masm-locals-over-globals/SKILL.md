---
name: masm-locals-over-globals
description: Use when a MASM procedure needs temporary scratch storage — keep it in procedure-local memory so it cannot collide in a shared global region.
---

# Prefer Procedure Locals for MASM Scratch Storage

## Rule

When a MASM procedure needs scratch storage that lives only for the duration of one invocation, use procedure-local memory (`loc_store`, `loc_load`, `loc_storew`, `loc_loadw`) rather than allocating in a shared global memory region.

Global memory regions are reserved for state that crosses procedure boundaries (kernel inputs, account data, advice-keyed state). Stashing per-call scratch there leaks an implementation detail into a shared namespace and ties the procedure to a fixed address.

## Why

Procedure locals are allocated and freed by the VM, so two callers of the same procedure can't collide. A hard-coded scratch slot in global memory risks colliding with another procedure, forces every caller to avoid clobbering it, and locks the layout.

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
