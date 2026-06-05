---
name: masm-explicit-stack-inputs
description: Use when defining the interface for a new MASM procedure — keep its inputs explicit on the stack so the signature reflects what it consumes.
---

# Pass MASM Procedure Inputs Explicitly on the Stack

## Rule

A MASM procedure's inputs should arrive on the stack, named in its `Inputs:` doc block. Do not design a procedure that reads its inputs from a fixed memory location that the caller must populate beforehand.

Use memory I/O only when:

- The data has a fixed canonical home (account storage, kernel inputs, advice-keyed regions).
- The data is too large to keep on the stack (a full Merkle proof, a large vector).

For everything else — counts, indices, single words, small structs — pass on the stack.

## Why

Hidden memory inputs make the procedure's signature a lie — a reader of `Inputs: [ptr]` can't tell what's behind the pointer or what the caller had to set up, and the real contract drifts out of sync in prose. Stack inputs are typed by the doc, testable in isolation, and trap if the shape is wrong.

## Examples

```masm
# Good
#! Inputs:  [note_index, ASSET]
#! Outputs: []
proc add_asset_to_note
    # ... uses values directly from the stack
end

# Bad: implicit input via memory location the caller had to populate
#! Inputs:  []
#! Outputs: []
proc add_asset_to_note
    mem_load.PENDING_NOTE_PTR    # caller had to set this first
    mem_loadw.PENDING_ASSET_PTR
    # ...
end

# OK: the exception — data too large for the stack lives in memory, and the
# pointer to it is an explicit stack input named in the doc block
#! Inputs:  [proof_ptr, leaf_index, ROOT]
#! Outputs: [is_valid]
proc verify_merkle_proof
    # the full proof (many words) was written to memory by the caller;
    # only the pointer, index, and root travel on the stack
    # ...
end
```
