---
name: masm-explicit-stack-inputs
description: Use when defining the interface for a new MASM procedure — pass inputs explicitly on the stack; reserve memory I/O for data that must cross many procedure boundaries.
---

# Pass MASM Procedure Inputs Explicitly on the Stack

## Rule

A MASM procedure's inputs should arrive on the stack, named in its `Inputs:` doc block. Do not design a procedure that reads its inputs from a fixed memory location that the caller must populate beforehand.

Use memory I/O only when:

- The data has a fixed canonical home (account storage, kernel inputs, advice-keyed regions).
- The data is too large to keep on the stack (a full Merkle proof, a large vector).

For everything else — counts, indices, single words, small structs — pass on the stack.

## Why

Hidden memory inputs make the procedure's signature a lie. A reader of `Inputs: [ptr]` cannot tell what's at the other end of that pointer or what invariants the caller had to set up; the contract lives in prose and gets out of sync.

Stack-passed inputs are typed by the `Inputs:` doc, easy to test in isolation (no global setup required), and impossible to forget — the procedure traps if the stack shape is wrong.

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
```
