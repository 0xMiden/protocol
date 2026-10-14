---
name: masm-explicit-stack-interface
description: Use when defining the interface for a new MASM procedure — keep its inputs explicit on the stack and its outputs limited to values it produces.
---

# Keep MASM Procedure Interfaces Explicit

## Inputs: pass on the stack

A MASM procedure's inputs should arrive on the stack, named in its `Inputs:` doc block. Do not design a procedure that reads its inputs from a fixed memory location that the caller must populate beforehand.

Use memory I/O only when:

- The data has a fixed canonical home (account storage, kernel inputs, advice-keyed regions).
- The data is too large to keep on the stack (a full Merkle proof, a large vector).

For everything else — counts, indices, single words, small structs — pass on the stack.

### Why

Hidden memory inputs make the procedure's signature a lie — a reader of `Inputs: [ptr]` can't tell what's behind the pointer or what the caller had to set up, and the real contract drifts out of sync in prose. Stack inputs are typed by the doc, testable in isolation, and trap if the shape is wrong.

## Outputs: return only produced values

A procedure's `Outputs:` carry only values the procedure computes. An input the procedure consumes unchanged is dropped inside the procedure; a caller that still needs it `dup`s it before the call. A modified input (an advanced pointer, a decremented counter) is a produced value and may be returned.

### Why

Rust code calls MASM procedures through generated bindings that follow the C ABI: every return value is written to memory through a pointer. An echoed input costs that store on every Rust call, while the Rust caller already holds its own copy of the parameter (see [#1717](https://github.com/0xMiden/protocol/issues/1717)). The few cycles a MASM caller saves by reusing an echoed value do not outweigh this.

## Examples

```masm
# Good
#! Inputs:  [ASSET_ID, ASSET_VALUE, note_idx]
#! Outputs: []
pub proc add_asset(asset: Asset, note_idx: u16)
    # ... uses values directly from the stack
end

# Bad: implicit input via memory location the caller had to populate
#! Inputs:  []
#! Outputs: []
pub proc add_asset
    mem_load.PENDING_NOTE_PTR    # caller had to set this first
    mem_loadw.PENDING_ASSET_PTR
    # ...
end

# Bad: echoes its inputs back to the caller
#! Inputs:  [ASSET_ID, ASSET_VALUE, note_idx]
#! Outputs: [ASSET_ID, ASSET_VALUE, note_idx]
pub proc add_asset(asset: Asset, note_idx: u16) -> (Asset, u16)
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
