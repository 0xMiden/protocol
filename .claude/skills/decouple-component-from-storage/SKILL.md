---
name: decouple-component-from-storage
description: Use when writing a MASM procedure that lives inside an account component and currently reads from a hard-coded storage slot — accept the required values as stack parameters, so the procedure works regardless of where the component is mapped in the account's storage layout.
---

# Decouple Component Procedures from Storage Layout

## Rule

Procedures that belong to an account component must not bake the component's storage-slot index into their bodies. Instead:

- Accept the required values as stack parameters (see `masm-explicit-stack-inputs`).
- Let the caller — the account-level glue procedure that knows the actual slot layout — read from storage and push the values.

If a procedure truly needs to read from "its own" storage, it should take the slot index (or a pointer to it) on the stack, not hard-code it.

## Why

A component can be installed into many accounts, each with different storage layouts. Hard-coding a slot index in the component's body ties that component to a single layout — installing it in any other account silently misreads memory.

Stack-parameter inputs make the component portable: the account-level caller decides where the slot lives and passes the data in. The component then operates on what it was given, with no implicit assumption about where it came from.

## Examples

```masm
# Good: component procedure takes its inputs on the stack
proc transfer_asset
    # => [ASSET, recipient_id, current_balance]
    # operates on what was passed in
end

# Account-level caller reads from the actual slot, then invokes:
mem_loadw.OUR_VAULT_SLOT
exec.transfer_asset

# Bad: component procedure reads a hard-coded slot
proc transfer_asset
    # => [ASSET, recipient_id]
    mem_loadw.4   # only works if THIS component is at slot 4
end
```
