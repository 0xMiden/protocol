---
name: decouple-component-from-storage
description: Use when writing a MASM procedure inside a reusable account component that accesses account storage — receive the storage slot as a parameter so the component is portable across storage layouts.
---

# Decouple Component Procedures from Storage Layout

## Rule

A reusable account component must not bake a storage-slot index into its procedure bodies. The same component can be installed into many accounts, each mapping it to a different slot, so a hard-coded slot index only works for one layout.

Instead, take the storage slot as a parameter — the slot id, split into its `slot_id_prefix` / `slot_id_suffix` felts — and pass it into the storage-access procedure (`active_account::get_item` / `get_map_item`, `native_account::set_item` / `set_map_item`). The account-level glue procedure that knows the real layout supplies the slot id.

## Why

A component installed into different accounts sits at a different storage slot in each. Hard-coding the slot ties the component to one layout and silently misreads storage everywhere else; taking the slot id as a parameter makes the procedure portable.

## Examples

```masm
# Good: the component proc takes the slot id and uses it for the storage access
pub proc get(slot_id_suffix: felt, slot_id_prefix: felt, index: felt) -> word
    movup.2 push.0.0.0        # build KEY = [0, 0, 0, index]
    movup.5 movup.5           # => [slot_id_suffix, slot_id_prefix, KEY]
    exec.active_account::get_map_item
    # => [VALUE]
end

# The account-level caller knows the real layout and passes the slot in:
push.index push.MY_SLOT_ID_PREFIX push.MY_SLOT_ID_SUFFIX
exec.get

# Bad: the component hard-codes its own slot, so it only works at that one layout
pub proc get_authority
    push.AUTHORITY_SLOT[0..2] exec.active_account::get_item
end
```
