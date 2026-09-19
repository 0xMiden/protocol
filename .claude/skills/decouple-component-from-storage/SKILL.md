---
name: decouple-component-from-storage
description: Use when writing a generic MASM utility that accesses a caller-selected account storage slot — receive the slot as a parameter so the utility is portable across storage layouts.
---

# Decouple Generic Utilities from Storage Layout

## Rule

A generic storage utility that operates on a caller-selected slot must not bake that slot into its procedure body. Hard-coding one caller's slot makes the utility work for only that storage layout.

Instead, take the storage slot as a parameter — the slot id, split into its `slot_id_prefix` / `slot_id_suffix` felts — and pass it into the storage-access procedure (`active_account::get_item` / `get_map_item`, `native_account::set_item` / `set_map_item`). The account-level glue procedure that knows the real layout supplies the slot id.

Component-owned named slots are different. A named slot's ID is derived deterministically from its stable name, so a component may reference its own slot by that name. The `authority` component follows this pattern with `AUTHORITY_SLOT`; generic array utilities accept caller-supplied slot IDs instead.

## Why

Taking a caller-selected slot as a parameter makes a generic utility portable. Referencing a component-owned slot by its stable name keeps that component's storage identity deterministic across accounts.

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

# Also good: a component references its own deterministic named slot
pub const AUTHORITY_SLOT = word("miden::standards::access::authority::authority_config")
pub proc get_authority
    push.AUTHORITY_SLOT[0..2] exec.active_account::get_item
end
```
