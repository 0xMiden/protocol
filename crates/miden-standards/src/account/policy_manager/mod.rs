use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::account::{StorageMap, StorageMapKey, StorageSlot, StorageSlotName};

/// Builds the three storage slots for an auth-controlled policy manager component.
///
/// `active_slot` / `allowed_slot` are storage **names**. `allow_all_procedure_root` is the
/// MAST root of the built-in `allow_all` procedure (map key when seeding `allowed_slot`), not
/// a slot.
///
/// used by mint and burn auth-controlled account components.
pub(crate) fn auth_controlled_initial_storage_slots(
    initial_policy_root: Word,
    active_slot: &StorageSlotName,
    allowed_slot: &StorageSlotName,
    authority_slot: StorageSlot,
    allow_all_procedure_root: Word,
) -> Vec<StorageSlot> {
    let allowed_policy_flag = Word::from([1u32, 0, 0, 0]);
    let mut allowed_policy_entries =
        vec![(StorageMapKey::from_raw(allow_all_procedure_root), allowed_policy_flag)];

    if initial_policy_root != allow_all_procedure_root {
        allowed_policy_entries
            .push((StorageMapKey::from_raw(initial_policy_root), allowed_policy_flag));
    }

    let allowed_policy_proc_roots = StorageMap::with_entries(allowed_policy_entries)
        .expect("allowed policy roots should have unique keys");

    vec![
        StorageSlot::with_value(active_slot.clone(), initial_policy_root),
        StorageSlot::with_map(allowed_slot.clone(), allowed_policy_proc_roots),
        authority_slot,
    ]
}

/// Initial active policy root for owner-controlled mint/burn policy manager newtypes.
///
/// Mint and burn components wrap this field, each builds its own initial storage layout (the two
/// layouts differ).
#[derive(Debug, Clone, Copy)]
pub(crate) struct OwnerControlled {
    pub(crate) initial_policy_root: Word,
}
