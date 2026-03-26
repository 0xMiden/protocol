use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::account::{StorageMap, StorageMapKey, StorageSlot, StorageSlotName};

/// Shared inner state for auth-controlled mint/burn policy manager components.
///
/// Crate-private helper: not part of the `miden-standards` public API. We use `pub(crate)` rather
/// than `pub(super)` so `mint_policies` / `burn_policies` can wrap this in their component
/// newtypes; `pub(super)` would only be visible inside `policy_manager`, not in sibling `account`
/// modules.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AuthControlled {
    pub(crate) initial_policy_root: Word,
}

impl AuthControlled {
    /// Builds the three storage slots for an auth-controlled policy manager component.
    ///
    /// `active_slot` / `allowed_slot` are storage **names**. `allow_all_procedure_root` is the
    /// MAST root of the built-in `allow_all` procedure (map key when seeding `allowed_slot`), not
    /// a slot.
    pub(crate) fn initial_storage_slots(
        &self,
        active_slot: &StorageSlotName,
        allowed_slot: &StorageSlotName,
        authority_slot: StorageSlot,
        allow_all_procedure_root: Word,
    ) -> Vec<StorageSlot> {
        let initial_policy_root = self.initial_policy_root;
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
}

/// Shared inner state for owner-controlled mint/burn policy manager components.
///
/// Crate-private helper: not part of the `miden-standards` public API. We use `pub(crate)` rather
/// than `pub(super)` so `mint_policies` / `burn_policies` can wrap this in their component
/// newtypes; `pub(super)` would only be visible inside `policy_manager`, not in sibling `account`
/// modules.
#[derive(Debug, Clone, Copy)]
pub(crate) struct OwnerControlled {
    pub(crate) initial_policy_root: Word,
}

impl OwnerControlled {
    pub(crate) fn mint_initial_storage_slots(
        &self,
        active_slot: &StorageSlotName,
        allowed_slot: &StorageSlotName,
        authority_slot: StorageSlot,
        owner_only_procedure_root: Word,
    ) -> Vec<StorageSlot> {
        let initial_policy_root = self.initial_policy_root;
        let allowed_policy_flag = Word::from([1u32, 0, 0, 0]);
        let mut allowed_policy_entries =
            vec![(StorageMapKey::from_raw(owner_only_procedure_root), allowed_policy_flag)];

        if initial_policy_root != owner_only_procedure_root {
            allowed_policy_entries
                .push((StorageMapKey::from_raw(initial_policy_root), allowed_policy_flag));
        }

        let allowed_policy_proc_roots = StorageMap::with_entries(allowed_policy_entries)
            .expect("allowed mint policy roots should have unique keys");

        vec![
            StorageSlot::with_value(active_slot.clone(), initial_policy_root),
            StorageSlot::with_map(allowed_slot.clone(), allowed_policy_proc_roots),
            authority_slot,
        ]
    }

    pub(crate) fn burn_initial_storage_slots(
        &self,
        active_slot: &StorageSlotName,
        allowed_slot: &StorageSlotName,
        authority_slot: StorageSlot,
        allow_all_procedure_root: Word,
        owner_only_procedure_root: Word,
    ) -> Vec<StorageSlot> {
        let initial_policy_root = self.initial_policy_root;
        let allowed_policy_flag = Word::from([1u32, 0, 0, 0]);
        let mut allowed_policy_entries = vec![
            (StorageMapKey::from_raw(allow_all_procedure_root), allowed_policy_flag),
            (StorageMapKey::from_raw(owner_only_procedure_root), allowed_policy_flag),
        ];

        if initial_policy_root != allow_all_procedure_root
            && initial_policy_root != owner_only_procedure_root
        {
            allowed_policy_entries
                .push((StorageMapKey::from_raw(initial_policy_root), allowed_policy_flag));
        }

        let allowed_policy_proc_roots = StorageMap::with_entries(allowed_policy_entries)
            .expect("allowed burn policy roots should have unique keys");

        vec![
            StorageSlot::with_value(active_slot.clone(), initial_policy_root),
            StorageSlot::with_map(allowed_slot.clone(), allowed_policy_proc_roots),
            authority_slot,
        ]
    }
}
