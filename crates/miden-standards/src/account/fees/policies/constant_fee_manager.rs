use miden_protocol::account::component::{
    AccountComponentCode,
    AccountComponentMetadata,
    SchemaType,
    StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{
    AccountComponent,
    AccountProcedureRoot,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};

use super::BasicConstantFeePolicy;
use crate::account::account_component_code;
use crate::procedure_root;

// CONSTANT FEE MANAGER
// ================================================================================================

account_component_code!(
    CONSTANT_FEE_MANAGER_CODE,
    "miden-standards-fees-policies-constant-fee-manager.masp"
);

procedure_root!(
    CONSTANT_FEE_MANAGER_SET_NOTE_FEE,
    ConstantFeeManager::NAME,
    ConstantFeeManager::SET_NOTE_FEE_PROC_NAME,
    ConstantFeeManager::code()
);

/// The value slot this component owns, holding the ID of the fee schedule slot it manages.
static FEE_SCHEDULE_SLOT_ID_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new(
        "miden::standards::fees::policies::constant_fee_manager::fee_schedule_slot_id",
    )
    .expect("storage slot name should be valid")
});

/// Account component that exposes the `set_note_fee` admin procedure gated by the account-wide
/// [`crate::account::access::Authority`] component via `exec.authority::assert_authorized`.
///
/// `set_note_fee` updates the fee schedule map of a constant-fee policy after deployment, replacing
/// the scheduled fee for a note lookup key (the note's script root) with the amount of the supplied
/// fee asset. The supplied asset's ID must match the account's configured fee asset ID. This makes
/// an otherwise static fee schedule updatable by an authorized party.
///
/// The managed fee schedule slot is not hardcoded: the manager owns a value slot holding the ID of
/// the fee schedule slot to write, populated at construction from the managed policy's slot name
/// (see [`Self::new`] and [`Self::for_basic_constant_fee_policy`]). It can therefore manage any
/// constant-fee policy's schedule without sharing a slot name with the policy.
///
/// Because the fee schedule policy and the fee asset ID both live on an `AuthNetworkAccount`, this
/// manager is only usable on a network account.
///
/// `set_note_fee` must be gated by an [`Authority`](crate::account::access::Authority) component in
/// one of these modes:
/// - [`OwnerControlled`](crate::account::access::Authority::OwnerControlled) — requires the
///   Ownable2Step owner.
/// - [`RbacControlled`](crate::account::access::Authority::RbacControlled) — resolves a role for
///   the procedure. Map [`Self::set_note_fee_root`] to a role symbol (e.g. a `FEE_ADMIN` role) to
///   gate the operation.
///
/// Do NOT use [`AuthControlled`](crate::account::access::Authority::AuthControlled): it makes
/// `assert_authorized` a no-op, deferring to the account's own auth scheme, which on an
/// `AuthNetworkAccount` is permissionless for allowlisted notes — that would leave `set_note_fee`
/// callable by anyone, letting an unauthorized party rewrite the fee schedule.
///
/// Companion components required:
/// - [`crate::account::auth::AuthNetworkAccount`] — provides the fee asset ID slot and the fee
///   manager the schedule is priced against.
/// - [`crate::account::access::Authority`] — provides the mode-aware auth dispatch.
/// - The constant-fee policy whose `fee_schedule` slot this manager writes (installed as the
///   network account's active or allowed fee policy) — typically [`BasicConstantFeePolicy`].
#[derive(Debug, Clone)]
pub struct ConstantFeeManager {
    /// Name of the fee schedule map slot this manager updates.
    fee_schedule_slot: StorageSlotName,
}

impl ConstantFeeManager {
    /// The name of the component.
    pub const NAME: &'static str =
        "miden::standards::components::fees::policies::constant_fee_manager";

    const SET_NOTE_FEE_PROC_NAME: &'static str = "set_note_fee";

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a manager that updates the fee schedule map stored under `fee_schedule_slot`.
    ///
    /// The slot must belong to a constant-fee policy installed on the same account whose entries
    /// are `NOTE_SCRIPT_ROOT => [fee_amount, 0, 0, 1]`.
    pub fn new(fee_schedule_slot: StorageSlotName) -> Self {
        Self { fee_schedule_slot }
    }

    /// Creates a manager for the fee schedule of the standard [`BasicConstantFeePolicy`].
    pub fn for_basic_constant_fee_policy() -> Self {
        Self::new(BasicConstantFeePolicy::fee_schedule_slot_name().clone())
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &CONSTANT_FEE_MANAGER_CODE
    }

    /// Returns the procedure root of the `set_note_fee` procedure exposed by this component.
    ///
    /// Use it to key the [`crate::account::access::Authority::RbacControlled`] role map.
    pub fn set_note_fee_root() -> AccountProcedureRoot {
        *CONSTANT_FEE_MANAGER_SET_NOTE_FEE
    }

    /// Returns the [`StorageSlotName`] of the value slot this component owns, holding the ID of the
    /// managed fee schedule slot.
    pub fn fee_schedule_slot_id_slot_name() -> &'static StorageSlotName {
        &FEE_SCHEDULE_SLOT_ID_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] of the fee schedule slot this manager updates.
    pub fn fee_schedule_slot(&self) -> &StorageSlotName {
        &self.fee_schedule_slot
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema = StorageSchema::new([(
            FEE_SCHEDULE_SLOT_ID_SLOT_NAME.clone(),
            StorageSlotSchema::value(
                "ID of the fee schedule slot this manager updates",
                SchemaType::native_word(),
            ),
        )])
        .expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME)
            .with_description(
                "Authority-gated constant-fee schedule admin: exposes `set_note_fee` to update the \
                 fee schedule slot recorded in its storage, gated by the account-wide Authority \
                 component.",
            )
            .with_storage_schema(storage_schema)
    }
}

impl From<ConstantFeeManager> for AccountComponent {
    fn from(manager: ConstantFeeManager) -> Self {
        // Store the managed fee schedule slot's ID as [slot_id_suffix, slot_id_prefix, 0, 0], which
        // `set_note_fee` reads to locate the schedule map.
        let id = manager.fee_schedule_slot.id();
        let slot_id_word = Word::from([id.suffix(), id.prefix(), Felt::ZERO, Felt::ZERO]);
        let slot = StorageSlot::with_value(FEE_SCHEDULE_SLOT_ID_SLOT_NAME.clone(), slot_id_word);

        AccountComponent::new(
            ConstantFeeManager::code().clone(),
            vec![slot],
            ConstantFeeManager::component_metadata(),
        )
        .expect(
            "authority-gated constant-fee schedule admin component should satisfy the \
             requirements of a valid account component",
        )
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::account::StorageSlotContent;

    use super::*;

    /// The component stores the managed fee schedule slot's ID as `[suffix, prefix, 0, 0]`.
    #[test]
    fn stores_managed_fee_schedule_slot_id() {
        let policy_slot = BasicConstantFeePolicy::fee_schedule_slot_name().clone();
        let component: AccountComponent = ConstantFeeManager::new(policy_slot.clone()).into();

        let slot = component
            .storage_slots()
            .iter()
            .find(|slot| slot.name() == ConstantFeeManager::fee_schedule_slot_id_slot_name())
            .expect("manager should declare the fee schedule slot ID slot");

        let id = policy_slot.id();
        let expected = Word::from([id.suffix(), id.prefix(), Felt::ZERO, Felt::ZERO]);
        assert_eq!(slot.content(), &StorageSlotContent::Value(expected));
    }
}
