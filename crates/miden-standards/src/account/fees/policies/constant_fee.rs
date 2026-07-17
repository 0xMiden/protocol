use alloc::collections::BTreeMap;

use miden_protocol::account::component::{
    AccountComponentCode,
    AccountComponentMetadata,
    SchemaType,
    StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{
    AccountComponent,
    AccountComponentName,
    AccountProcedureRoot,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::AssetAmount;
use miden_protocol::note::NoteScriptRoot;
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};

use crate::account::account_component_code;
use crate::procedure_root;

// CONSTANT FEE POLICY
// ================================================================================================

account_component_code!(
    CONSTANT_FEE_POLICY_CODE,
    "miden-standards-fees-policies-constant-fee.masp"
);

procedure_root!(
    CONSTANT_FEE_POLICY_ROOT,
    ConstantFeePolicy::NAME,
    ConstantFeePolicy::PROC_NAME,
    ConstantFeePolicy::code()
);

static FEE_SCHEDULE_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::fees::policies::constant_fee::fee_schedule")
        .expect("storage slot name should be valid")
});

/// Set-marker element of a fee schedule entry, distinguishing scheduled entries (including
/// explicit 0 fees) from unset keys: storage maps prune zero-word values and return the zero
/// word for unset keys, so a scheduled entry must be a non-zero word. The MASM
/// `compute_note_fee` counterpart asserts this element equals 1 (unset keys read as the zero
/// word, whose marker element is 0) and strips it before returning the fee asset value.
const FEE_SCHEDULE_ENTRY_MARKER: Felt = Felt::ONE;

/// Encodes a fee as a fee schedule map entry: the asset value word with the set-marker as the
/// last element, i.e. `[fee_amount, 0, 0, 1]`.
fn fee_schedule_entry(fee: AssetAmount) -> Word {
    let mut entry = fee.to_word();
    entry[3] = FEE_SCHEDULE_ENTRY_MARKER;
    entry
}

/// The `constant_fee` fee policy account component.
///
/// Pair with a [`crate::account::fees::FeeManager`] whose allowed fee-policies map includes
/// [`ConstantFeePolicy::root`]. When active, the manager's `estimate_note_fee` dispatches to this
/// policy's `compute_note_fee` procedure, which returns the fee as an asset value word: the
/// amount is looked up in the fee schedule under the note's script root, and note scripts
/// without a schedule entry abort fee estimation. To make a note script free, schedule an
/// explicit 0 fee for it via [`ConstantFeePolicy::with_fee`]. The manager prepends the fee asset
/// ID it stores to the returned fee value.
///
/// ## Storage layout
///
/// - [`Self::fee_schedule_slot_name`] map slot: `NOTE_SCRIPT_ROOT => [fee_amount, 0, 0, 1]`, where
///   the last element is a set-marker distinguishing scheduled entries from unset keys.
#[derive(Debug, Clone, Default)]
pub struct ConstantFeePolicy {
    /// The fee charged per note script root.
    fee_schedule: BTreeMap<NoteScriptRoot, AssetAmount>,
}

impl ConstantFeePolicy {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::fees::policies::constant_fee";

    pub(crate) const PROC_NAME: &str = "compute_note_fee";

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new `constant_fee` fee policy with an empty fee schedule.
    pub fn new() -> Self {
        Self { fee_schedule: BTreeMap::new() }
    }

    /// Sets the fee for notes with the given script root, replacing any previous entry.
    ///
    /// Scheduling an explicit fee of 0 makes notes with this script root free; script roots
    /// without a schedule entry abort fee estimation.
    #[must_use]
    pub fn with_fee(mut self, script_root: NoteScriptRoot, fee: AssetAmount) -> Self {
        self.fee_schedule.insert(script_root, fee);
        self
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &CONSTANT_FEE_POLICY_CODE
    }

    /// Returns the procedure root of the `compute_note_fee` fee policy procedure.
    pub fn root() -> AccountProcedureRoot {
        *CONSTANT_FEE_POLICY_ROOT
    }

    /// Returns the [`StorageSlotName`] of the slot holding the fee schedule map.
    pub fn fee_schedule_slot_name() -> &'static StorageSlotName {
        &FEE_SCHEDULE_SLOT_NAME
    }

    /// Returns the fee charged per note script root.
    pub fn fee_schedule(&self) -> &BTreeMap<NoteScriptRoot, AssetAmount> {
        &self.fee_schedule
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema = StorageSchema::new([(
            Self::fee_schedule_slot_name().clone(),
            StorageSlotSchema::map(
                "Fee charged per note script root, as [fee_amount, 0, 0, 1] with a set-marker \
                 as the last element",
                SchemaType::native_word(),
                SchemaType::native_word(),
            ),
        )])
        .expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME)
            .with_description("`constant_fee` fee policy charging a constant per-note-script fee")
            .with_storage_schema(storage_schema)
    }
}

impl From<ConstantFeePolicy> for AccountComponent {
    fn from(policy: ConstantFeePolicy) -> Self {
        let entries = policy
            .fee_schedule
            .into_iter()
            .map(|(root, fee)| (StorageMapKey::new(root.as_word()), fee_schedule_entry(fee)));
        let fee_schedule_map = StorageMap::with_entries(entries)
            .expect("fee schedule entries should produce a valid storage map");
        let fee_schedule_slot = StorageSlot::with_map(
            ConstantFeePolicy::fee_schedule_slot_name().clone(),
            fee_schedule_map,
        );

        AccountComponent::new(
            ConstantFeePolicy::code().clone(),
            vec![fee_schedule_slot],
            ConstantFeePolicy::component_metadata(),
        )
        .expect(
            "`constant_fee` fee policy component should satisfy the requirements of a valid account component",
        )
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::account::{AccountBuilder, AccountId, AccountType, StorageSlotContent};
    use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;

    use super::*;
    use crate::account::auth::NoAuth;
    use crate::account::fees::FeeManager;

    fn fee_faucet_id() -> AccountId {
        AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)
            .expect("testing account ID should be valid")
    }

    /// Check that the policy's storage slot contains the fee schedule entries.
    #[test]
    fn storage_slots_contain_expected_entries() -> anyhow::Result<()> {
        let script_root = NoteScriptRoot::from_array([1, 2, 3, 4]);
        let fee = AssetAmount::new(500)?;
        let free_script_root = NoteScriptRoot::from_array([5, 6, 7, 8]);

        let policy = ConstantFeePolicy::new()
            .with_fee(script_root, fee)
            .with_fee(free_script_root, AssetAmount::ZERO);
        let fee_manager = FeeManager::builder()
            .fee_faucet_id(fee_faucet_id())
            .active_fee_policy(policy.into())
            .build();

        let account = AccountBuilder::new([1; 32])
            .account_type(AccountType::Public)
            .with_auth_component(NoAuth)
            .with_components(fee_manager)
            .build_existing()?;

        let slot = account
            .storage()
            .get(ConstantFeePolicy::fee_schedule_slot_name())
            .expect("fee schedule slot should exist");
        let StorageSlotContent::Map(map) = slot.content() else {
            panic!("fee schedule slot must be a map");
        };
        assert_eq!(
            map.get(&StorageMapKey::new(script_root.as_word())),
            Word::new([Felt::new(500)?, Felt::ZERO, Felt::ZERO, Felt::ONE]),
            "the fee entry should be stored as an asset value word with the set-marker"
        );
        assert_eq!(
            map.get(&StorageMapKey::new(free_script_root.as_word())),
            Word::new([Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::ONE]),
            "an explicit 0-fee entry should survive as a non-zero word"
        );

        Ok(())
    }
}
