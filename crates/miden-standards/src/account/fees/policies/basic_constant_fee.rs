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

// BASIC CONSTANT FEE POLICY
// ================================================================================================

account_component_code!(
    BASIC_CONSTANT_FEE_POLICY_CODE,
    "miden-standards-fees-policies-basic-constant-fee.masp"
);

procedure_root!(
    BASIC_CONSTANT_FEE_POLICY_ROOT,
    BasicConstantFeePolicy::NAME,
    BasicConstantFeePolicy::PROC_NAME,
    BasicConstantFeePolicy::code()
);

static FEE_SCHEDULE_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::fees::policies::basic_constant_fee::fee_schedule")
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

/// The `basic_constant_fee` fee policy account component.
///
/// This is the simplest constant fee policy: the fee depends only on the note's script root. More
/// sophisticated constant fee policies can be derived from it by swapping the lookup-key
/// computation of its `compute_note_fee` procedure, which yields a policy with a new root.
///
/// Register with a [`crate::account::fees::FeePolicyManager`], whose allowed fee-policies map then
/// includes [`BasicConstantFeePolicy::root`]. When active, `estimate_note_fee` dispatches to this
/// policy's `compute_note_fee` procedure, which returns the fee as a fee asset (asset ID and
/// value words): the amount is looked up in the fee schedule under the note's script root
/// (recovered from the note's recipient via the advice provider), and note scripts without a
/// schedule entry abort fee estimation. To make a note script free, schedule an explicit 0 fee
/// for it via [`BasicConstantFeePolicy::with_fee`]. The remaining note parameters, including the
/// timeframe and priority, are ignored by this policy. The fee asset ID is read from the
/// fee-policy storage, so the fee is always charged in the configured asset and the policy
/// requires an [`AuthNetworkAccount`][crate::account::auth::AuthNetworkAccount] component on the
/// same account.
///
/// ## Storage layout
///
/// - [`Self::fee_schedule_slot_name`] map slot: `NOTE_SCRIPT_ROOT => [fee_amount, 0, 0, 1]`, where
///   the last element is a set-marker distinguishing scheduled entries from unset keys.
#[derive(Debug, Clone, Default)]
pub struct BasicConstantFeePolicy {
    /// The fee charged per note script root.
    fee_schedule: BTreeMap<NoteScriptRoot, AssetAmount>,
}

impl BasicConstantFeePolicy {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The name of the component.
    pub const NAME: &'static str =
        "miden::standards::components::fees::policies::basic_constant_fee";

    pub(crate) const PROC_NAME: &str = "compute_note_fee";

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new `basic_constant_fee` fee policy with an empty fee schedule, charging fees in
    /// the fungible asset its [`crate::account::fees::FeePolicyManager`] is configured with.
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
        &BASIC_CONSTANT_FEE_POLICY_CODE
    }

    /// Returns the procedure root of the `compute_note_fee` fee policy procedure.
    pub fn root() -> AccountProcedureRoot {
        *BASIC_CONSTANT_FEE_POLICY_ROOT
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
                "Fee charged per note script root",
                SchemaType::native_word(),
                SchemaType::native_word(),
            ),
        )])
        .expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME)
            .with_description(
                "`basic_constant_fee` fee policy charging a constant per-note-script fee",
            )
            .with_storage_schema(storage_schema)
    }
}

impl From<BasicConstantFeePolicy> for AccountComponent {
    fn from(policy: BasicConstantFeePolicy) -> Self {
        let entries = policy
            .fee_schedule
            .into_iter()
            .map(|(root, fee)| (StorageMapKey::new(root.as_word()), fee_schedule_entry(fee)));
        let fee_schedule_map = StorageMap::with_entries(entries)
            .expect("fee schedule entries should produce a valid storage map");
        let fee_schedule_slot = StorageSlot::with_map(
            BasicConstantFeePolicy::fee_schedule_slot_name().clone(),
            fee_schedule_map,
        );

        AccountComponent::new(
            BasicConstantFeePolicy::code().clone(),
            vec![fee_schedule_slot],
            BasicConstantFeePolicy::component_metadata(),
        )
        .expect(
            "`basic_constant_fee` fee policy component should satisfy the requirements of a valid account component",
        )
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::account::StorageSlotContent;

    use super::*;

    /// Check that the policy's storage slot contains the fee schedule entries.
    #[test]
    fn storage_slots_contain_expected_entries() -> anyhow::Result<()> {
        let script_root = NoteScriptRoot::from_array([1, 2, 3, 4]);
        let fee = AssetAmount::new(500)?;
        let free_script_root = NoteScriptRoot::from_array([5, 6, 7, 8]);

        let policy = BasicConstantFeePolicy::new()
            .with_fee(script_root, fee)
            .with_fee(free_script_root, AssetAmount::ZERO);

        let component = AccountComponent::from(policy);
        let slot = component
            .storage_slots()
            .iter()
            .find(|slot| slot.name() == BasicConstantFeePolicy::fee_schedule_slot_name())
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
