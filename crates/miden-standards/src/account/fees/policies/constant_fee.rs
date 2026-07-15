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
    AccountId,
    AccountProcedureRoot,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::{AssetAmount, AssetId};
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

static FEE_ASSET_ID_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::fees::policies::constant_fee::fee_asset_id")
        .expect("storage slot name should be valid")
});

static FEE_SCHEDULE_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::fees::policies::constant_fee::fee_schedule")
        .expect("storage slot name should be valid")
});

/// The `constant_fee` fee policy account component.
///
/// Pair with a [`crate::account::fees::FeeManager`] whose allowed fee-policies map includes
/// [`ConstantFeePolicy::root`]. When active, the manager's `estimate_note_fee` dispatches to this
/// policy's `compute_note_fee` procedure, which returns the fee as a fee asset (asset ID and
/// value words): the amount is looked up in the fee schedule under the note's script root, and
/// note scripts without a schedule entry estimate to an amount of 0.
///
/// ## Storage layout
///
/// - [`Self::fee_asset_id_slot_name`] value slot: the [`AssetId`] word of the fungible asset the
///   fee is charged in.
/// - [`Self::fee_schedule_slot_name`] map slot: `NOTE_SCRIPT_ROOT => [fee_amount, 0, 0, 0]`.
#[derive(Debug, Clone)]
pub struct ConstantFeePolicy {
    /// The ID of the fungible asset the fee is charged in.
    fee_asset_id: AssetId,
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

    /// Creates a new `constant_fee` fee policy with an empty fee schedule, charging fees in the
    /// fungible asset issued by the given faucet.
    pub fn new(fee_faucet_id: AccountId) -> Self {
        Self {
            fee_asset_id: AssetId::new_fungible(fee_faucet_id),
            fee_schedule: BTreeMap::new(),
        }
    }

    /// Sets the fee for notes with the given script root, replacing any previous entry.
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

    /// Returns the [`StorageSlotName`] of the slot holding the fee asset ID.
    pub fn fee_asset_id_slot_name() -> &'static StorageSlotName {
        &FEE_ASSET_ID_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] of the slot holding the fee schedule map.
    pub fn fee_schedule_slot_name() -> &'static StorageSlotName {
        &FEE_SCHEDULE_SLOT_NAME
    }

    /// Returns the [`AssetId`] of the fungible asset the fee is charged in.
    pub fn fee_asset_id(&self) -> AssetId {
        self.fee_asset_id
    }

    /// Returns the fee charged per note script root.
    pub fn fee_schedule(&self) -> &BTreeMap<NoteScriptRoot, AssetAmount> {
        &self.fee_schedule
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema = StorageSchema::new([
            (
                Self::fee_asset_id_slot_name().clone(),
                StorageSlotSchema::value(
                    "ID of the fungible asset the fee is charged in",
                    SchemaType::native_word(),
                ),
            ),
            (
                Self::fee_schedule_slot_name().clone(),
                StorageSlotSchema::map(
                    "Fee charged per note script root",
                    SchemaType::native_word(),
                    SchemaType::native_word(),
                ),
            ),
        ])
        .expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME)
            .with_description("`constant_fee` fee policy charging a constant per-note-script fee")
            .with_storage_schema(storage_schema)
    }
}

impl From<ConstantFeePolicy> for AccountComponent {
    fn from(policy: ConstantFeePolicy) -> Self {
        let fee_asset_id_slot = StorageSlot::with_value(
            ConstantFeePolicy::fee_asset_id_slot_name().clone(),
            policy.fee_asset_id.to_word(),
        );

        // Each fee is stored as an asset value word so that `compute_note_fee` can return the
        // map entry as FEE_ASSET_VALUE unmodified.
        let entries = policy.fee_schedule.into_iter().map(|(root, fee)| {
            (
                StorageMapKey::new(root.as_word()),
                Word::new([fee.into(), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
            )
        });
        let fee_schedule_map = StorageMap::with_entries(entries)
            .expect("fee schedule entries should produce a valid storage map");
        let fee_schedule_slot = StorageSlot::with_map(
            ConstantFeePolicy::fee_schedule_slot_name().clone(),
            fee_schedule_map,
        );

        AccountComponent::new(
            ConstantFeePolicy::code().clone(),
            vec![fee_asset_id_slot, fee_schedule_slot],
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
    use miden_protocol::account::{AccountBuilder, AccountType, StorageSlotContent};
    use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;

    use super::*;
    use crate::account::auth::NoAuth;
    use crate::account::fees::{FeeManager, FeePolicy};

    fn fee_faucet_id() -> AccountId {
        AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)
            .expect("testing account ID should be valid")
    }

    /// Check that the policy's storage slots contain the fee asset ID and the fee schedule
    /// entries.
    #[test]
    fn storage_slots_contain_expected_entries() -> anyhow::Result<()> {
        let script_root = NoteScriptRoot::from_array([1, 2, 3, 4]);
        let fee = AssetAmount::new(500)?;

        let policy = ConstantFeePolicy::new(fee_faucet_id()).with_fee(script_root, fee);
        let fee_manager =
            FeeManager::builder().active_fee_policy(FeePolicy::constant(policy)).build();

        let account = AccountBuilder::new([1; 32])
            .account_type(AccountType::Public)
            .with_auth_component(NoAuth)
            .with_components(fee_manager)
            .build_existing()?;

        let fee_asset_id_word =
            account.storage().get_item(ConstantFeePolicy::fee_asset_id_slot_name())?;
        assert_eq!(fee_asset_id_word, AssetId::new_fungible(fee_faucet_id()).to_word());

        let slot = account
            .storage()
            .get(ConstantFeePolicy::fee_schedule_slot_name())
            .expect("fee schedule slot should exist");
        let StorageSlotContent::Map(map) = slot.content() else {
            panic!("fee schedule slot must be a map");
        };
        assert_eq!(
            map.get(&StorageMapKey::new(script_root.as_word())),
            Word::new([Felt::from(500u32), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
            "the fee entry should be stored as an asset value word"
        );

        Ok(())
    }
}
