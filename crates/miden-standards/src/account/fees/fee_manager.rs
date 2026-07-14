use alloc::collections::BTreeMap;

use miden_protocol::account::component::{
    AccountComponentCode,
    AccountComponentMetadata,
    SchemaType,
    StorageSchema,
    StorageSlotSchema,
    WordSchema,
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

// FEE MANAGER
// ================================================================================================

account_component_code!(FEE_MANAGER_CODE, "miden-standards-fees-fee-manager.masp");

// Initialize the procedure root of the `estimate_note_fee` procedure only once.
procedure_root!(
    FEE_MANAGER_ESTIMATE_NOTE_FEE,
    FeeManager::NAME,
    FeeManager::ESTIMATE_NOTE_FEE_PROC_NAME,
    FeeManager::code()
);

static FEE_ASSET_ID_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::fees::fee_manager::fee_asset_id")
        .expect("storage slot name should be valid")
});

static FEE_SCHEDULE_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::fees::fee_manager::fee_schedule")
        .expect("storage slot name should be valid")
});

/// An [`AccountComponent`] exposing fee estimation over a fixed per-note-script fee schedule.
///
/// The component's single procedure, `estimate_note_fee`, is designed to be `call`ed by external
/// callers - typically via FPI from the authentication component of an account that creates a
/// note targeted at this account. It returns the fee this account charges for a note with the
/// given parameters as a fee asset (asset ID and value words): the amount is looked up in the fee
/// schedule under the note's script root, and note scripts without a schedule entry estimate to
/// an amount of 0.
///
/// Both storage slots are populated at account creation and there are no on-chain setters.
///
/// ## Storage Layout
///
/// - `fee_asset_id` value slot: the [`AssetId`] word of the fungible asset this account accepts
///   fees in.
/// - `fee_schedule` map slot: `NOTE_SCRIPT_ROOT => [fee_amount, 0, 0, 0]`.
#[derive(Debug, Clone)]
pub struct FeeManager {
    /// The ID of the fungible asset this account accepts fees in.
    fee_asset_id: AssetId,
    /// The fee charged per note script root.
    fee_schedule: BTreeMap<NoteScriptRoot, AssetAmount>,
}

impl FeeManager {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::fees::fee_manager";

    const ESTIMATE_NOTE_FEE_PROC_NAME: &str = "estimate_note_fee";

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`FeeManager`] with an empty fee schedule, accepting fees in the fungible
    /// asset issued by the given faucet.
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
        &FEE_MANAGER_CODE
    }

    /// Returns the procedure root of the `estimate_note_fee` procedure.
    pub fn estimate_note_fee_root() -> AccountProcedureRoot {
        *FEE_MANAGER_ESTIMATE_NOTE_FEE
    }

    /// Returns the [`StorageSlotName`] of the slot holding the fee asset ID.
    pub fn fee_asset_id_slot_name() -> &'static StorageSlotName {
        &FEE_ASSET_ID_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] of the slot holding the fee schedule map.
    pub fn fee_schedule_slot_name() -> &'static StorageSlotName {
        &FEE_SCHEDULE_SLOT_NAME
    }

    /// Returns the [`AssetId`] of the fungible asset this account accepts fees in.
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
                    "ID of the fungible asset the account accepts fees in",
                    WordSchema::new_simple(SchemaType::native_word()),
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
            .with_description("Fee estimation over a fixed per-note-script fee schedule")
            .with_storage_schema(storage_schema)
    }
}

impl From<FeeManager> for AccountComponent {
    fn from(fee_manager: FeeManager) -> Self {
        let fee_asset_id_slot = StorageSlot::with_value(
            FeeManager::fee_asset_id_slot_name().clone(),
            fee_manager.fee_asset_id.to_word(),
        );

        // Each fee is stored as an asset value word so that `estimate_note_fee` can return the
        // map entry as FEE_ASSET_VALUE unmodified.
        let entries = fee_manager.fee_schedule.into_iter().map(|(root, fee)| {
            (
                StorageMapKey::new(root.as_word()),
                Word::new([fee.into(), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
            )
        });
        let fee_schedule_map = StorageMap::with_entries(entries)
            .expect("fee schedule entries should produce a valid storage map");
        let fee_schedule_slot =
            StorageSlot::with_map(FeeManager::fee_schedule_slot_name().clone(), fee_schedule_map);

        let metadata = FeeManager::component_metadata();

        AccountComponent::new(
            FeeManager::code().clone(),
            vec![fee_asset_id_slot, fee_schedule_slot],
            metadata,
        )
        .expect(
            "fee manager component should satisfy the requirements of a valid account component",
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

    fn fee_faucet_id() -> AccountId {
        AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)
            .expect("testing account ID should be valid")
    }

    /// Check that the component can be added to an account and that the resulting account exposes
    /// the `estimate_note_fee` procedure.
    #[test]
    fn account_exposes_estimate_note_fee() -> anyhow::Result<()> {
        let account = AccountBuilder::new([1; 32])
            .account_type(AccountType::Public)
            .with_auth_component(NoAuth)
            .with_component(FeeManager::new(fee_faucet_id()))
            .build_existing()?;

        assert!(account.code().has_procedure(*FeeManager::estimate_note_fee_root().mast_root()));

        Ok(())
    }

    /// Check that the component's storage slots contain the fee asset ID and the fee schedule
    /// entries.
    #[test]
    fn storage_slots_contain_expected_entries() -> anyhow::Result<()> {
        let script_root = NoteScriptRoot::from_array([1, 2, 3, 4]);
        let fee = AssetAmount::new(500)?;

        let account = AccountBuilder::new([1; 32])
            .account_type(AccountType::Public)
            .with_auth_component(NoAuth)
            .with_component(FeeManager::new(fee_faucet_id()).with_fee(script_root, fee))
            .build_existing()?;

        let fee_asset_id_word = account.storage().get_item(FeeManager::fee_asset_id_slot_name())?;
        assert_eq!(fee_asset_id_word, AssetId::new_fungible(fee_faucet_id()).to_word());

        let slot = account
            .storage()
            .get(FeeManager::fee_schedule_slot_name())
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
