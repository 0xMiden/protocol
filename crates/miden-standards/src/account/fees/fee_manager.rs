use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use miden_protocol::account::component::{
    AccountComponentCode,
    AccountComponentMetadata,
    FeltSchema,
    SchemaType,
    StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{
    AccountComponent,
    AccountId,
    AccountProcedureRoot,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::FungibleAsset;
use miden_protocol::errors::AccountError;
use miden_protocol::note::NoteScriptRoot;
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};

use crate::account::account_component_code;
use crate::procedure_root;

// COMPONENT CODE AND PROCEDURE ROOTS
// ================================================================================================

account_component_code!(FEE_MANAGER_CODE, "miden-standards-fees-fee-manager.masp");

static FEE_ASSET_ID_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::fees::fee_manager::fee_asset_id")
        .expect("storage slot name should be valid")
});

static FEE_SCHEDULE_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::fees::fee_manager::fee_schedule")
        .expect("storage slot name should be valid")
});

procedure_root!(
    FEE_MANAGER_GET_FEE_ASSET_ID_ROOT,
    FeeManager::NAME,
    "get_fee_asset_id",
    FeeManager::code()
);
procedure_root!(
    FEE_MANAGER_ESTIMATE_NOTE_FEE_ROOT,
    FeeManager::NAME,
    "estimate_note_fee",
    FeeManager::code()
);
procedure_root!(FEE_MANAGER_SET_FEE_ROOT, FeeManager::NAME, "set_fee", FeeManager::code());
procedure_root!(FEE_MANAGER_REMOVE_FEE_ROOT, FeeManager::NAME, "remove_fee", FeeManager::code());

// FEE SCHEDULE ENTRY
// ================================================================================================

/// The price a network account charges for consuming one note script.
///
/// The two portions travel together in a single sponsorship note, but they end up in different
/// places: `app_fee` stays with the account as payment for the note's business logic, while
/// `protocol_fee` is forwarded to the batch builder in a
/// [`FeeNote`](crate::note::FeeNote).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeScheduleEntry {
    app_fee: u64,
    protocol_fee: u64,
    enabled: bool,
}

impl FeeScheduleEntry {
    /// Creates an enabled entry with the provided application and protocol fee portions.
    ///
    /// # Errors
    ///
    /// Returns an error if the two portions together exceed [`FungibleAsset::MAX_AMOUNT`]. The two
    /// are always charged as a single fungible asset, so a total that cannot be represented as one
    /// is unusable, and a schedule that admits it would only fail later, inside the transaction.
    pub fn new(app_fee: u64, protocol_fee: u64) -> Result<Self, AccountError> {
        let total = app_fee.checked_add(protocol_fee).ok_or_else(|| {
            AccountError::other("fee schedule entry overflows when its portions are summed")
        })?;

        if total > u64::from(FungibleAsset::MAX_AMOUNT) {
            return Err(AccountError::other(
                "fee schedule entry exceeds the maximum fungible asset amount",
            ));
        }

        Ok(Self { app_fee, protocol_fee, enabled: true })
    }

    /// Creates a disabled entry, which prices its script as denied rather than absent.
    pub const fn disabled() -> Self {
        Self {
            app_fee: 0,
            protocol_fee: 0,
            enabled: false,
        }
    }

    /// Returns the portion the account keeps.
    pub const fn app_fee(&self) -> u64 {
        self.app_fee
    }

    /// Returns the portion forwarded to the batch builder.
    pub const fn protocol_fee(&self) -> u64 {
        self.protocol_fee
    }

    /// Returns the total fee required to consume a note bearing this script root.
    ///
    /// Cannot overflow: the constructor rejects portions whose sum exceeds
    /// [`FungibleAsset::MAX_AMOUNT`].
    pub const fn total(&self) -> u64 {
        self.app_fee + self.protocol_fee
    }

    /// Returns whether the entry is enabled.
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Encodes the entry as the storage map value `[app_fee, protocol_fee, enabled, 0]`.
    fn to_word(self) -> Word {
        // Both portions are bounded by `FungibleAsset::MAX_AMOUNT`, which is below the field
        // modulus, so neither conversion can fail.
        Word::new([
            Felt::new(self.app_fee).expect("fee portion is bounded by MAX_AMOUNT"),
            Felt::new(self.protocol_fee).expect("fee portion is bounded by MAX_AMOUNT"),
            Felt::from(u8::from(self.enabled)),
            Felt::ZERO,
        ])
    }
}

// FEE MANAGER
// ================================================================================================

/// Account component holding the price list a network account charges for consuming notes.
///
/// It answers "what does this note cost?" and nothing else. The component never touches assets:
/// moving the fee is the job of the
/// [`NetworkSponsorshipNote`](crate::note::NetworkSponsorshipNote) and the account's auth
/// procedure.
///
/// `get_fee_asset_id` and `estimate_note_fee` are read-only and reachable over a foreign procedure
/// invocation, so that a note creator -- or an upstream network account pricing a note it is about
/// to spawn -- can size the sponsorship before the note exists. This is what makes chained network
/// transactions work without the upstream account fronting any liquidity.
///
/// # Dependencies
///
/// The account must also install the [`Authority`](crate::account::access::Authority) component,
/// whose `assert_authorized` gates `set_fee` and `remove_fee`.
#[derive(Debug, Clone)]
pub struct FeeManager {
    fee_asset_id: Word,
    schedule: BTreeMap<NoteScriptRoot, FeeScheduleEntry>,
}

impl FeeManager {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::fees::fee_manager";

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a [`FeeManager`] accepting fees in the fungible asset issued by `fee_faucet`, with
    /// an empty schedule.
    ///
    /// # Errors
    ///
    /// Returns an error if `fee_faucet` does not issue fungible assets.
    pub fn new(fee_faucet: AccountId) -> Result<Self, AccountError> {
        let fee_asset = FungibleAsset::new(fee_faucet, 0).map_err(|error| {
            AccountError::other_with_source("fee faucet must issue fungible assets", error)
        })?;

        Ok(Self {
            fee_asset_id: fee_asset.to_id_word(),
            schedule: BTreeMap::new(),
        })
    }

    /// Prices the provided note script root.
    pub fn with_fee(mut self, script_root: NoteScriptRoot, entry: FeeScheduleEntry) -> Self {
        self.schedule.insert(script_root, entry);
        self
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &FEE_MANAGER_CODE
    }

    /// Returns the procedure root of the `get_fee_asset_id` procedure.
    pub fn get_fee_asset_id_root() -> AccountProcedureRoot {
        *FEE_MANAGER_GET_FEE_ASSET_ID_ROOT
    }

    /// Returns the procedure root of the `estimate_note_fee` procedure.
    pub fn estimate_note_fee_root() -> AccountProcedureRoot {
        *FEE_MANAGER_ESTIMATE_NOTE_FEE_ROOT
    }

    /// Returns the procedure root of the `set_fee` procedure.
    pub fn set_fee_root() -> AccountProcedureRoot {
        *FEE_MANAGER_SET_FEE_ROOT
    }

    /// Returns the procedure root of the `remove_fee` procedure.
    pub fn remove_fee_root() -> AccountProcedureRoot {
        *FEE_MANAGER_REMOVE_FEE_ROOT
    }

    /// Returns the storage slot name of the fee asset ID.
    pub fn fee_asset_id_slot() -> &'static StorageSlotName {
        &FEE_ASSET_ID_SLOT_NAME
    }

    /// Returns the storage slot name of the fee schedule map.
    pub fn fee_schedule_slot() -> &'static StorageSlotName {
        &FEE_SCHEDULE_SLOT_NAME
    }

    /// Returns the ASSET_ID word of the asset this account accepts fees in.
    pub fn fee_asset_id(&self) -> Word {
        self.fee_asset_id
    }

    /// Returns the fee schedule entry for the provided script root, if any.
    pub fn fee(&self, script_root: &NoteScriptRoot) -> Option<FeeScheduleEntry> {
        self.schedule.get(script_root).copied()
    }

    /// Returns the [`AccountComponentMetadata`] of this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let slots = vec![
            (
                FEE_ASSET_ID_SLOT_NAME.clone(),
                StorageSlotSchema::value(
                    "ASSET_ID of the asset this account accepts fees in",
                    [
                        FeltSchema::felt("asset_id_0"),
                        FeltSchema::felt("asset_id_1"),
                        FeltSchema::felt("asset_id_2"),
                        FeltSchema::felt("asset_id_3"),
                    ],
                ),
            ),
            (
                FEE_SCHEDULE_SLOT_NAME.clone(),
                StorageSlotSchema::map(
                    "Fee schedule (note script root -> [app_fee, protocol_fee, enabled, 0])",
                    SchemaType::native_word(),
                    SchemaType::native_word(),
                ),
            ),
        ];

        let storage_schema = StorageSchema::new(slots).expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME)
            .with_description(
                "FeeManager: holds the price a network account charges for consuming a note \
                 script, and the asset it accepts fees in. Read-only estimation is reachable over \
                 FPI so that a sponsorship can be sized before the note exists.",
            )
            .with_storage_schema(storage_schema)
    }
}

// CONVERSIONS
// ================================================================================================

impl From<FeeManager> for AccountComponent {
    fn from(fee_manager: FeeManager) -> Self {
        let entries = fee_manager.schedule.into_iter().map(|(script_root, entry)| {
            (StorageMapKey::new(script_root.as_word()), entry.to_word())
        });

        let slots: Vec<StorageSlot> = vec![
            StorageSlot::with_value(FEE_ASSET_ID_SLOT_NAME.clone(), fee_manager.fee_asset_id),
            StorageSlot::with_map(
                FEE_SCHEDULE_SLOT_NAME.clone(),
                StorageMap::with_entries(entries).expect("fee schedule map should be valid"),
            ),
        ];

        AccountComponent::new(FeeManager::code().clone(), slots, FeeManager::component_metadata())
            .expect("fee manager component should satisfy the requirements of a valid component")
    }
}
