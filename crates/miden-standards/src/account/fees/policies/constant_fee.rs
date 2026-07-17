use alloc::collections::BTreeMap;

use miden_protocol::account::component::{
    AccountComponentCode, AccountComponentMetadata, SchemaType, StorageSchema, StorageSlotSchema,
};
use miden_protocol::account::{
    AccountComponent, AccountComponentName, AccountId, AccountProcedureRoot, StorageMap,
    StorageMapKey, StorageSlot, StorageSlotName,
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

procedure_root!(
    CONSTANT_FEE_POLICY_LOOKUP_KEY_PROC_ROOT,
    ConstantFeePolicy::NAME,
    ConstantFeePolicy::LOOKUP_KEY_PROC_NAME,
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

static LOOKUP_KEY_PROC_ROOT_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::fees::policies::constant_fee::lookup_key_proc_root")
        .expect("storage slot name should be valid")
});

// NOTE FEE LOOKUP KEY
// ================================================================================================

/// Key under which a fee schedule entry is stored in a [`ConstantFeePolicy`].
///
/// The on-chain policy computes this key from the note parameters via the lookup-key procedure
/// stored in its [`ConstantFeePolicy::lookup_key_proc_root_slot_name`] slot; a note's fee is the
/// schedule entry stored under the computed key. The built-in `build_note_fee_lookup_key`
/// procedure uses the note's script root as the key, which the [`NoteScriptRoot`] conversion
/// mirrors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NoteFeeLookupKey(Word);

impl NoteFeeLookupKey {
    /// Creates a new [`NoteFeeLookupKey`] from the given word.
    pub fn new(word: Word) -> Self {
        Self(word)
    }

    /// Returns the underlying [`Word`] of the lookup key.
    pub fn as_word(&self) -> Word {
        self.0
    }
}

impl From<NoteScriptRoot> for NoteFeeLookupKey {
    /// Converts a [`NoteScriptRoot`] into the lookup key the built-in `build_note_fee_lookup_key`
    /// procedure produces for a note with that script root.
    fn from(root: NoteScriptRoot) -> Self {
        Self(root.as_word())
    }
}

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
/// policy's `compute_note_fee` procedure, which returns the fee as a fee asset (asset ID and
/// value words): the amount is looked up in the fee schedule under a [`NoteFeeLookupKey`] built
/// from the note parameters by the lookup-key procedure stored in the policy's
/// [`Self::lookup_key_proc_root_slot_name`] slot, and lookup keys without a schedule entry abort
/// fee estimation. To make a lookup key free, schedule an explicit 0 fee via
/// [`ConstantFeePolicy::with_fee`]. The slot defaults to the built-in `build_note_fee_lookup_key`
/// procedure ([`Self::lookup_key_proc_root`]), which keys on the note's script root.
///
/// The `From<ConstantFeePolicy>` conversion always writes the built-in root; a custom lookup-key
/// procedure requires building the [`AccountComponent`] manually. The stored root must be an
/// account procedure (enforced on dispatch) matching the `build_note_fee_lookup_key` interface
/// (unchecked on-chain; a non-conforming one yields schedule-miss keys that abort fee estimation).
///
/// ## Storage layout
///
/// - [`Self::fee_asset_id_slot_name`] value slot: the [`AssetId`] word of the fungible asset the
///   fee is charged in.
/// - [`Self::fee_schedule_slot_name`] map slot: `LOOKUP_KEY => [fee_amount, 0, 0, 1]`, where the
///   last element is a set-marker distinguishing scheduled entries from unset keys.
/// - [`Self::lookup_key_proc_root_slot_name`] value slot: the root of the procedure that builds the
///   fee schedule lookup key.
#[derive(Debug, Clone)]
pub struct ConstantFeePolicy {
    /// The ID of the fungible asset the fee is charged in.
    fee_asset_id: AssetId,
    /// The fee charged per lookup key.
    fee_schedule: BTreeMap<NoteFeeLookupKey, AssetAmount>,
}

impl ConstantFeePolicy {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::fees::policies::constant_fee";

    pub(crate) const PROC_NAME: &str = "compute_note_fee";

    pub(crate) const LOOKUP_KEY_PROC_NAME: &str = "build_note_fee_lookup_key";

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

    /// Sets the fee for notes with the given lookup key, replacing any previous entry.
    ///
    /// The key must match the output of the policy's lookup-key procedure for the targeted
    /// notes; with the built-in `build_note_fee_lookup_key`, that is the note's script root.
    /// Scheduling an explicit fee of 0 makes matching notes free; lookup keys without a schedule
    /// entry abort fee estimation.
    #[must_use]
    pub fn with_fee(mut self, lookup_key: impl Into<NoteFeeLookupKey>, fee: AssetAmount) -> Self {
        self.fee_schedule.insert(lookup_key.into(), fee);
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

    /// Returns the procedure root of the built-in `build_note_fee_lookup_key` procedure, which
    /// keys the fee schedule on the note's script root.
    pub fn lookup_key_proc_root() -> AccountProcedureRoot {
        *CONSTANT_FEE_POLICY_LOOKUP_KEY_PROC_ROOT
    }

    /// Returns the [`StorageSlotName`] of the slot holding the fee asset ID.
    pub fn fee_asset_id_slot_name() -> &'static StorageSlotName {
        &FEE_ASSET_ID_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] of the slot holding the fee schedule map.
    pub fn fee_schedule_slot_name() -> &'static StorageSlotName {
        &FEE_SCHEDULE_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] of the slot holding the lookup-key procedure root.
    pub fn lookup_key_proc_root_slot_name() -> &'static StorageSlotName {
        &LOOKUP_KEY_PROC_ROOT_SLOT_NAME
    }

    /// Returns the [`AssetId`] of the fungible asset the fee is charged in.
    pub fn fee_asset_id(&self) -> AssetId {
        self.fee_asset_id
    }

    /// Returns the fee charged per lookup key.
    pub fn fee_schedule(&self) -> &BTreeMap<NoteFeeLookupKey, AssetAmount> {
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
                    "Fee charged per lookup key, as [fee_amount, 0, 0, 1] with a set-marker \
                     as the last element",
                    SchemaType::native_word(),
                    SchemaType::native_word(),
                ),
            ),
            (
                Self::lookup_key_proc_root_slot_name().clone(),
                StorageSlotSchema::value(
                    "Root of the procedure that builds the fee schedule lookup key",
                    SchemaType::native_word(),
                ),
            ),
        ])
        .expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME)
            .with_description("`constant_fee` fee policy charging a constant per-lookup-key fee")
            .with_storage_schema(storage_schema)
    }
}

impl From<ConstantFeePolicy> for AccountComponent {
    fn from(policy: ConstantFeePolicy) -> Self {
        let fee_asset_id_slot = StorageSlot::with_value(
            ConstantFeePolicy::fee_asset_id_slot_name().clone(),
            policy.fee_asset_id.to_word(),
        );

        let entries = policy.fee_schedule.into_iter().map(|(lookup_key, fee)| {
            (StorageMapKey::new(lookup_key.as_word()), fee_schedule_entry(fee))
        });
        let fee_schedule_map = StorageMap::with_entries(entries)
            .expect("fee schedule entries should produce a valid storage map");
        let fee_schedule_slot = StorageSlot::with_map(
            ConstantFeePolicy::fee_schedule_slot_name().clone(),
            fee_schedule_map,
        );

        let lookup_key_proc_root_slot = StorageSlot::with_value(
            ConstantFeePolicy::lookup_key_proc_root_slot_name().clone(),
            ConstantFeePolicy::lookup_key_proc_root().as_word(),
        );

        AccountComponent::new(
            ConstantFeePolicy::code().clone(),
            vec![fee_asset_id_slot, fee_schedule_slot, lookup_key_proc_root_slot],
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
    use crate::account::fees::FeeManager;

    fn fee_faucet_id() -> AccountId {
        AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)
            .expect("testing account ID should be valid")
    }

    /// Check that the policy's storage slots contain the fee asset ID, the fee schedule
    /// entries, and the lookup-key procedure root.
    #[test]
    fn storage_slots_contain_expected_entries() -> anyhow::Result<()> {
        let script_root = NoteScriptRoot::from_array([1, 2, 3, 4]);
        let fee = AssetAmount::new(500)?;
        let free_script_root = NoteScriptRoot::from_array([5, 6, 7, 8]);

        let policy = ConstantFeePolicy::new(fee_faucet_id())
            .with_fee(script_root, fee)
            .with_fee(free_script_root, AssetAmount::ZERO);
        let fee_manager = FeeManager::builder().active_fee_policy(policy.into()).build();

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
            Word::new([Felt::new(500)?, Felt::ZERO, Felt::ZERO, Felt::ONE]),
            "the fee entry should be stored under the note's script root with the set-marker"
        );
        assert_eq!(
            map.get(&StorageMapKey::new(free_script_root.as_word())),
            Word::new([Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::ONE]),
            "an explicit 0-fee entry should survive as a non-zero word"
        );

        let lookup_key_proc_root_word = account
            .storage()
            .get_item(ConstantFeePolicy::lookup_key_proc_root_slot_name())?;
        assert_eq!(
            lookup_key_proc_root_word,
            ConstantFeePolicy::lookup_key_proc_root().as_word(),
            "the lookup-key procedure root slot should default to the built-in procedure"
        );

        Ok(())
    }
}
