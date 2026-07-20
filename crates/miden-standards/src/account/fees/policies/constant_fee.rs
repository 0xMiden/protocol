use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use miden_crypto_derive::WordWrapper;
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
use thiserror::Error;

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

static ACTIVE_LOOKUP_KEY_BUILDER_PROC_ROOT_SLOT_NAME: LazyLock<StorageSlotName> =
    LazyLock::new(|| {
        StorageSlotName::new(
            "miden::standards::fees::policies::constant_fee::active_lookup_key_builder_proc_root",
        )
        .expect("storage slot name should be valid")
    });

static ALLOWED_LOOKUP_KEY_BUILDER_PROC_ROOTS_SLOT_NAME: LazyLock<StorageSlotName> =
    LazyLock::new(|| {
        StorageSlotName::new(
            "miden::standards::fees::policies::constant_fee::allowed_lookup_key_builder_proc_roots",
        )
        .expect("storage slot name should be valid")
    });

// NOTE FEE LOOKUP KEY
// ================================================================================================

/// Key under which a fee schedule entry is stored in a [`ConstantFeePolicy`].
///
/// The on-chain policy computes this key from the note parameters via the active lookup-key
/// builder procedure stored in its [`ConstantFeePolicy::active_lookup_key_builder_slot`] slot; a
/// note's fee is the schedule entry stored under the computed key. The default
/// `build_default_note_fee_lookup_key` procedure uses the note's script root as the key, which
/// the [`NoteScriptRoot`] conversion mirrors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, WordWrapper)]
pub struct NoteFeeLookupKey(Word);

impl From<NoteScriptRoot> for NoteFeeLookupKey {
    /// Converts a [`NoteScriptRoot`] into the lookup key the default
    /// `build_default_note_fee_lookup_key` procedure produces for a note with that script root.
    fn from(root: NoteScriptRoot) -> Self {
        Self(root.as_word())
    }
}

// NOTE FEE LOOKUP KEY BUILDER
// ================================================================================================

/// Errors returned by [`NoteFeeLookupKeyBuilder::custom`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum NoteFeeLookupKeyBuilderError {
    /// The procedure root supplied to [`NoteFeeLookupKeyBuilder::custom`] is not exported by any
    /// of the provided components.
    #[error(
        "custom lookup-key builder root must match a procedure root in one of the provided components"
    )]
    RootNotInComponents,
}

/// Descriptor for a lookup-key builder procedure registered with a [`ConstantFeePolicy`].
///
/// Binds the procedure root the policy dispatches to (via `dyncall`) with any companion
/// [`AccountComponent`]s that must be installed for the procedure to work. The procedure must
/// match the `build_default_note_fee_lookup_key` interface (unchecked on-chain; a non-conforming
/// one yields schedule-miss keys that abort fee estimation).
///
/// Construct via [`NoteFeeLookupKeyBuilder::default`] (keys on the note's script root) or
/// [`Self::custom`]. Pass to a [`ConstantFeePolicy`] via
/// [`ConstantFeePolicy::with_active_lookup_key_builder`] or
/// [`ConstantFeePolicy::with_allowed_lookup_key_builder`].
#[derive(Debug, Clone)]
pub struct NoteFeeLookupKeyBuilder {
    root: AccountProcedureRoot,
    components: Vec<AccountComponent>,
}

impl Default for NoteFeeLookupKeyBuilder {
    /// Returns the default lookup-key builder: the `build_default_note_fee_lookup_key` procedure
    /// of the `constant_fee` component itself, which keys the fee schedule on the note's script
    /// root.
    fn default() -> Self {
        Self {
            root: ConstantFeePolicy::default_lookup_key_builder_root(),
            components: Vec::new(),
        }
    }
}

impl NoteFeeLookupKeyBuilder {
    /// Returns a lookup-key builder resolving to `root` and shipping the provided companion
    /// `components` (anything that can be converted into an [`AccountComponent`]).
    ///
    /// # Errors
    ///
    /// Returns [`NoteFeeLookupKeyBuilderError::RootNotInComponents`] if `root` is not the
    /// procedure root of any procedure exported by the provided components.
    pub fn custom<I>(
        root: AccountProcedureRoot,
        components: I,
    ) -> Result<Self, NoteFeeLookupKeyBuilderError>
    where
        I: IntoIterator,
        I::Item: Into<AccountComponent>,
    {
        let components: Vec<AccountComponent> = components.into_iter().map(Into::into).collect();
        if !components.iter().any(|component| component.has_procedure(root)) {
            return Err(NoteFeeLookupKeyBuilderError::RootNotInComponents);
        }
        Ok(Self { root, components })
    }

    /// Returns the procedure root of the lookup-key builder this descriptor resolves to.
    pub fn root(&self) -> AccountProcedureRoot {
        self.root
    }
}

impl IntoIterator for NoteFeeLookupKeyBuilder {
    type Item = AccountComponent;
    type IntoIter = alloc::vec::IntoIter<AccountComponent>;

    /// Yields the companion [`AccountComponent`]s carried by this lookup-key builder descriptor.
    fn into_iter(self) -> Self::IntoIter {
        self.components.into_iter()
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
/// from the note parameters by the active lookup-key builder procedure stored in the policy's
/// [`Self::active_lookup_key_builder_slot`] slot, and lookup keys without a schedule entry abort
/// fee estimation. To make a lookup key free, schedule an explicit 0 fee via
/// [`ConstantFeePolicy::with_fee`]. The active builder defaults to the
/// `build_default_note_fee_lookup_key` procedure ([`NoteFeeLookupKeyBuilder::default`]), which keys
/// on the note's script root (recovered from the note's recipient via the advice provider) and
/// ignores the remaining parameters, including the timeframe and priority. The manager asserts
/// the returned fee asset ID matches the fee asset ID it stores itself, so a policy configured
/// with a different fee asset than its manager aborts fee estimation.
///
/// A custom key computation is installed by activating a [`NoteFeeLookupKeyBuilder`] via
/// [`Self::with_active_lookup_key_builder`]; its companion components are bundled into the
/// policy's component set. Additional builders may be registered for future runtime switching
/// via [`Self::with_allowed_lookup_key_builder`]. The stored root must be an account procedure
/// (enforced on dispatch) matching the `build_default_note_fee_lookup_key` interface (unchecked
/// on-chain; a non-conforming one yields schedule-miss keys that abort fee estimation).
///
/// ## Storage layout
///
/// - [`Self::fee_asset_id_slot_name`] value slot: the [`AssetId`] word of the fungible asset the
///   fee is charged in.
/// - [`Self::fee_schedule_slot_name`] map slot: `LOOKUP_KEY => [fee_amount, 0, 0, 1]`, where the
///   last element is a set-marker distinguishing scheduled entries from unset keys.
/// - [`Self::active_lookup_key_builder_slot`] value slot: the root of the active procedure that
///   builds the fee schedule lookup key.
/// - [`Self::allowed_lookup_key_builders_slot`] map slot: the registered lookup-key builder roots,
///   reserved for runtime switching.
#[derive(Debug, Clone)]
pub struct ConstantFeePolicy {
    /// The ID of the fungible asset the fee is charged in.
    fee_asset_id: AssetId,
    /// The fee charged per lookup key.
    fee_schedule: BTreeMap<NoteFeeLookupKey, AssetAmount>,
    /// The lookup-key builder the policy dispatches to.
    active_lookup_key_builder: NoteFeeLookupKeyBuilder,
    /// Reserved lookup-key builders registered for runtime switching, keyed by procedure root.
    allowed_lookup_key_builders: BTreeMap<AccountProcedureRoot, NoteFeeLookupKeyBuilder>,
}

impl ConstantFeePolicy {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::fees::policies::constant_fee";

    pub(crate) const PROC_NAME: &str = "compute_note_fee";

    pub(crate) const LOOKUP_KEY_PROC_NAME: &str = "build_default_note_fee_lookup_key";

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new `constant_fee` fee policy with an empty fee schedule, charging fees in the
    /// fungible asset issued by the given faucet. The active lookup-key builder defaults to the
    /// `build_default_note_fee_lookup_key` procedure, which keys on the note's script root.
    pub fn new(fee_faucet_id: AccountId) -> Self {
        Self {
            fee_asset_id: AssetId::new_fungible(fee_faucet_id),
            fee_schedule: BTreeMap::new(),
            active_lookup_key_builder: NoteFeeLookupKeyBuilder::default(),
            allowed_lookup_key_builders: BTreeMap::new(),
        }
    }

    /// Sets the fee for notes with the given lookup key, replacing any previous entry.
    ///
    /// The key must match the output of the policy's active lookup-key builder for the targeted
    /// notes; with the default `build_default_note_fee_lookup_key`, that is the note's script
    /// root. Scheduling an explicit fee of 0 makes matching notes free; lookup keys without a
    /// schedule entry abort fee estimation.
    #[must_use]
    pub fn with_fee(mut self, lookup_key: impl Into<NoteFeeLookupKey>, fee: AssetAmount) -> Self {
        self.fee_schedule.insert(lookup_key.into(), fee);
        self
    }

    /// Sets the lookup-key builder the policy dispatches to, replacing the default. Its
    /// companion components are bundled into the policy's component set.
    #[must_use]
    pub fn with_active_lookup_key_builder(mut self, builder: NoteFeeLookupKeyBuilder) -> Self {
        self.active_lookup_key_builder = builder;
        self
    }

    /// Registers a reserved lookup-key builder in the `allowed_lookup_key_builder_proc_roots`
    /// map for future runtime switching. Its companion components are bundled into the policy's
    /// component set. Registered entries are deduplicated by procedure root.
    #[must_use]
    pub fn with_allowed_lookup_key_builder(mut self, builder: NoteFeeLookupKeyBuilder) -> Self {
        self.allowed_lookup_key_builders.insert(builder.root(), builder);
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

    /// Returns the procedure root of the default `build_default_note_fee_lookup_key` procedure,
    /// which keys the fee schedule on the note's script root.
    pub fn default_lookup_key_builder_root() -> AccountProcedureRoot {
        *CONSTANT_FEE_POLICY_LOOKUP_KEY_PROC_ROOT
    }

    /// Returns the procedure root of the active lookup-key builder.
    pub fn active_lookup_key_builder_root(&self) -> AccountProcedureRoot {
        self.active_lookup_key_builder.root()
    }

    /// Returns all registered lookup-key builder procedure roots (active + reserved).
    pub fn allowed_lookup_key_builder_roots(&self) -> Vec<AccountProcedureRoot> {
        let mut roots = vec![self.active_lookup_key_builder.root()];
        roots.extend(
            self.allowed_lookup_key_builders
                .keys()
                .filter(|root| **root != self.active_lookup_key_builder.root())
                .copied(),
        );
        roots
    }

    /// Returns the [`StorageSlotName`] of the slot holding the fee asset ID.
    pub fn fee_asset_id_slot_name() -> &'static StorageSlotName {
        &FEE_ASSET_ID_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] of the slot holding the fee schedule map.
    pub fn fee_schedule_slot_name() -> &'static StorageSlotName {
        &FEE_SCHEDULE_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] of the slot holding the active lookup-key builder root.
    pub fn active_lookup_key_builder_slot() -> &'static StorageSlotName {
        &ACTIVE_LOOKUP_KEY_BUILDER_PROC_ROOT_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] of the map slot holding the registered lookup-key builder
    /// roots.
    pub fn allowed_lookup_key_builders_slot() -> &'static StorageSlotName {
        &ALLOWED_LOOKUP_KEY_BUILDER_PROC_ROOTS_SLOT_NAME
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
                Self::active_lookup_key_builder_slot().clone(),
                StorageSlotSchema::value(
                    "Root of the active procedure that builds the fee schedule lookup key",
                    SchemaType::native_word(),
                ),
            ),
            (
                Self::allowed_lookup_key_builders_slot().clone(),
                StorageSlotSchema::map(
                    "Registered lookup-key builder procedure roots",
                    SchemaType::native_word(),
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

impl ConstantFeePolicy {
    /// Builds the `allowed_lookup_key_builder_proc_roots` storage map from the registered
    /// lookup-key builders (active + reserved). Each entry maps the builder procedure root to a
    /// non-zero flag, so a future switching procedure can confirm the root is allowed before
    /// activating it.
    fn build_allowed_lookup_key_builders_map(&self) -> StorageMap {
        let allowed_flag = Word::from([1u32, 0, 0, 0]);
        let entries: Vec<_> = self
            .allowed_lookup_key_builder_roots()
            .into_iter()
            .map(|root| (StorageMapKey::new(root.as_word()), allowed_flag))
            .collect();
        StorageMap::with_entries(entries)
            .expect("allowed lookup-key builder roots should have unique keys")
    }

    /// Builds the `constant_fee` policy component itself, without the companion components
    /// contributed by the registered lookup-key builders.
    fn to_policy_component(&self) -> AccountComponent {
        let fee_asset_id_slot = StorageSlot::with_value(
            Self::fee_asset_id_slot_name().clone(),
            self.fee_asset_id.to_word(),
        );

        let entries = self.fee_schedule.iter().map(|(lookup_key, fee)| {
            (StorageMapKey::new(lookup_key.as_word()), fee_schedule_entry(*fee))
        });
        let fee_schedule_map = StorageMap::with_entries(entries)
            .expect("fee schedule entries should produce a valid storage map");
        let fee_schedule_slot =
            StorageSlot::with_map(Self::fee_schedule_slot_name().clone(), fee_schedule_map);

        let active_lookup_key_builder_slot = StorageSlot::with_value(
            Self::active_lookup_key_builder_slot().clone(),
            self.active_lookup_key_builder.root().as_word(),
        );

        let allowed_lookup_key_builders_slot = StorageSlot::with_map(
            Self::allowed_lookup_key_builders_slot().clone(),
            self.build_allowed_lookup_key_builders_map(),
        );

        AccountComponent::new(
            Self::code().clone(),
            vec![
                fee_asset_id_slot,
                fee_schedule_slot,
                active_lookup_key_builder_slot,
                allowed_lookup_key_builders_slot,
            ],
            Self::component_metadata(),
        )
        .expect(
            "`constant_fee` fee policy component should satisfy the requirements of a valid account component",
        )
    }
}

impl IntoIterator for ConstantFeePolicy {
    type Item = AccountComponent;
    type IntoIter = alloc::vec::IntoIter<AccountComponent>;

    /// Yields the [`AccountComponent`]s implementing this fee policy configuration: the policy
    /// component itself first, then the companion components contributed by the active and every
    /// reserved lookup-key builder. Deduplication of reserved builders by procedure root is
    /// implicit (the internal map is keyed by root).
    fn into_iter(self) -> Self::IntoIter {
        let policy_component = self.to_policy_component();
        let mut components = vec![policy_component];
        components.extend(self.active_lookup_key_builder);
        for (_, builder) in self.allowed_lookup_key_builders {
            components.extend(builder);
        }
        components.into_iter()
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
        let fee_manager = FeeManager::builder()
            .fee_faucet_id(fee_faucet_id())
            .active_fee_policy(policy.into())
            .build();

        let account = AccountBuilder::new([1; 32])
            .account_type(AccountType::Public)
            .with_auth_component(NoAuth)
            .with_components(fee_manager)
            .build_existing()?;

        let fee_asset_id_slot = account
            .storage()
            .get(ConstantFeePolicy::fee_asset_id_slot_name())
            .expect("fee asset ID slot should exist");
        assert_eq!(
            fee_asset_id_slot.value(),
            AssetId::new_fungible(fee_faucet_id()).to_word(),
            "the fee asset ID slot should hold the configured fee asset ID"
        );

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

        let active_builder_word = account
            .storage()
            .get_item(ConstantFeePolicy::active_lookup_key_builder_slot())?;
        assert_eq!(
            active_builder_word,
            ConstantFeePolicy::default_lookup_key_builder_root().as_word(),
            "the active lookup-key builder slot should hold the default builder root"
        );

        let allowed_slot = account
            .storage()
            .get(ConstantFeePolicy::allowed_lookup_key_builders_slot())
            .expect("allowed lookup-key builders slot should exist");
        let StorageSlotContent::Map(allowed_map) = allowed_slot.content() else {
            panic!("allowed lookup-key builders slot must be a map");
        };
        assert_eq!(
            allowed_map.get(&StorageMapKey::new(
                ConstantFeePolicy::default_lookup_key_builder_root().as_word()
            )),
            Word::from([1u32, 0, 0, 0]),
            "the active builder root should be registered in the allowed map"
        );

        Ok(())
    }
}
