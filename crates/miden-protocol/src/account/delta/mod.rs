use alloc::string::ToString;
use alloc::vec::Vec;

use crate::account::{Account, AccountCode, AccountId, AccountStorage, AccountStoragePatch};
use crate::asset::AssetVault;
use crate::crypto::SequentialCommit;
use crate::errors::{AccountDeltaError, AccountError};
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{Felt, Hasher, Word, ZERO};

mod delta_op;
pub use delta_op::AssetDeltaOperation;

mod vault;
pub use vault::{AccountVaultDelta, AssetDelta};

// ACCOUNT DELTA
// ================================================================================================

/// The [`AccountDelta`] stores the differences between two account states, which can result from
/// one or more transaction.
///
/// The differences are represented as follows:
/// - storage: an [`AccountStoragePatch`] that contains the changes to the account storage.
/// - vault: an [`AccountVaultDelta`] object that contains the changes to the account vault.
/// - nonce: if the nonce of the account has changed, the _delta_ of the nonce is stored, i.e. the
///   value by which the nonce increased.
/// - code: an [`AccountCode`] for new accounts and `None` for others.
///
/// The presence of the code in a delta signals if the delta is a _full state_ or _partial state_
/// delta. A full state delta must be converted into an [`Account`] object, while a partial state
/// delta must be applied to an existing [`Account`]. Because a full state delta reconstructs the
/// account from empty storage, its storage patch may only create slots, never update or remove
/// them; [`AccountDelta::new`] enforces this.
///
/// TODO(code_upgrades): The ability to track account code updates is an outstanding feature. For
/// that reason, the account code is not considered as part of the "nonce must be incremented if
/// state changed" check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountDelta {
    /// The ID of the account to which this delta applies. If the delta is created during
    /// transaction execution, that is the native account of the transaction.
    account_id: AccountId,
    /// The patch of the account's storage.
    storage: AccountStoragePatch,
    /// The delta of the account's asset vault.
    vault: AccountVaultDelta,
    /// The code of a new account (`Some`) or `None` for existing accounts.
    code: Option<AccountCode>,
    /// The value by which the nonce was incremented. Must be greater than zero if storage or vault
    /// are non-empty.
    nonce_delta: Felt,
}

impl AccountDelta {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Domain separator for the account delta commitment.
    ///
    /// It is placed in the capacity word of the hasher rather than in the hashed elements, so that
    /// it stays fixed even as the layout of those elements evolves across versions. The value is
    /// allocated from the range that the [Poseidon2 domain registry][registry] delegates to this
    /// repository.
    ///
    /// [registry]: https://github.com/0xMiden/crypto/blob/main/docs/registry/poseidon2-domains.toml
    const DOMAIN: Felt = Felt::new_unchecked(0x02_0001);

    /// Version 1 of the account delta commitment layout.
    ///
    /// The version occupies the first element of the commitment header, so a reader can get it
    /// before it interprets the rest of the commitment.
    const VERSION_1: u8 = 1;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns new [AccountDelta] instantiated from the provided components.
    ///
    /// `code` is `Some` for a full state delta (a new account) and `None` otherwise.
    ///
    /// # Errors
    ///
    /// - Returns an error if storage or vault were updated, but the nonce_delta is 0.
    /// - Returns an error if `code` is provided but the storage patch contains an `Update` or
    ///   `Remove` operation. A full state delta must reconstruct the account from empty storage, so
    ///   it may only create slots.
    pub fn new(
        account_id: AccountId,
        storage: AccountStoragePatch,
        vault: AccountVaultDelta,
        code: Option<AccountCode>,
        nonce_delta: Felt,
    ) -> Result<Self, AccountDeltaError> {
        // nonce must be updated if either account storage or vault were updated
        validate_nonce(nonce_delta, &storage, &vault)?;

        // A full state delta (carrying code) must reconstruct the account from empty storage, so it
        // may only create slots. An `Update` or `Remove` assumes the slot already exists and would
        // make reconstruction impossible.
        if code.is_some() && storage.contains_non_create_ops() {
            return Err(AccountDeltaError::FullStateDeltaContainsNonCreateOp);
        }

        Ok(Self {
            account_id,
            storage,
            vault,
            code,
            nonce_delta,
        })
    }

    // PUBLIC MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Returns a mutable reference to the account vault delta.
    pub fn vault_mut(&mut self) -> &mut AccountVaultDelta {
        &mut self.vault
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns true if this account delta does not contain any vault, storage or nonce updates.
    pub fn is_empty(&self) -> bool {
        self.storage.is_empty() && self.vault.is_empty() && self.nonce_delta == ZERO
    }

    /// Returns `true` if this delta is a "full state" delta, `false` otherwise, i.e. if it is a
    /// "partial state" delta.
    ///
    /// See the type-level docs for more on this distinction.
    pub fn is_full_state(&self) -> bool {
        // TODO(code_upgrades): Change this to another detection mechanism once we have code upgrade
        // support, at which point the presence of code may not be enough of an indication
        // that a delta can be converted to a full account.
        //
        // The presence of code alone is sufficient to identify a full state delta: the constructor
        // enforces that a code-carrying delta's storage patch contains only `Create` ops, so it
        // always reconstructs a full account.
        self.code.is_some()
    }

    /// Returns storage updates for this account delta.
    pub fn storage(&self) -> &AccountStoragePatch {
        &self.storage
    }

    /// Returns vault updates for this account delta.
    pub fn vault(&self) -> &AccountVaultDelta {
        &self.vault
    }

    /// Returns the amount by which the nonce was incremented.
    pub fn nonce_delta(&self) -> Felt {
        self.nonce_delta
    }

    /// Returns the account ID to which this delta applies.
    pub fn id(&self) -> AccountId {
        self.account_id
    }

    /// Returns a reference to the account code of this delta, if present.
    pub fn code(&self) -> Option<&AccountCode> {
        self.code.as_ref()
    }

    /// Converts this delta into its individual components.
    pub fn into_parts(self) -> (AccountStoragePatch, AccountVaultDelta, Option<AccountCode>, Felt) {
        (self.storage, self.vault, self.code, self.nonce_delta)
    }

    /// Computes the commitment to the account delta.
    ///
    /// ## Computation
    ///
    /// The delta commitment is a sequential hash over a vector of field elements which starts out
    /// empty and is appended to in the following way. If no asset or storage elements were
    /// appended, the commitment is defined as the empty word. Whenever sorting is expected, it
    /// is that of a [`Word`]. The hash is domain-separated by the delta's `DOMAIN`, which is
    /// placed in the capacity word of the hasher.
    ///
    /// - Append `[[version = 1, nonce_delta, account_id_suffix, account_id_prefix], EMPTY_WORD]`,
    ///   where `account_id_{prefix,suffix}` are the prefix and suffix felts of the native account
    ///   id, `nonce_delta` is the value by which the nonce was incremented, and `version` is the
    ///   version of this layout.
    /// - Asset Delta
    ///   - For each **added** asset, sorted by its asset ID:
    ///     - Append `[ASSET_ID, ASSET_VALUE]`.
    ///   - Append `[domain = 1, delta_op = 1, num_added_assets, 0]` if `num_added_assets != 0`
    ///     where `num_added_assets` is the number of added assets and `delta_op` is set to `1`
    ///     indicating asset addition.
    ///   - For each **removed** asset, sorted by its asset ID:
    ///     - Append `[ASSET_ID, ASSET_VALUE]`.
    ///   - Append `[domain = 1, delta_op = 2, num_removed_assets, 0]` if `num_removed_assets != 0`
    ///     where `num_removed_assets` is the number of removed assets and `delta_op` is set to `2`
    ///     indicating asset removal.
    ///   - Note that the domain is the same independent of asset addition or removal, since the
    ///     `delta_op` sufficiently distinguishes the two domains.
    /// - Storage Slots are sorted by slot ID and are iterated in this order. `patch_op` is the
    ///   [`StoragePatchOperation`](crate::account::StoragePatchOperation) of the slot patch and
    ///   `slot_id_{suffix, prefix}` is the identifier of the slot. For each slot, depending on its
    ///   slot type:
    ///   - Value Slot
    ///     - Append `[[domain = 2, patch_op, slot_id_suffix, slot_id_prefix], NEW_VALUE]` where
    ///       `NEW_VALUE` is the new value of the slot.
    ///   - Map Slot
    ///     - For each key-value pair, sorted by key, whose new value is different from the previous
    ///       value in the map:
    ///       - Append `[KEY, NEW_VALUE]`.
    ///     - The map trailer is constructed as `[[domain = 3, patch_op, slot_id_suffix,
    ///       slot_id_prefix], [num_changed_entries, 0, 0, 0]]`, where `num_changed_entries` is the
    ///       number of key-value pairs appended above. Whether the trailer is included depends on
    ///       `patch_op`:
    ///         - For
    ///           [`StoragePatchOperation::Create`](crate::account::StoragePatchOperation::Create),
    ///           the trailer is always included, since the slot's creation must be committed to even
    ///           when the map is created empty (`num_changed_entries == 0`).
    ///         - For
    ///           [`StoragePatchOperation::Update`](crate::account::StoragePatchOperation::Update),
    ///           the trailer is included only if `num_changed_entries != 0`. An update that changes
    ///           no entries is a no-op and is omitted entirely.
    ///         - For
    ///           [`StoragePatchOperation::Remove`](crate::account::StoragePatchOperation::Remove),
    ///           the trailer is always included with `num_changed_entries` set to zero, since the
    ///           number of removed entries is unknown.
    ///
    /// ## Rationale
    ///
    /// The rationale for this layout is that hashing in the VM should be as efficient as possible
    /// and minimize the number of branches to be as efficient as possible. Every high-level section
    /// in this bullet point list should add an even number of words since the hasher operates
    /// on double words. In the VM, each permutation is done immediately, so adding an uneven
    /// number of words in a given step will result in more difficulty in the MASM implementation.
    ///
    /// ### New Accounts
    ///
    /// The delta for new accounts (a full state delta) must commit to all the created storage slots
    /// of the account, even if these slots contain the default value (e.g. the empty word for value
    /// slots or an empty storage map). This ensures the full state delta commits to the exact
    /// storage slots that are contained in the account.
    ///
    /// ## Security
    ///
    /// The general concern with the commitment is that two distinct deltas must never hash to the
    /// same commitment. E.g. a commitment of a delta that changes a key-value pair in a storage
    /// map slot should be different from a delta that adds a non-fungible asset to the vault.
    /// If not, a delta can be crafted in the VM that sets a map key but a malicious actor
    /// crafts a delta outside the VM that adds a non-fungible asset. To prevent that, a couple
    /// of measures are taken.
    ///
    /// - Because multiple unrelated domains (e.g. vaults and storage slots) are hashed in the same
    ///   hasher, domain separators are used to disambiguate. For each changed asset and each
    ///   changed slot in the delta, a domain separator is hashed into the delta. The domain
    ///   separator is always at the same index in each layout so it cannot be maliciously crafted
    ///   (see below for an example). These separators only need to be unique _within_ a delta or
    ///   patch, since the `DOMAIN` of a delta and of a patch already separate the two objects.
    /// - Storage value slots:
    ///   - since value slots are only included in the patch if their value has changed when the
    ///     operation is `Update`, there is no ambiguity between a value slot being set to
    ///     EMPTY_WORD and its value being unchanged.
    /// - Storage map slots:
    ///   - Map slots append a header which summarizes the changes in the slot, in particular the
    ///     slot ID and number of changed entries.
    ///   - Two distinct storage map slots use the same domain but are disambiguated due to
    ///     inclusion of the slot ID.
    ///
    /// ### Domain Separators
    ///
    /// As an example for ambiguity, consider these two deltas:
    ///
    /// ```text
    /// [
    ///   METADATA, EMPTY_WORD,
    ///   [ASSET_ID, ASSET_VALUE],
    ///   [[domain = 1, delta_op = 1, num_added_assets = 1, 0], EMPTY_WORD],
    ///   [/* no removed assets delta */],
    ///   [/* no storage patch */]
    /// ]
    /// ```
    ///
    /// ```text
    /// [
    ///   METADATA, EMPTY_WORD,
    ///   [/* no asset delta */],
    ///   [[domain = 2, patch_op, slot_id_suffix0, slot_id_prefix0], NEW_VALUE]
    ///   [[domain = 2, patch_op, slot_id_suffix1, slot_id_prefix1], NEW_VALUE]
    /// ]
    /// ```
    ///
    /// - `NEW_VALUE` is user-controlled and can be crafted to match `ASSET_VALUE` or `EMPTY_WORD`.
    /// - Slot IDs are user-controlled and can be crafted to match the two most significant elements
    ///   in the asset ID or `num_added_assets` and the fixed 0.
    /// - This leaves only the domain separator and the patch_op to differentiate these two deltas.
    ///
    /// A delta and a patch have identically shaped headers, so their element sequences can be made
    /// to match. They cannot collide because the delta and the patch commitment use distinct hasher
    /// capacity domains.
    ///
    /// ### Number of Changed Entries
    ///
    /// As an example for ambiguity, consider these two deltas:
    ///
    /// ```text
    /// [
    ///   METADATA, EMPTY_WORD,
    ///   [/* no asset delta */],
    ///   [domain = 3, patch_op, slot_id_suffix = 20, slot_id_prefix = 21, num_changed_entries = 0, 0, 0, 0]
    ///   [domain = 3, patch_op, slot_id_suffix = 42, slot_id_prefix = 43, num_changed_entries = 0, 0, 0, 0]
    /// ]
    /// ```
    ///
    /// ```text
    /// [
    ///   METADATA, EMPTY_WORD,
    ///   [/* no asset delta */],
    ///   [KEY0, VALUE0],
    ///   [domain = 3, patch_op, slot_id_suffix = 42, slot_id_prefix = 43, num_changed_entries = 1, 0, 0, 0]
    /// ]
    /// ```
    ///
    /// The keys and values of map slots are user-controllable so `KEY0` and `VALUE0` could be
    /// crafted to match the first map header in the first delta. So, _without_ having
    /// `num_changed_entries` included in the commitment, these deltas would be ambiguous. A delta
    /// with two empty maps could have the same commitment as a delta with one map entry where one
    /// key-value pair has changed.
    ///
    /// #### New Accounts
    ///
    /// The number of changed entries of a storage map can be validly zero when an empty storage map
    /// is created in account (e.g. at account creation time). In such cases, the number of changed
    /// key-value pairs is 0, but the map must still be committed to, in order to differentiate
    /// between a slot being created as an empty map or not being created at all.
    pub fn to_commitment(&self) -> Word {
        <Self as SequentialCommit>::to_commitment(self)
    }
}

impl TryFrom<&AccountDelta> for Account {
    type Error = AccountError;

    /// Converts an [`AccountDelta`] into an [`Account`].
    ///
    /// Conceptually, this applies the delta onto an empty account.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - If the delta is not a full state delta. See [`AccountDelta`] for details.
    /// - If any vault delta operation removes an asset.
    /// - If any vault delta operation adds an asset that would overflow the maximum representable
    ///   amount.
    /// - If any storage patch update violates account storage constraints.
    fn try_from(delta: &AccountDelta) -> Result<Self, Self::Error> {
        if !delta.is_full_state() {
            return Err(AccountError::PartialStateDeltaToAccount);
        }

        let Some(code) = delta.code().cloned() else {
            return Err(AccountError::PartialStateDeltaToAccount);
        };

        // The asset vault of a new account is empty, so if the delta contains removed assets, the
        // delta is invalid.
        if delta.vault().removed_assets().count() != 0 {
            return Err(AccountError::AssetsRemovedFromNewAccount);
        }

        let mut vault = AssetVault::default();
        for added_asset in delta.vault().added_assets() {
            vault.insert_asset(added_asset).map_err(AccountError::AssetVaultUpdateError)?;
        }

        // A full state delta consists of `Create` slot patches, so applying it to empty storage
        // reconstructs the account's full storage.
        let mut storage = AccountStorage::default();
        storage.apply_patch(delta.storage())?;

        // The nonce of the account is the initial nonce of 0 plus the nonce_delta, so the
        // nonce_delta itself.
        let nonce = delta.nonce_delta();

        Account::new(delta.id(), vault, storage, code, nonce, None)
    }
}

impl SequentialCommit for AccountDelta {
    type Commitment = Word;

    /// Computes the commitment to the delta, domain-separated by its `DOMAIN`.
    ///
    /// See [AccountDelta::to_commitment()] for more details.
    fn to_commitment(&self) -> Word {
        let elements = self.to_elements();

        // An empty delta produces no elements and its commitment is defined as the empty word.
        if elements.is_empty() {
            return Word::empty();
        }

        Hasher::hash_elements_in_domain(&elements, Self::DOMAIN)
    }

    /// Reduces the delta to a sequence of field elements.
    ///
    /// See [AccountDelta::to_commitment()] for more details.
    fn to_elements(&self) -> Vec<Felt> {
        // The commitment to an empty delta is defined as the empty word.
        if self.is_empty() {
            return Vec::new();
        }

        // Minor optimization: At least 24 elements are always added.
        let mut elements = Vec::with_capacity(24);

        // Metadata
        elements.extend_from_slice(&[
            Felt::from(Self::VERSION_1),
            self.nonce_delta,
            self.account_id.suffix(),
            self.account_id.prefix().as_felt(),
        ]);
        elements.extend_from_slice(Word::empty().as_elements());

        // Vault Delta
        self.vault.append_delta_elements(&mut elements);

        // Storage Patch
        self.storage.append_patch_elements(&mut elements);

        debug_assert!(
            elements.len() % (2 * crate::WORD_SIZE) == 0,
            "expected elements to contain an even number of words, but it contained {} elements",
            elements.len()
        );

        elements
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for AccountDelta {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.account_id.write_into(target);
        self.storage.write_into(target);
        self.vault.write_into(target);
        self.code.write_into(target);
        self.nonce_delta.write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        self.account_id.get_size_hint()
            + self.storage.get_size_hint()
            + self.vault.get_size_hint()
            + self.code.get_size_hint()
            + self.nonce_delta.get_size_hint()
    }
}

impl Deserializable for AccountDelta {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let account_id = AccountId::read_from(source)?;
        let storage = AccountStoragePatch::read_from(source)?;
        let vault = AccountVaultDelta::read_from(source)?;
        let code = <Option<AccountCode>>::read_from(source)?;
        let nonce_delta = Felt::read_from(source)?;

        validate_nonce(nonce_delta, &storage, &vault)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))?;

        Ok(Self {
            account_id,
            storage,
            vault,
            code,
            nonce_delta,
        })
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Checks if the nonce was updated correctly given the provided storage and vault deltas.
///
/// # Errors
///
/// Returns an error if:
/// - storage or vault were updated, but the nonce_delta was set to 0.
fn validate_nonce(
    nonce_delta: Felt,
    storage: &AccountStoragePatch,
    vault: &AccountVaultDelta,
) -> Result<(), AccountDeltaError> {
    if (!storage.is_empty() || !vault.is_empty()) && nonce_delta == ZERO {
        return Err(AccountDeltaError::NonEmptyStorageOrVaultDeltaWithZeroNonceDelta);
    }

    Ok(())
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {

    use assert_matches::assert_matches;
    use rstest::rstest;

    use super::{AccountDelta, AccountStoragePatch, AccountVaultDelta};
    use crate::account::{
        Account,
        AccountCode,
        AccountId,
        AccountPatch,
        AccountStorage,
        AccountType,
        AccountVaultPatch,
        StorageMapKey,
        StorageMapPatch,
        StorageSlotName,
    };
    use crate::asset::{
        Asset,
        AssetVault,
        FungibleAsset,
        NonFungibleAsset,
        NonFungibleAssetDetails,
    };
    use crate::crypto::SequentialCommit;
    use crate::errors::AccountDeltaError;
    use crate::testing::account_id::{
        ACCOUNT_ID_PRIVATE_SENDER,
        ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE,
        AccountIdBuilder,
    };
    use crate::utils::serde::Serializable;
    use crate::{Felt, ONE, Word, ZERO};

    #[test]
    fn empty_account_delta_commitment_is_empty_word() -> anyhow::Result<()> {
        let empty_delta = AccountDelta::new(
            AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER)?,
            AccountStoragePatch::new(),
            AccountVaultDelta::default(),
            None,
            ZERO,
        )?;
        assert_eq!(empty_delta.to_commitment(), Word::empty());

        Ok(())
    }

    /// A delta and a patch that reduce to identical element sequences still commit to different
    /// words, because they use distinct hasher domains.
    #[test]
    fn account_delta_commitment_domain_separation() -> anyhow::Result<()> {
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER)?;
        let nonce = Felt::from(2u8);

        let delta = AccountDelta::new(
            account_id,
            AccountStoragePatch::new(),
            AccountVaultDelta::default(),
            None,
            nonce,
        )?;
        let patch = AccountPatch::new(
            account_id,
            AccountStoragePatch::new(),
            AccountVaultPatch::default(),
            None,
            Some(nonce),
        )?;

        assert_eq!(delta.to_elements(), patch.to_elements());
        assert_ne!(delta.to_commitment(), Word::empty());
        assert_ne!(delta.to_commitment(), patch.to_commitment());

        Ok(())
    }

    #[test]
    fn account_delta_nonce_validation() {
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER).unwrap();
        // empty delta
        let storage_patch = AccountStoragePatch::new();
        let vault_delta = AccountVaultDelta::default();

        AccountDelta::new(account_id, storage_patch.clone(), vault_delta.clone(), None, ZERO)
            .unwrap();
        AccountDelta::new(account_id, storage_patch.clone(), vault_delta.clone(), None, ONE)
            .unwrap();

        // non-empty delta
        let storage_patch = AccountStoragePatch::from_iters([StorageSlotName::mock(1)], [], []);

        assert_matches!(
            AccountDelta::new(account_id, storage_patch.clone(), vault_delta.clone(), None, ZERO)
                .unwrap_err(),
            AccountDeltaError::NonEmptyStorageOrVaultDeltaWithZeroNonceDelta
        );
        AccountDelta::new(account_id, storage_patch.clone(), vault_delta.clone(), None, ONE)
            .unwrap();
    }

    /// A full state delta (carrying code) must only contain `Create` storage ops, since an `Update`
    /// or `Remove` could not be applied to the empty storage of a new account.
    #[rstest]
    #[case::update(
        AccountStoragePatch::builder().update_value(StorageSlotName::mock(1), Word::empty()).build()
    )]
    #[case::remove(
        AccountStoragePatch::builder().remove_value(StorageSlotName::mock(1)).build()
    )]
    fn account_delta_new_rejects_full_state_with_non_create_op(
        #[case] storage: AccountStoragePatch,
    ) -> anyhow::Result<()> {
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER)?;

        let error = AccountDelta::new(
            account_id,
            storage,
            AccountVaultDelta::default(),
            Some(AccountCode::mock()),
            ONE,
        )
        .unwrap_err();
        assert_matches!(error, AccountDeltaError::FullStateDeltaContainsNonCreateOp);

        Ok(())
    }

    /// A full state delta whose storage only creates slots can be reconstructed into an account.
    #[test]
    fn account_delta_full_state_with_create_reconstructs() -> anyhow::Result<()> {
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER)?;
        let code = AccountCode::mock();
        let created_slot = StorageSlotName::mock(1);
        let created_value = Word::from([7u32, 0, 0, 0]);

        let storage = AccountStoragePatch::builder()
            .create_value(created_slot.clone(), created_value)
            .build();

        let delta = AccountDelta::new(
            account_id,
            storage,
            AccountVaultDelta::default(),
            Some(code.clone()),
            ONE,
        )?;
        assert!(delta.is_full_state());

        let account = Account::try_from(&delta)?;
        assert_eq!(account.code(), &code);
        assert_eq!(account.storage().get_item(&created_slot)?, created_value);

        Ok(())
    }

    #[test]
    fn account_delta_size_hint() {
        // AccountDelta
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER).unwrap();
        let storage_patch = AccountStoragePatch::new();
        let vault_delta = AccountVaultDelta::default();
        assert_eq!(storage_patch.to_bytes().len(), storage_patch.get_size_hint());
        assert_eq!(vault_delta.to_bytes().len(), vault_delta.get_size_hint());

        let account_delta =
            AccountDelta::new(account_id, storage_patch, vault_delta, None, ZERO).unwrap();
        assert_eq!(account_delta.to_bytes().len(), account_delta.get_size_hint());

        let storage_patch = AccountStoragePatch::from_iters(
            [StorageSlotName::mock(1)],
            [
                (StorageSlotName::mock(2), Word::from([1, 1, 1, 1u32])),
                (StorageSlotName::mock(3), Word::from([1, 1, 0, 1u32])),
            ],
            [(
                StorageSlotName::mock(4),
                StorageMapPatch::from_iters(
                    [
                        StorageMapKey::from_array([1, 1, 1, 0]),
                        StorageMapKey::from_array([0, 1, 1, 1]),
                    ],
                    [(StorageMapKey::from_array([1, 1, 1, 1]), Word::from([1, 1, 1, 1u32]))],
                ),
            )],
        );

        let non_fungible: Asset = NonFungibleAsset::new(&NonFungibleAssetDetails::new(
            AccountIdBuilder::new()
                .account_type(AccountType::Public)
                .build_with_rng(&mut rand::rng()),
            vec![6],
        ))
        .into();
        let fungible_2: Asset = FungibleAsset::new(
            AccountIdBuilder::new()
                .account_type(AccountType::Public)
                .build_with_rng(&mut rand::rng()),
            10,
        )
        .unwrap()
        .into();
        let vault_delta = AccountVaultDelta::from_iters([non_fungible], [fungible_2]);

        assert_eq!(storage_patch.to_bytes().len(), storage_patch.get_size_hint());
        assert_eq!(vault_delta.to_bytes().len(), vault_delta.get_size_hint());

        let account_delta =
            AccountDelta::new(account_id, storage_patch, vault_delta, None, ONE).unwrap();
        assert_eq!(account_delta.to_bytes().len(), account_delta.get_size_hint());

        // Account

        let account_id =
            AccountId::try_from(ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE).unwrap();

        let asset_vault = AssetVault::mock();
        assert_eq!(asset_vault.to_bytes().len(), asset_vault.get_size_hint());

        let account_storage = AccountStorage::mock();
        assert_eq!(account_storage.to_bytes().len(), account_storage.get_size_hint());

        let account_code = AccountCode::mock();
        assert_eq!(account_code.to_bytes().len(), account_code.get_size_hint());

        let account =
            Account::new_existing(account_id, asset_vault, account_storage, account_code, ONE);
        assert_eq!(account.to_bytes().len(), account.get_size_hint());
    }
}
