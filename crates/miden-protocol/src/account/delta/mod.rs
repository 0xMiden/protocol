use alloc::string::ToString;
use alloc::vec::Vec;

use crate::account::{Account, AccountCodePatch, AccountId, AccountStorage, AccountStoragePatch};
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
use crate::{Felt, Hasher, Word};

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
/// - code: an [`AccountCodePatch`] containing the code of a new or upgraded account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountDelta {
    /// The ID of the account to which this delta applies. If the delta is created during
    /// transaction execution, that is the native account of the transaction.
    account_id: AccountId,
    /// The patch of the account's storage.
    storage: AccountStoragePatch,
    /// The delta of the account's asset vault.
    vault: AccountVaultDelta,
    /// The code of a new or upgraded account.
    code: AccountCodePatch,
    /// The value by which the nonce was incremented. Must be greater than zero if storage, vault
    /// or code are non-empty.
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
    /// # Errors
    ///
    /// Returns an error if storage, vault or code were updated, but the nonce_delta is 0.
    pub fn new(
        account_id: AccountId,
        storage: AccountStoragePatch,
        vault: AccountVaultDelta,
        code: AccountCodePatch,
        nonce_delta: Felt,
    ) -> Result<Self, AccountDeltaError> {
        // nonce must be updated if either account storage, vault or code were updated
        validate_nonce(nonce_delta, &storage, &vault, &code)?;

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

    /// Returns true if this account delta does not contain any vault, storage or code updates and
    /// the nonce wasn't updated.
    pub fn is_empty(&self) -> bool {
        // A nonce delta of zero means the delta is empty, since the constructor validates that
        // non-empty storage, vault or code updates must increment the nonce.
        self.nonce_delta == Felt::ZERO
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

    /// Returns code updates for this account delta.
    pub fn code(&self) -> &AccountCodePatch {
        &self.code
    }

    /// Converts this delta into its individual components.
    pub fn into_parts(self) -> (AccountStoragePatch, AccountVaultDelta, AccountCodePatch, Felt) {
        (self.storage, self.vault, self.code, self.nonce_delta)
    }

    /// Computes the commitment to the account delta.
    ///
    /// ## Computation
    ///
    /// The delta commitment is a sequential hash over a vector of field elements which starts out
    /// empty and is appended to in the following way. If no asset, storage or code elements were
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
    /// - If the account is new or its code was upgraded, append `[[domain = 4, 0, 0, 0],
    ///   CODE_COMMITMENT]`, where `CODE_COMMITMENT` is the commitment of the account code.
    ///
    /// ## Rationale
    ///
    /// The rationale for this layout is that hashing in the VM should be as efficient as possible
    /// and minimize the number of branches to be as efficient as possible. Every high-level section
    /// in this bullet point list should add an even number of words since the hasher operates
    /// on double words. In the VM, each permutation is done immediately, so adding an uneven
    /// number of words in a given step will result in more difficulty in the MASM implementation.
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
    pub fn to_commitment(&self) -> Word {
        <Self as SequentialCommit>::to_commitment(self)
    }

    /// Returns the new [`Account`] created by this delta.
    ///
    /// Conceptually, this applies the delta onto an empty account.
    ///
    /// # Warning
    ///
    /// This method only results in a semantically correct account if the caller knows that the
    /// delta comes from an account-creating transaction. The method can also succeed on deltas
    /// coming from code-upgrading transactions, but the result will not correspond to a meaningful
    /// account state.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the delta does not carry account code.
    /// - the storage patch contains an `Update` or `Remove` operation, which cannot be applied to
    ///   the empty storage of a new account.
    /// - the vault delta removes an asset.
    /// - the vault delta adds an asset that would overflow the maximum representable amount.
    /// - applying the storage patch to empty storage fails.
    /// - [`Account::new`] fails on the resulting components.
    pub fn try_to_new_account(&self) -> Result<Account, AccountError> {
        let Some(code) = self.code.as_code() else {
            return Err(AccountError::NewAccountRequiresCodeAndNonce);
        };

        if self.storage.contains_non_create_ops() {
            return Err(AccountError::NewAccountStorageRequiresCreateOps);
        }

        // The asset vault of a new account is empty, so if the delta contains removed assets, the
        // delta is invalid.
        if self.vault.removed_assets().count() != 0 {
            return Err(AccountError::AssetsRemovedFromNewAccount);
        }

        let mut vault = AssetVault::default();
        for added_asset in self.vault.added_assets() {
            vault.insert_asset(added_asset).map_err(AccountError::AssetVaultUpdateError)?;
        }

        let mut storage = AccountStorage::default();
        storage.apply_patch(&self.storage)?;

        // The nonce of the account is the initial nonce of 0 plus the nonce_delta, so the
        // nonce_delta itself.
        Account::new(self.account_id, vault, storage, code.clone(), self.nonce_delta, None)
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

        // Code
        self.code.append_patch_elements(&mut elements);

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
        let code = AccountCodePatch::read_from(source)?;
        let nonce_delta = Felt::read_from(source)?;

        validate_nonce(nonce_delta, &storage, &vault, &code)
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

/// Checks if the nonce was updated correctly given the provided storage, vault and code deltas.
///
/// # Errors
///
/// Returns an error if:
/// - storage, vault or code were updated, but the nonce_delta is 0.
fn validate_nonce(
    nonce_delta: Felt,
    storage: &AccountStoragePatch,
    vault: &AccountVaultDelta,
    code: &AccountCodePatch,
) -> Result<(), AccountDeltaError> {
    if (!storage.is_empty() || !vault.is_empty() || !code.is_empty()) && nonce_delta == Felt::ZERO {
        return Err(AccountDeltaError::NonEmptyDeltaWithZeroNonceDelta);
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
        AccountCodePatch,
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
    use crate::errors::{AccountDeltaError, AccountError};
    use crate::testing::account_id::{
        ACCOUNT_ID_PRIVATE_SENDER,
        ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE,
        AccountIdBuilder,
    };
    use crate::utils::serde::Serializable;
    use crate::{Felt, Word};

    #[test]
    fn empty_account_delta_commitment_is_empty_word() -> anyhow::Result<()> {
        let empty_delta = AccountDelta::new(
            AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER)?,
            AccountStoragePatch::new(),
            AccountVaultDelta::default(),
            AccountCodePatch::default(),
            Felt::ZERO,
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
            AccountCodePatch::default(),
            nonce,
        )?;
        let patch = AccountPatch::new(
            account_id,
            AccountStoragePatch::new(),
            AccountVaultPatch::default(),
            AccountCodePatch::default(),
            Some(nonce),
        )?;

        assert_eq!(delta.to_elements(), patch.to_elements());
        assert_ne!(delta.to_commitment(), Word::empty());
        assert_ne!(delta.to_commitment(), patch.to_commitment());

        Ok(())
    }

    /// A delta that updates storage, the vault or the code but leaves the nonce unchanged is
    /// rejected, since any account state change requires the nonce to be incremented.
    #[rstest]
    #[case::non_empty_storage(
        AccountStoragePatch::from_iters([StorageSlotName::mock(1)], [], []),
        AccountVaultDelta::default(),
        AccountCodePatch::default(),
    )]
    #[case::non_empty_vault(
        AccountStoragePatch::new(),
        AccountVaultDelta::from_iters([FungibleAsset::mock(100)], []),
        AccountCodePatch::default(),
    )]
    #[case::non_empty_code(
        AccountStoragePatch::new(),
        AccountVaultDelta::default(),
        AccountCodePatch::new(Some(AccountCode::mock()))
    )]
    fn account_delta_with_state_change_requires_nonce_delta(
        #[case] storage: AccountStoragePatch,
        #[case] vault: AccountVaultDelta,
        #[case] code: AccountCodePatch,
    ) -> anyhow::Result<()> {
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER)?;

        assert_matches!(
            AccountDelta::new(account_id, storage, vault, code, Felt::ZERO).unwrap_err(),
            AccountDeltaError::NonEmptyDeltaWithZeroNonceDelta
        );

        Ok(())
    }

    /// An empty delta is valid with or without a nonce delta, and a delta with a state change is
    /// valid with a nonce delta.
    #[rstest]
    #[case::empty_without_nonce_delta(
        AccountStoragePatch::new(),
        AccountVaultDelta::default(),
        AccountCodePatch::default(),
        Felt::ZERO
    )]
    #[case::empty_with_nonce_delta(
        AccountStoragePatch::new(),
        AccountVaultDelta::default(),
        AccountCodePatch::default(),
        Felt::ONE
    )]
    #[case::non_empty_storage(
        AccountStoragePatch::from_iters([StorageSlotName::mock(1)], [], []),
        AccountVaultDelta::default(),
        AccountCodePatch::default(),
        Felt::ONE,
    )]
    #[case::non_empty_vault(
        AccountStoragePatch::new(),
        AccountVaultDelta::from_iters([FungibleAsset::mock(100)], []),
        AccountCodePatch::default(),
        Felt::ONE,
    )]
    #[case::non_empty_code(
        AccountStoragePatch::new(),
        AccountVaultDelta::default(),
        AccountCodePatch::new(Some(AccountCode::mock())),
        Felt::ONE
    )]
    fn account_delta_valid_nonce_delta(
        #[case] storage: AccountStoragePatch,
        #[case] vault: AccountVaultDelta,
        #[case] code: AccountCodePatch,
        #[case] nonce_delta: Felt,
    ) -> anyhow::Result<()> {
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER)?;

        AccountDelta::new(account_id, storage, vault, code, nonce_delta)?;

        Ok(())
    }

    /// A delta carrying code may contain `Update` or `Remove` storage ops, since it can describe a
    /// code upgrade. Such a delta cannot create an account, since the ops cannot be applied to the
    /// empty storage of a new account.
    #[rstest]
    #[case::update(
        AccountStoragePatch::builder().update_value(StorageSlotName::mock(1), Word::empty()).build()
    )]
    #[case::remove(
        AccountStoragePatch::builder().remove_value(StorageSlotName::mock(1)).build()
    )]
    fn account_delta_try_to_new_account_rejects_non_create_op(
        #[case] storage: AccountStoragePatch,
    ) -> anyhow::Result<()> {
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER)?;

        let delta = AccountDelta::new(
            account_id,
            storage,
            AccountVaultDelta::default(),
            AccountCodePatch::new(Some(AccountCode::mock())),
            Felt::ONE,
        )?;
        assert_matches!(
            delta.try_to_new_account().unwrap_err(),
            AccountError::NewAccountStorageRequiresCreateOps
        );

        Ok(())
    }

    /// A delta without code cannot create an account.
    #[test]
    fn account_delta_try_to_new_account_requires_code() -> anyhow::Result<()> {
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER)?;

        let delta = AccountDelta::new(
            account_id,
            AccountStoragePatch::new(),
            AccountVaultDelta::default(),
            AccountCodePatch::default(),
            Felt::ONE,
        )?;
        assert_matches!(
            delta.try_to_new_account().unwrap_err(),
            AccountError::NewAccountRequiresCodeAndNonce
        );

        Ok(())
    }

    /// A delta whose storage only creates slots can be reconstructed into an account.
    #[test]
    fn account_delta_try_to_new_account_with_create_reconstructs() -> anyhow::Result<()> {
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
            AccountCodePatch::new(Some(code.clone())),
            Felt::ONE,
        )?;

        let account = delta.try_to_new_account()?;
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

        let account_delta = AccountDelta::new(
            account_id,
            storage_patch,
            vault_delta,
            AccountCodePatch::default(),
            Felt::ZERO,
        )
        .unwrap();
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

        let account_delta = AccountDelta::new(
            account_id,
            storage_patch,
            vault_delta,
            AccountCodePatch::default(),
            Felt::ONE,
        )
        .unwrap();
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

        let account = Account::new_existing(
            account_id,
            asset_vault,
            account_storage,
            account_code,
            Felt::ONE,
        );
        assert_eq!(account.to_bytes().len(), account.get_size_hint());
    }
}
