mod code;
mod vault;

mod storage;
mod update_details;
use alloc::string::ToString;
use alloc::vec::Vec;

pub use code::AccountCodePatch;
pub use storage::{
    AccountStoragePatch,
    StorageMapPatch,
    StorageMapPatchEntries,
    StoragePatchOperation,
    StorageSlotPatch,
    StorageValuePatch,
};
pub use update_details::AccountUpdateDetails;
pub(crate) use update_details::validate_new_public_account;
pub use vault::AccountVaultPatch;

use crate::account::{Account, AccountId, AccountStorage};
use crate::asset::AssetVault;
use crate::crypto::SequentialCommit;
use crate::errors::{AccountError, AccountPatchError};
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{Felt, Hasher, Word};

/// An [`AccountPatch`] describes the new absolute state of an account after one or more
/// transactions, in contrast to an [`AccountDelta`](crate::account::AccountDelta), which describes
/// the relative change.
///
/// For example, where a delta might say "remove 50 USDC from the vault", a patch says "the new
/// USDC balance is 100". This means a patch can be applied to compute the new account state
/// without loading the previous state and without invoking any custom asset compose logic (e.g.
/// merge/split procedures defined by the issuing faucet).
///
/// [`Account::apply_patch`]: crate::account::Account::apply_patch
///
/// The patch represents updates to the account as follows:
/// - storage: an [`AccountStoragePatch`] containing the new values of changed storage slots and map
///   entries. Storage updates are already absolute per changed entry, so no dedicated patch type is
///   required for storage.
/// - vault: an [`AccountVaultPatch`] containing the new values of changed vault entries.
/// - nonce: the new (absolute) nonce of the account, in contrast to
///   [`AccountDelta::nonce_delta`](crate::account::AccountDelta::nonce_delta) which stores the
///   increment.
/// - code: an [`AccountCodePatch`] containing the code of a new or upgraded account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountPatch {
    /// The ID of the account to which this patch applies.
    account_id: AccountId,
    /// The new values of changed storage slots and map entries.
    storage: AccountStoragePatch,
    /// The new values of changed vault entries.
    vault: AccountVaultPatch,
    /// The code of a new or upgraded account.
    code: AccountCodePatch,
    /// The new (absolute) nonce of the account.
    ///
    /// Should be set to `None` if the nonce wasn't updated.
    final_nonce: Option<Felt>,
}

impl AccountPatch {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Domain separator for the account patch commitment.
    ///
    /// See [`AccountDelta::DOMAIN`](crate::account::AccountDelta) for why it lives in the capacity
    /// word and where the value is allocated from.
    const DOMAIN: Felt = Felt::new_unchecked(0x02_0000);

    /// Version 1 of the account patch commitment layout.
    ///
    /// The version occupies the first element of the commitment header, so a reader can get it
    /// before it interprets the rest of the commitment. Version 0 is unused, which means an
    /// all-zero word is never a valid header.
    const VERSION_1: u8 = 1;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns a new [`AccountPatch`] instantiated from the provided components.
    ///
    /// `final_nonce` must be `Some(non_zero_nonce)` if `storage`, `vault` or `code` contain any
    /// updates, and can be `None` only for empty patches.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `final_nonce` is `Some(Felt::ZERO)`. The tx kernel guarantees that an updated nonce is at
    ///   least one, so a zero nonce is never a valid post-tx-state. Empty patches must be
    ///   constructed with `None` instead.
    /// - `storage` or `vault` contain updates or code is present but `final_nonce` is `None`. The
    ///   tx kernel mandates that the nonce is incremented whenever account state changes.
    /// - `final_nonce` is 1 but `code` is not `Some`. Such a patch describes a new account and
    ///   should be convertible into a full [`Account`](crate::account::Account), so account code is
    ///   required.
    pub fn new(
        account_id: AccountId,
        storage: AccountStoragePatch,
        vault: AccountVaultPatch,
        code: AccountCodePatch,
        final_nonce: Option<Felt>,
    ) -> Result<Self, AccountPatchError> {
        // New nonce should never be zero as the tx kernel requires that the nonce must be
        // incremented to at least 1 in the account-creating transaction.
        // Patches that do not change the account (and the nonce) should pass `None`.
        if final_nonce.is_some_and(|final_nonce| final_nonce == Felt::ZERO) {
            return Err(AccountPatchError::FinalNonceIsZero);
        }

        // If account storage or vault were updated or code is present, the patch represents a state
        // change and so the nonce cannot be zero. The tx kernel mandates this.
        if (!storage.is_empty() || !vault.is_empty() || !code.is_empty()) && final_nonce.is_none() {
            return Err(AccountPatchError::StateChangeRequiresNonceUpdate);
        }

        // Code must be provided for new accounts to be able to reconstruct the full Account.
        // New accounts are defined with nonce 0, but here we have the post-creation
        // final nonce, so we define new accounts as having final_nonce = 1.
        if final_nonce.is_some_and(|final_nonce| final_nonce == Felt::ONE) && code.is_empty() {
            return Err(AccountPatchError::CodeMustBeProvidedForNewAccounts);
        }

        Ok(Self {
            account_id,
            storage,
            vault,
            code,
            final_nonce,
        })
    }

    /// Returns an empty patch for the provided account ID.
    pub fn empty(account_id: AccountId) -> Self {
        AccountPatch::new(
            account_id,
            AccountStoragePatch::default(),
            AccountVaultPatch::default(),
            AccountCodePatch::default(),
            None,
        )
        .expect("empty patch should be valid")
    }

    // PUBLIC MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Merges the `other` [`AccountPatch`] into this one with patch semantics: entries present in
    /// `other` overwrite their counterparts in `self`, and `other.final_nonce`, if present,
    /// becomes the new final nonce.
    ///
    /// Both patches must apply to the same account, and `other.final_nonce` must be exactly one
    /// greater than `self.final_nonce` whenever both are set. The exact `+1` requirement reflects
    /// the tx kernel invariants that (a) a state-changing transaction must increment the nonce,
    /// and (b) the nonce can be incremented at most once per transaction. As a consequence
    /// the patch of the next transaction always lands at `self.final_nonce + 1`. The same nonce in
    /// both patches represents a fork and a nonce delta larger than 1 means a missed transaction.
    ///
    /// If `other` carries code, it replaces the code of `self`, since `other` describes the later
    /// state.
    ///
    /// Empty patches are neutral: merging into an empty `self` adopts `other`, and merging an empty
    /// `other` is a no-op.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the two patches apply to different accounts.
    /// - both patches carry a final nonce and the nonce in `other` is not exactly one greater than
    ///   the nonce in `self`.
    /// - a storage slot is used as different slot types in the two patches.
    pub fn merge(&mut self, other: Self) -> Result<(), AccountPatchError> {
        if self.account_id != other.account_id {
            return Err(AccountPatchError::AccountIdMismatch {
                expected: self.account_id,
                actual: other.account_id,
            });
        }

        match (self.final_nonce, other.final_nonce) {
            // Both patches are empty, nothing to merge.
            (None, None) => return Ok(()),

            // `self` is empty, so `other` becomes the merged result.
            (None, Some(_)) => {
                *self = other;
                return Ok(());
            },

            // `other` is empty, nothing to merge.
            (Some(_), None) => return Ok(()),

            (Some(current), Some(new)) => {
                if new != current + Felt::ONE {
                    return Err(AccountPatchError::NonceMustIncrementByOne { current, new });
                }
                self.final_nonce = Some(new);
            },
        }

        self.storage.merge(other.storage)?;
        self.vault.merge(other.vault);
        self.code.merge(other.code);

        Ok(())
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the account ID to which this patch applies.
    pub fn id(&self) -> AccountId {
        self.account_id
    }

    /// Returns the storage updates of this patch.
    pub fn storage(&self) -> &AccountStoragePatch {
        &self.storage
    }

    /// Returns the vault updates of this patch.
    pub fn vault(&self) -> &AccountVaultPatch {
        &self.vault
    }

    /// Returns the code updates of this patch.
    pub fn code(&self) -> &AccountCodePatch {
        &self.code
    }

    /// Returns the new (absolute) nonce of the account after this patch is applied, or `None` if
    /// the nonce wasn't updated.
    pub fn final_nonce(&self) -> Option<Felt> {
        self.final_nonce
    }

    /// Returns true if this account patch does not contain any vault, storage or code updates and
    /// the nonce wasn't updated.
    pub fn is_empty(&self) -> bool {
        // A nonce that wasn't updated means the patch is empty, since the constructor validates
        // that non-empty storage, vault or code updates must increment the nonce.
        self.final_nonce.is_none()
    }

    /// Computes the commitment to the account patch.
    ///
    /// This is very similar to
    /// [`AccountDelta::to_commitment`](crate::account::AccountDelta::to_commitment). See its docs
    /// for the rationale, security aspects, and other details. The only differences between
    /// these are:
    /// - the patch includes the new nonce rather than the nonce delta.
    /// - The patch includes the new absolute asset values ([`AccountVaultPatch`]) while the delta
    ///   includes the relative asset changes
    ///   ([`AccountVaultDelta`](crate::account::AccountVaultDelta)).
    ///
    /// ## Computation
    ///
    /// The patch commitment is a sequential hash over a vector of field elements which starts out
    /// empty and is appended to in the following way. If no asset, storage or code elements were
    /// appended, the commitment is defined as the empty word. Whenever sorting is expected, it is
    /// that of a [`Word`]. The hash is domain-separated by the patch's `DOMAIN`, which is
    /// placed in the capacity word of the hasher. This is what distinguishes a patch commitment
    /// from a delta commitment, whose headers are otherwise identically shaped.
    ///
    /// - Append `[[version = 1, final_nonce, account_id_suffix, account_id_prefix], EMPTY_WORD]`,
    ///   where `account_id_{prefix,suffix}` are the prefix and suffix felts of the native account
    ///   id, `final_nonce` is the new nonce of the account, and `version` is the version of this
    ///   layout.
    /// - Asset Patch
    ///   - For each asset whose value has changed compared to the initial state of the transaction,
    ///     including if it was removed, sorted by its asset ID:
    ///     - Append `[ASSET_ID, ASSET_VALUE_OR_EMPTY_WORD]` which are the key and either the value
    ///       of the asset (for updates) or the empty word (for removals).
    ///     - Append `[[domain = 1, num_changed_assets, 0, 0], 0, 0, 0, 0]`, where
    ///       `num_changed_assets` is the number of assets that were appended. This is the same
    ///       domain as the delta asset section uses, since the capacity domain already prevents an
    ///       asset delta and an asset patch from producing the same commitment.
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
    /// Headers for storage map slots and asset patches are appended rather than prepended since the
    /// tx kernel cannot efficiently get the number of changed entries before the iteration.
    pub fn to_commitment(&self) -> Word {
        <Self as SequentialCommit>::to_commitment(self)
    }

    /// Returns the new [`Account`] created by this patch.
    ///
    /// Conceptually, this applies the patch onto an empty account.
    ///
    /// # Warning
    ///
    /// This method only results in a semantically correct account if the caller knows that the
    /// patch is from an account-creating transaction itself or resulted from merging patches
    /// onto the account-creating patch. The method can also succeed on patches coming from
    /// code-upgrading transactions, but the but the result will not correspond to a meaningful
    /// account state. Prefer applying the patch onto the new account against which the
    /// account-creating transaction was executed.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the patch does not carry account code or a final nonce.
    /// - the storage patch contains an `Update` or `Remove` operation, which cannot be applied to
    ///   the empty storage of a new account.
    /// - applying the vault patch to an empty vault fails.
    /// - applying the storage patch to empty storage fails.
    /// - [`Account::new`] fails on the resulting components.
    pub fn try_to_new_account(&self) -> Result<Account, AccountError> {
        let (Some(code), Some(nonce)) = (self.code.as_code(), self.final_nonce) else {
            return Err(AccountError::NewAccountRequiresCodeAndNonce);
        };

        if self.storage.contains_non_create_ops() {
            return Err(AccountError::NewAccountStorageRequiresCreateOps);
        }

        let mut vault = AssetVault::default();
        vault.apply_patch(&self.vault).map_err(AccountError::AssetVaultUpdateError)?;

        let mut storage = AccountStorage::default();
        storage.apply_patch(&self.storage)?;

        Account::new(self.account_id, vault, storage, code.clone(), nonce, None)
    }
}

impl SequentialCommit for AccountPatch {
    type Commitment = Word;

    /// Computes the commitment to the patch, domain-separated by its `DOMAIN`.
    ///
    /// See [AccountPatch::to_commitment()] for more details.
    fn to_commitment(&self) -> Word {
        let elements = self.to_elements();

        // An empty patch produces no elements and its commitment is defined as the empty word.
        if elements.is_empty() {
            return Word::empty();
        }

        Hasher::hash_elements_in_domain(&elements, Self::DOMAIN)
    }

    /// Reduces the patch to a sequence of field elements.
    ///
    /// See [AccountPatch::to_commitment()] for more details.
    fn to_elements(&self) -> Vec<Felt> {
        // The commitment to an empty patch is defined as the empty word.
        if self.is_empty() {
            return Vec::new();
        }

        // Minor optimization: At least 8 elements are always added.
        let mut elements = Vec::with_capacity(8);

        // Metadata
        let final_nonce = self.final_nonce.expect("non-empty patches should have a new nonce set");
        elements.extend_from_slice(&[
            Felt::from(Self::VERSION_1),
            final_nonce,
            self.account_id.suffix(),
            self.account_id.prefix().as_felt(),
        ]);
        elements.extend_from_slice(Word::empty().as_elements());

        // Vault patch
        self.vault.append_patch_elements(&mut elements);

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

impl Serializable for AccountPatch {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.account_id.write_into(target);
        self.storage.write_into(target);
        self.vault.write_into(target);
        self.code.write_into(target);
        self.final_nonce.write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        self.account_id.get_size_hint()
            + self.storage.get_size_hint()
            + self.vault.get_size_hint()
            + self.code.get_size_hint()
            + self.final_nonce.get_size_hint()
    }
}

impl Deserializable for AccountPatch {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let account_id = AccountId::read_from(source)?;
        let storage = AccountStoragePatch::read_from(source)?;
        let vault = AccountVaultPatch::read_from(source)?;
        let code = AccountCodePatch::read_from(source)?;
        let final_nonce = <Option<Felt>>::read_from(source)?;

        Self::new(account_id, storage, vault, code, final_nonce)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use miden_core::serde::Deserializable;
    use rstest::rstest;

    use super::{AccountCodePatch, AccountPatch, AccountVaultPatch};
    use crate::account::{
        AccountCode,
        AccountId,
        AccountStoragePatch,
        StorageMapKey,
        StorageMapPatch,
        StorageSlotName,
        StorageSlotPatch,
        StorageValuePatch,
    };
    use crate::asset::{Asset, FungibleAsset, NonFungibleAsset};
    use crate::errors::{AccountError, AccountPatchError};
    use crate::testing::account_id::{
        ACCOUNT_ID_PRIVATE_SENDER,
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
    };
    use crate::testing::add_component::AddComponent;
    use crate::testing::noop_auth_component::NoopAuthComponent;
    use crate::utils::serde::Serializable;
    use crate::{Felt, Word};

    #[test]
    fn account_patch_serde() -> anyhow::Result<()> {
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER).unwrap();
        let asset_0 = FungibleAsset::mock(100);
        let asset_1 = FungibleAsset::new(ACCOUNT_ID_PRIVATE_SENDER.try_into()?, 500_000)?.into();
        let asset_2 = NonFungibleAsset::mock(&[10]);
        let asset_3 = NonFungibleAsset::mock(&[20]);
        let vault_patch = AccountVaultPatch::with_assets([asset_0, asset_1, asset_2, asset_3]);

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

        assert_eq!(storage_patch.to_bytes().len(), storage_patch.get_size_hint());
        assert_eq!(vault_patch.to_bytes().len(), vault_patch.get_size_hint());

        let account_patch = AccountPatch::new(
            account_id,
            storage_patch,
            vault_patch,
            AccountCodePatch::default(),
            Some(Felt::from(5u8)),
        )?;
        assert_eq!(AccountPatch::read_from_bytes(&account_patch.to_bytes())?, account_patch);
        assert_eq!(account_patch.to_bytes().len(), account_patch.get_size_hint());

        Ok(())
    }

    /// A `final_nonce` set to `Some(Felt::ZERO)` is rejected: the tx kernel guarantees the nonce of
    /// an updated account is at least one, so empty patches must pass `None` instead.
    #[test]
    fn account_patch_final_nonce_is_zero() -> anyhow::Result<()> {
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER)?;

        let error = AccountPatch::new(
            account_id,
            AccountStoragePatch::new(),
            AccountVaultPatch::default(),
            AccountCodePatch::default(),
            Some(Felt::ZERO),
        )
        .unwrap_err();

        assert_matches!(error, AccountPatchError::FinalNonceIsZero);

        Ok(())
    }

    /// A patch that updates storage, the vault, or carries code but leaves `final_nonce` as `None`
    /// is rejected, since any account state change requires the nonce to be incremented.
    #[rstest::rstest]
    #[case::non_empty_storage(
        AccountStoragePatch::from_iters([StorageSlotName::mock(1)], [], []),
        AccountVaultPatch::default(),
        AccountCodePatch::default(),
    )]
    #[case::non_empty_vault(
        AccountStoragePatch::new(),
        AccountVaultPatch::with_assets([FungibleAsset::mock(100)]),
        AccountCodePatch::default(),
    )]
    #[case::non_empty_code(
        AccountStoragePatch::new(),
        AccountVaultPatch::default(),
        AccountCodePatch::new(Some(AccountCode::mock()))
    )]
    #[test]
    fn account_patch_with_state_change_requires_nonce_update(
        #[case] storage: AccountStoragePatch,
        #[case] vault: AccountVaultPatch,
        #[case] code: AccountCodePatch,
    ) -> anyhow::Result<()> {
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER)?;

        let error = AccountPatch::new(account_id, storage, vault, code, None).unwrap_err();
        assert_matches!(error, AccountPatchError::StateChangeRequiresNonceUpdate);

        Ok(())
    }

    /// A patch for a newly created account (`final_nonce = Some(Felt::ONE)`) must include the
    /// account code, since otherwise the full account cannot be reconstructed from the patch.
    #[test]
    fn account_patch_new_account_requires_code() -> anyhow::Result<()> {
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER)?;

        let error = AccountPatch::new(
            account_id,
            AccountStoragePatch::new(),
            AccountVaultPatch::default(),
            AccountCodePatch::default(),
            Some(Felt::ONE),
        )
        .unwrap_err();
        assert_matches!(error, AccountPatchError::CodeMustBeProvidedForNewAccounts);

        // With the code provided, the same patch should succeed.
        AccountPatch::new(
            account_id,
            AccountStoragePatch::new(),
            AccountVaultPatch::default(),
            AccountCodePatch::new(Some(AccountCode::mock())),
            Some(Felt::ONE),
        )?;

        Ok(())
    }

    /// A patch carrying account code and a final nonce can be converted to an [`Account`] and back,
    /// preserving all components.
    #[test]
    fn account_patch_roundtrip() -> anyhow::Result<()> {
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER)?;
        let code = AccountCode::mock();
        let asset = FungibleAsset::mock(42);

        let slot_name = StorageSlotName::mock(4);
        let slot_value = Word::from([1, 2, 3, 4u32]);

        // A creation patch is composed of `Create` slot patches.
        let storage_patch = AccountStoragePatch::from_entries([(
            slot_name.clone(),
            StorageSlotPatch::Value(StorageValuePatch::Create { value: slot_value }),
        )])?;

        let patch = AccountPatch::new(
            account_id,
            storage_patch,
            AccountVaultPatch::with_assets([asset]),
            AccountCodePatch::new(Some(code.clone())),
            Some(Felt::ONE),
        )?;

        let account = patch.try_to_new_account()?;

        assert_eq!(account.id(), account_id);
        assert_eq!(account.code(), &code);
        assert_eq!(account.nonce(), Felt::ONE);
        assert_eq!(account.storage().get_item(&slot_name)?, slot_value);
        assert_eq!(account.vault().get(asset.id()), Some(asset));

        // Roundtrip back to a patch should reproduce the original.
        let roundtripped_patch = AccountPatch::try_from(account)?;
        assert_eq!(roundtripped_patch, patch);

        Ok(())
    }

    /// A patch lacking code cannot be converted to an [`Account`], whether or not a final nonce
    /// is present.
    #[rstest::rstest]
    #[case::missing_code(Some(Felt::from(2_u32)))]
    #[case::empty_patch(None)]
    #[test]
    fn account_patch_try_to_new_account_requires_code(
        #[case] final_nonce: Option<Felt>,
    ) -> anyhow::Result<()> {
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER)?;

        let patch = AccountPatch::new(
            account_id,
            AccountStoragePatch::new(),
            AccountVaultPatch::default(),
            AccountCodePatch::default(),
            final_nonce,
        )?;
        assert_matches!(
            patch.try_to_new_account().unwrap_err(),
            AccountError::NewAccountRequiresCodeAndNonce
        );

        Ok(())
    }

    /// A patch carrying code may contain `Update` or `Remove` storage ops, since it can describe a
    /// code upgrade. Such a patch cannot create an account, since the ops cannot be applied to the
    /// empty storage of a new account.
    #[rstest]
    #[case::update(
        AccountStoragePatch::builder().update_value(StorageSlotName::mock(1), Word::empty()).build()
    )]
    #[case::remove(
        AccountStoragePatch::builder().remove_value(StorageSlotName::mock(1)).build()
    )]
    fn account_patch_try_to_new_account_rejects_non_create_op(
        #[case] storage: AccountStoragePatch,
    ) -> anyhow::Result<()> {
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER)?;

        let patch = AccountPatch::new(
            account_id,
            storage,
            AccountVaultPatch::default(),
            AccountCodePatch::new(Some(AccountCode::mock())),
            Some(Felt::from(2u32)),
        )?;
        assert_matches!(
            patch.try_to_new_account().unwrap_err(),
            AccountError::NewAccountStorageRequiresCreateOps
        );

        Ok(())
    }

    /// A patch whose storage only creates slots can be reconstructed into an account.
    #[test]
    fn account_patch_try_to_new_account_with_create_reconstructs() -> anyhow::Result<()> {
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER)?;
        let code = AccountCode::mock();
        let created_slot = StorageSlotName::mock(1);
        let created_value = Word::from([7u32, 0, 0, 0]);

        let storage = AccountStoragePatch::builder()
            .create_value(created_slot.clone(), created_value)
            .build();

        let patch = AccountPatch::new(
            account_id,
            storage,
            AccountVaultPatch::default(),
            AccountCodePatch::new(Some(code.clone())),
            Some(Felt::ONE),
        )?;

        let account = patch.try_to_new_account()?;
        assert_eq!(account.code(), &code);
        assert_eq!(account.storage().get_item(&created_slot)?, created_value);

        Ok(())
    }

    // MERGE TESTS
    // ============================================================================================

    /// Returns account code that differs from [`AccountCode::mock`].
    fn upgraded_code() -> anyhow::Result<AccountCode> {
        Ok(AccountCode::from_components(&[NoopAuthComponent.into(), AddComponent.into()])?)
    }

    /// Returns a patch with a single updated value slot and the provided final nonce.
    fn update_patch(account_id: AccountId, final_nonce: u32) -> anyhow::Result<AccountPatch> {
        let storage = AccountStoragePatch::from_iters(
            [],
            [(StorageSlotName::mock(1), Word::from([1u32, 0, 0, 0]))],
            [],
        );
        AccountPatch::new(
            account_id,
            storage,
            AccountVaultPatch::default(),
            AccountCodePatch::default(),
            Some(Felt::from(final_nonce)),
        )
        .map_err(Into::into)
    }

    #[test]
    fn account_patch_merge_rejects_id_mismatch() -> anyhow::Result<()> {
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER)?;
        let other_account_id =
            AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE)?;

        let mut patch = update_patch(account_id, 2)?;
        let other = update_patch(other_account_id, 3)?;

        assert_matches!(
            patch.merge(other).unwrap_err(),
            AccountPatchError::AccountIdMismatch { expected, actual } => {
                assert_eq!(expected, account_id);
                assert_eq!(actual, other_account_id);
            }
        );

        Ok(())
    }

    /// Merging a patch that upgrades the code replaces the code of the base and keeps the storage
    /// updates of both patches.
    #[test]
    fn account_patch_merge_replaces_code() -> anyhow::Result<()> {
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER)?;
        let code = upgraded_code()?;
        let updated_slot = StorageSlotName::mock(2);
        let updated_value = Word::from([2u32, 0, 0, 0]);

        let mut patch = update_patch(account_id, 2)?;
        let other = AccountPatch::new(
            account_id,
            AccountStoragePatch::builder()
                .update_value(updated_slot.clone(), updated_value)
                .build(),
            AccountVaultPatch::default(),
            AccountCodePatch::new(Some(code.clone())),
            Some(Felt::from(3u32)),
        )?;

        patch.merge(other)?;

        assert_eq!(patch.code().as_code(), Some(&code));
        assert_eq!(patch.final_nonce(), Some(Felt::from(3u32)));
        assert_eq!(patch.storage().num_slots(), 2);
        assert_eq!(patch.storage().updated_value(&updated_slot), Some(updated_value));

        Ok(())
    }

    #[rstest::rstest]
    #[case::equal(3, 3)]
    #[case::smaller(3, 2)]
    #[case::gap(3, 5)]
    fn account_patch_merge_rejects_non_incrementing_nonce(
        #[case] self_nonce: u32,
        #[case] other_nonce: u32,
    ) -> anyhow::Result<()> {
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER)?;
        let mut patch = update_patch(account_id, self_nonce)?;
        let other = update_patch(account_id, other_nonce)?;

        assert_matches!(
            patch.merge(other).unwrap_err(),
            AccountPatchError::NonceMustIncrementByOne { current, new } => {
                assert_eq!(current, Felt::from(self_nonce));
                assert_eq!(new, Felt::from(other_nonce));
            }
        );

        Ok(())
    }

    #[test]
    fn account_patch_merge_rejects_storage_slot_type_conflict() -> anyhow::Result<()> {
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER)?;
        let shared_slot = StorageSlotName::mock(7);

        let value_storage = AccountStoragePatch::from_iters(
            [],
            [(shared_slot.clone(), Word::from([9u32, 0, 0, 0]))],
            [],
        );
        let map_storage = AccountStoragePatch::from_iters(
            [],
            [],
            [(shared_slot.clone(), StorageMapPatch::from_iters([], []))],
        );

        let mut patch = AccountPatch::new(
            account_id,
            value_storage,
            AccountVaultPatch::default(),
            AccountCodePatch::default(),
            Some(Felt::from(2u32)),
        )?;
        let other = AccountPatch::new(
            account_id,
            map_storage,
            AccountVaultPatch::default(),
            AccountCodePatch::default(),
            Some(Felt::from(3u32)),
        )?;

        assert_matches!(
            patch.merge(other).unwrap_err(),
            AccountPatchError::StorageSlotUsedAsDifferentTypes(slot) => {
                assert_eq!(slot, shared_slot);
            }
        );

        Ok(())
    }

    #[test]
    fn account_patch_merge_overrides_vault_entry() -> anyhow::Result<()> {
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER)?;
        let asset_initial: Asset = FungibleAsset::mock(100);
        let asset_updated: Asset = FungibleAsset::mock(250);
        assert_eq!(asset_initial.id(), asset_updated.id());

        let mut patch = AccountPatch::new(
            account_id,
            AccountStoragePatch::new(),
            AccountVaultPatch::with_assets([asset_initial]),
            AccountCodePatch::default(),
            Some(Felt::from(2u32)),
        )?;
        let other = AccountPatch::new(
            account_id,
            AccountStoragePatch::new(),
            AccountVaultPatch::with_assets([asset_updated]),
            AccountCodePatch::default(),
            Some(Felt::from(3u32)),
        )?;

        patch.merge(other)?;

        assert_eq!(patch.vault().num_assets(), 1);
        assert_eq!(
            patch.vault().as_map().get(&asset_updated.id()).copied(),
            Some(asset_updated.to_value_word())
        );

        Ok(())
    }

    #[test]
    fn account_patch_merge_overrides_storage_value() -> anyhow::Result<()> {
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER)?;
        let slot_name = StorageSlotName::mock(1);
        let initial_value = Word::from([1u32, 0, 0, 0]);
        let updated_value = Word::from([2u32, 0, 0, 0]);

        let mut patch = AccountPatch::new(
            account_id,
            AccountStoragePatch::from_iters([], [(slot_name.clone(), initial_value)], []),
            AccountVaultPatch::default(),
            AccountCodePatch::default(),
            Some(Felt::from(2u32)),
        )?;
        let other = AccountPatch::new(
            account_id,
            AccountStoragePatch::from_iters([], [(slot_name.clone(), updated_value)], []),
            AccountVaultPatch::default(),
            AccountCodePatch::default(),
            Some(Felt::from(3u32)),
        )?;

        patch.merge(other)?;

        assert_eq!(patch.storage().num_slots(), 1);
        assert_eq!(patch.storage().updated_value(&slot_name), Some(updated_value));

        Ok(())
    }

    #[test]
    fn account_patch_merge_extends_storage_map() -> anyhow::Result<()> {
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER)?;
        let map_slot = StorageSlotName::mock(1);
        let key_self = StorageMapKey::from_array([1, 0, 0, 0]);
        let value_self = Word::from([10u32, 0, 0, 0]);
        let key_other = StorageMapKey::from_array([2, 0, 0, 0]);
        let value_other = Word::from([20u32, 0, 0, 0]);

        let mut patch = AccountPatch::new(
            account_id,
            AccountStoragePatch::from_iters(
                [],
                [],
                [(map_slot.clone(), StorageMapPatch::from_iters([], [(key_self, value_self)]))],
            ),
            AccountVaultPatch::default(),
            AccountCodePatch::default(),
            Some(Felt::from(2u32)),
        )?;
        let other = AccountPatch::new(
            account_id,
            AccountStoragePatch::from_iters(
                [],
                [],
                [(map_slot.clone(), StorageMapPatch::from_iters([], [(key_other, value_other)]))],
            ),
            AccountVaultPatch::default(),
            AccountCodePatch::default(),
            Some(Felt::from(3u32)),
        )?;

        patch.merge(other)?;

        assert_eq!(patch.storage().num_slots(), 1);
        assert_eq!(patch.storage().updated_map(&map_slot).unwrap().num_entries(), 2);
        assert_eq!(patch.storage().updated_map_item(&map_slot, &key_self), Some(value_self));
        assert_eq!(patch.storage().updated_map_item(&map_slot, &key_other), Some(value_other));

        Ok(())
    }

    /// A creation patch as the merge base, with a patch updating one of its created slots, stays a
    /// creation patch carrying only `Create` ops.
    #[test]
    fn account_patch_merge_creation_base_stays_creation_patch() -> anyhow::Result<()> {
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER)?;
        let code = AccountCode::mock();
        let slot_name = StorageSlotName::mock(1);
        let created_value = Word::from([1u32, 0, 0, 0]);
        let updated_value = Word::from([2u32, 0, 0, 0]);

        // Creation base: a created value slot, code and the account-creation nonce of 1.
        let mut patch = AccountPatch::new(
            account_id,
            AccountStoragePatch::builder()
                .create_value(slot_name.clone(), created_value)
                .build(),
            AccountVaultPatch::default(),
            AccountCodePatch::new(Some(code.clone())),
            Some(Felt::ONE),
        )?;

        // Patch updating the same slot in the next transaction.
        let other = AccountPatch::new(
            account_id,
            AccountStoragePatch::builder()
                .update_value(slot_name.clone(), updated_value)
                .build(),
            AccountVaultPatch::default(),
            AccountCodePatch::default(),
            Some(Felt::from(2u32)),
        )?;

        patch.merge(other)?;

        assert_eq!(patch.code().as_code(), Some(&code));
        assert_eq!(patch.final_nonce(), Some(Felt::from(2u32)));
        assert!(!patch.storage().contains_non_create_ops());
        assert_eq!(patch.storage().created_value(&slot_name), Some(updated_value));

        Ok(())
    }

    /// A + B_empty = A
    #[test]
    fn account_patch_merge_empty_other_is_noop() -> anyhow::Result<()> {
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER)?;
        let mut patch = update_patch(account_id, 4)?;
        let snapshot = patch.clone();

        let empty = AccountPatch::empty(account_id);

        patch.merge(empty)?;
        assert_eq!(patch, snapshot);

        Ok(())
    }

    /// A_empty + B = B
    #[test]
    fn account_patch_merge_empty_self_adopts_other() -> anyhow::Result<()> {
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER)?;
        let mut empty = AccountPatch::empty(account_id);
        let other = update_patch(account_id, 7)?;
        let expected = other.clone();

        empty.merge(other)?;
        assert_eq!(empty, expected);

        Ok(())
    }
}
