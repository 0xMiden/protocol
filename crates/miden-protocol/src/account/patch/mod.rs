mod vault;

mod storage;
use alloc::string::ToString;
use alloc::vec::Vec;

pub use storage::{AccountStoragePatch, StorageMapPatch, StorageSlotPatch};
pub use vault::AccountVaultPatch;

use crate::account::{
    Account,
    AccountCode,
    AccountId,
    AccountStorage,
    StorageSlot,
    StorageSlotType,
};
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
use crate::{Felt, Word};

/// An [`AccountPatch`] describes the new absolute state of an account after one or more
/// transactions, in contrast to an [`AccountDelta`](crate::account::AccountDelta), which describes
/// the relative change.
///
/// For example, where a delta might say "remove 50 USDC from the vault", a patch says "the new
/// USDC balance is 100". This means a patch can be applied to compute the new account state
/// without loading the previous state and without invoking any custom asset compose logic (e.g.
/// merge/split procedures defined by the issuing faucet).
///
/// The presence of the code in a patch signals if the patch is a _full state_ or _partial state_
/// patch. A full state patch must be converted into an [`Account`] object, while a partial state
/// patch must be applied to an existing [`Account`].
///
/// The patch represents updates to the account as follows:
/// - storage: an [`AccountStoragePatch`] containing the new values of changed storage slots and map
///   entries. Storage updates are already absolute per changed entry, so no dedicated patch type is
///   required for storage.
/// - vault: an [`AccountVaultPatch`] containing the new values of changed vault entries.
/// - nonce: the new (absolute) nonce of the account, in contrast to
///   [`AccountDelta::nonce_delta`](crate::account::AccountDelta::nonce_delta) which stores the
///   increment.
/// - code: an [`AccountCode`] for new accounts and `None` for others, with the same semantics as in
///   [`AccountDelta`](crate::account::AccountDelta).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountPatch {
    /// The ID of the account to which this patch applies.
    account_id: AccountId,
    /// The new values of changed storage slots and map entries.
    storage: AccountStoragePatch,
    /// The new values of changed vault entries.
    vault: AccountVaultPatch,
    /// The code of a new account (`Some`) or `None` for existing accounts.
    code: Option<AccountCode>,
    /// The new (absolute) nonce of the account.
    ///
    /// Should be set to `None` if the nonce wasn't updated.
    final_nonce: Option<Felt>,
}

impl AccountPatch {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Domain separator for the account patch commitment header.
    const DOMAIN: Felt = Felt::new_unchecked(2);

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns a new [`AccountPatch`] instantiated from the provided components.
    ///
    /// `final_nonce` must be `Some(non_zero_nonce)` if `storage` or `vault` contain any updates,
    /// and can be `None` only for empty patches.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `final_nonce` is `Some(Felt::ZERO)`. The tx kernel guarantees that an updated nonce is at
    ///   least one, so a zero nonce is never a valid post-tx-state. Empty patches must be
    ///   constructed with `None` instead.
    /// - `storage` or `vault` contain updates but `final_nonce` is `None`. The tx kernel mandates
    ///   that the nonce is incremented whenever account state changes.
    /// - `code` is `Some` but `final_nonce` is `None`. A patch that carries account code describes
    ///   a full account state, which always has a nonce.
    pub fn new(
        account_id: AccountId,
        storage: AccountStoragePatch,
        vault: AccountVaultPatch,
        code: Option<AccountCode>,
        final_nonce: Option<Felt>,
    ) -> Result<Self, AccountPatchError> {
        // New nonce should never be zero as the tx kernel requires that the nonce must be
        // incremented to at least 1 in the account-creating transaction.
        // Patches that do not change the account (and the nonce) should pass `None`.
        if final_nonce.is_some_and(|final_nonce| final_nonce == Felt::ZERO) {
            return Err(AccountPatchError::FinalNonceIsZero);
        }

        // If account storage or vault were updated or code is present, the patch represents a state
        // change and so the nonce cannot be zero. The tx kernel mandates this (except it does not
        // consider code yet).
        if (!storage.is_empty() || !vault.is_empty() || code.is_some()) && final_nonce.is_none() {
            return Err(AccountPatchError::StateChangeRequiresNonceUpdate);
        }

        // Code must be provided for new accounts to be able to reconstruct the full Account.
        // New accounts are defined with nonce 0, but here we have the post-creation
        // final nonce, so we define new accounts as having final_nonce = 1.
        if final_nonce.is_some_and(|final_nonce| final_nonce == Felt::ONE) && code.is_none() {
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

    /// Returns a reference to the account code of this patch, if present.
    pub fn code(&self) -> Option<&AccountCode> {
        self.code.as_ref()
    }

    /// Returns the new (absolute) nonce of the account after this patch is applied, or `None` if
    /// the nonce wasn't updated.
    pub fn final_nonce(&self) -> Option<Felt> {
        self.final_nonce
    }

    /// Returns `true` if this patch is a "full state" patch, `false` otherwise, i.e. if it is a
    /// "partial state" patch.
    ///
    /// See the type-level docs for more on this distinction.
    pub fn is_full_state(&self) -> bool {
        // TODO(code_upgrades): Change this to another detection mechanism once we have code upgrade
        // support, at which point the presence of code may not be enough of an indication that a
        // patch can be converted to a full account.
        //
        // The constructor enforces that `code.is_some()` implies `final_nonce.is_some()`, so the
        // presence of code alone is sufficient to identify a full state patch.
        self.code.is_some()
    }

    /// Returns true if this account patch does not contain any vault or storage updates and the
    /// nonce wasn't updated.
    pub fn is_empty(&self) -> bool {
        // The check can be implemented by checking only the nonce, since the constructor validates
        // that non-empty storage or vault patches must increment the nonce.
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
    /// empty and is appended to in the following way. Whenever sorting is expected, it is that
    /// of a [`Word`].
    ///
    /// - Append `[[domain = 2, final_nonce, account_id_suffix, account_id_prefix], EMPTY_WORD]`,
    ///   where `account_id_{prefix,suffix}` are the prefix and suffix felts of the native account
    ///   id, `final_nonce` is the new nonce of the account, and `domain = 2` identifies the header
    ///   as the start of an account patch commitment (distinguishing it from a delta commitment,
    ///   which uses `domain = 1`).
    /// - Asset Patch
    ///   - For each asset whose value has changed compared to the initial state of the transaction,
    ///     including if it was removed, sorted by its vault key:
    ///     - Append `[ASSET_KEY, ASSET_VALUE_OR_EMPTY_WORD]` which are the key and either the value
    ///       of the asset (for updates) or the empty word (for removals).
    ///     - Append `[[domain = 4, num_changed_assets, 0, 0], 0, 0, 0, 0]`, where
    ///       `num_changed_assets` is the number of assets that were appended. Note that this is a
    ///       distinct domain from the delta asset domain (`3`), so an asset delta and an asset
    ///       patch can never produce the same commitment.
    /// - Storage Slots are sorted by slot ID and are iterated in this order. For each slot **whose
    ///   value has changed**, depending on the slot type:
    ///   - Value Slot
    ///     - Append `[[domain = 5, 0, slot_id_suffix, slot_id_prefix], NEW_VALUE]` where
    ///       `NEW_VALUE` is the new value of the slot and `slot_id_{suffix, prefix}` is the
    ///       identifier of the slot.
    ///   - Map Slot
    ///     - For each key-value pair, sorted by key, whose new value is different from the previous
    ///       value in the map:
    ///       - Append `[KEY, NEW_VALUE]`.
    ///     - Append `[[domain = 6, num_changed_entries, slot_id_suffix, slot_id_prefix], 0, 0, 0,
    ///       0]`, where `slot_id_{suffix, prefix}` are the slot identifiers and
    ///       `num_changed_entries` is the number of changed key-value pairs in the map.
    ///         - For partial state deltas, the map header must only be included if
    ///           `num_changed_entries` is not zero.
    ///         - For full state deltas, the map header must always be included.
    ///
    /// Headers for storage map slots and asset patches are appended rather than prepended since the
    /// tx kernel cannot efficiently get the number of changed entries before the iteration.
    pub fn to_commitment(&self) -> Word {
        <Self as SequentialCommit>::to_commitment(self)
    }
}

impl TryFrom<&AccountPatch> for Account {
    type Error = AccountError;

    /// Converts an [`AccountPatch`] into an [`Account`].
    ///
    /// Conceptually, this applies the patch onto an empty account. Only patches that fully
    /// describe an account (i.e. carry account code and a final nonce) can be converted; see
    /// [`AccountPatch`] for details.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The patch does not carry account code or a final nonce.
    /// - Applying the vault patch to an empty vault fails.
    /// - Applying the storage patch to the reconstructed initial storage fails.
    fn try_from(patch: &AccountPatch) -> Result<Self, Self::Error> {
        if !patch.is_full_state() {
            return Err(AccountError::PartialStatePatchToAccount);
        }

        // The constructor guarantees that a full state patch carries both code and a final nonce.
        let code = patch.code().cloned().expect("full state patch must carry code");
        let nonce = patch.final_nonce().expect("full state patch must carry final nonce");

        let mut vault = AssetVault::default();
        vault.apply_patch(patch.vault()).map_err(AccountError::AssetVaultUpdateError)?;

        let mut empty_storage_slots = Vec::new();
        for (slot_name, slot_patch) in patch.storage().slots() {
            let slot = match slot_patch.slot_type() {
                StorageSlotType::Value => StorageSlot::with_empty_value(slot_name.clone()),
                StorageSlotType::Map => StorageSlot::with_empty_map(slot_name.clone()),
            };
            empty_storage_slots.push(slot);
        }
        let mut storage = AccountStorage::new(empty_storage_slots)
            .expect("storage patch should contain a valid number of slots");
        storage.apply_patch(patch.storage())?;

        Account::new(patch.id(), vault, storage, code, nonce, None)
    }
}

impl SequentialCommit for AccountPatch {
    type Commitment = Word;

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

        // ID and Nonce
        let final_nonce = self.final_nonce.expect("non-empty patches should have a new nonce set");
        elements.extend_from_slice(&[
            Self::DOMAIN,
            final_nonce,
            self.account_id.suffix(),
            self.account_id.prefix().as_felt(),
        ]);
        elements.extend_from_slice(Word::empty().as_elements());

        // Vault patch
        self.vault.append_patch_elements(&mut elements);

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
        let code = <Option<AccountCode>>::read_from(source)?;
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

    use super::{AccountPatch, AccountVaultPatch};
    use crate::account::{
        Account,
        AccountCode,
        AccountId,
        AccountStoragePatch,
        StorageMapKey,
        StorageMapPatch,
        StorageSlotName,
    };
    use crate::asset::{FungibleAsset, NonFungibleAsset};
    use crate::errors::{AccountError, AccountPatchError};
    use crate::testing::account_id::ACCOUNT_ID_PRIVATE_SENDER;
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

        let account_patch =
            AccountPatch::new(account_id, storage_patch, vault_patch, None, Some(Felt::from(5u8)))?;
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
            None,
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
        None,
    )]
    #[case::non_empty_vault(
        AccountStoragePatch::new(),
        AccountVaultPatch::with_assets([FungibleAsset::mock(100)]),
        None,
    )]
    #[case::present_code(
        AccountStoragePatch::new(),
        AccountVaultPatch::default(),
        Some(AccountCode::mock())
    )]
    #[test]
    fn account_patch_with_state_change_requires_nonce_update(
        #[case] storage: AccountStoragePatch,
        #[case] vault: AccountVaultPatch,
        #[case] code: Option<AccountCode>,
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
            None,
            Some(Felt::ONE),
        )
        .unwrap_err();
        assert_matches!(error, AccountPatchError::CodeMustBeProvidedForNewAccounts);

        // With the code provided, the same patch should succeed.
        AccountPatch::new(
            account_id,
            AccountStoragePatch::new(),
            AccountVaultPatch::default(),
            Some(AccountCode::mock()),
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

        let storage_patch =
            AccountStoragePatch::from_iters([], [(slot_name.clone(), slot_value)], []);

        let patch = AccountPatch::new(
            account_id,
            storage_patch,
            AccountVaultPatch::with_assets([asset]),
            Some(code.clone()),
            Some(Felt::ONE),
        )?;

        let account = Account::try_from(&patch)?;

        assert_eq!(account.id(), account_id);
        assert_eq!(account.code(), &code);
        assert_eq!(account.nonce(), Felt::ONE);
        assert_eq!(account.storage().get_item(&slot_name)?, slot_value);
        assert_eq!(account.vault().get(asset.vault_key()), Some(asset));

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
    fn account_try_from_partial_patch_fails(
        #[case] final_nonce: Option<Felt>,
    ) -> anyhow::Result<()> {
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER)?;

        let patch = AccountPatch::new(
            account_id,
            AccountStoragePatch::new(),
            AccountVaultPatch::default(),
            None,
            final_nonce,
        )?;
        assert_matches!(
            Account::try_from(&patch).unwrap_err(),
            AccountError::PartialStatePatchToAccount
        );

        Ok(())
    }
}
