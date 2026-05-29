mod vault_patch;
use alloc::vec::Vec;

pub use vault_patch::AccountVaultPatch;

use crate::account::{AccountCode, AccountId, AccountStoragePatch};
use crate::crypto::SequentialCommit;
use crate::errors::AccountPatchError;
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
    new_nonce: Option<Felt>,
}

impl AccountPatch {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns a new [`AccountPatch`] instantiated from the provided components.
    ///
    /// `new_nonce` must be `Some(non_zero_nonce)` if `storage` or `vault` contain any updates, and
    /// can be `None` only for empty patches.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `new_nonce` is `Some(Felt::ZERO)`. The tx kernel guarantees that an updated nonce is at
    ///   least one, so a zero nonce is never a valid post-tx-state. Empty patches must be
    ///   constructed with `None` instead.
    /// - `storage` or `vault` contain updates but `new_nonce` is `None`. The tx kernel mandates
    ///   that the nonce is incremented whenever account state changes.
    pub fn new(
        account_id: AccountId,
        storage: AccountStoragePatch,
        vault: AccountVaultPatch,
        code: Option<AccountCode>,
        new_nonce: Option<Felt>,
    ) -> Result<Self, AccountPatchError> {
        // New nonce should never be zero as the tx kernel requires that the nonce must be
        // incremented to at least 1 in the account-creating transaction.
        // Patches that do not change the account (and the nonce) should pass `None`.
        if new_nonce.is_some_and(|new_nonce| new_nonce == Felt::ZERO) {
            return Err(AccountPatchError::NewNonceIsZero);
        }

        // If account storage or vault were updated the nonce cannot be zero, as mandated by the tx
        // kernel
        let was_nonce_not_updated =
            new_nonce.map(|new_nonce| new_nonce == Felt::ZERO).unwrap_or(true);
        if (!storage.is_empty() || !vault.is_empty()) && was_nonce_not_updated {
            return Err(AccountPatchError::NonEmptyStorageOrVaultDeltaWithZeroNonceDelta);
        }

        // Code must be provided for new accounts (nonce = 1) to be able to reconstruct the full
        // Account.
        if new_nonce.is_some_and(|new_nonce| new_nonce == Felt::ONE) && code.is_none() {
            return Err(AccountPatchError::CodeMustBeProvidedForNewAccounts);
        }

        Ok(Self {
            account_id,
            storage,
            vault,
            code,
            new_nonce,
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
    pub fn new_nonce(&self) -> Option<Felt> {
        self.new_nonce
    }

    /// Returns true if this account patch does not contain any vault or storage updates and the
    /// nonce wasn't updated.
    pub fn is_empty(&self) -> bool {
        self.storage.is_empty() && self.vault.is_empty() && self.new_nonce.is_none()
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
    /// - Append `[[new_nonce, 0, account_id_suffix, account_id_prefix], EMPTY_WORD]`, where
    ///   `account_id_{prefix,suffix}` are the prefix and suffix felts of the native account id and
    ///   `new_nonce` is the the new nonce of the account.
    /// - Asset Patch
    ///   - For each asset whose value has changed compared to the initial state of the transaction,
    ///     sorted by its vault key:
    ///     - Append `[ASSET_KEY, ASSET_VALUE]` which are the key and value of the asset.
    ///     - Append `[[domain = 1, num_changed_assets, 0, 0], 0, 0, 0, 0]`, where
    ///       `num_changed_assets` is the number of assets that were appended.
    /// - Storage Slots are sorted by slot ID and are iterated in this order. For each slot **whose
    ///   value has changed**, depending on the slot type:
    ///   - Value Slot
    ///     - Append `[[domain = 2, 0, slot_id_suffix, slot_id_prefix], NEW_VALUE]` where
    ///       `NEW_VALUE` is the new value of the slot and `slot_id_{suffix, prefix}` is the
    ///       identifier of the slot.
    ///   - Map Slot
    ///     - For each key-value pair, sorted by key, whose new value is different from the previous
    ///       value in the map:
    ///       - Append `[KEY, NEW_VALUE]`.
    ///     - Append `[[domain = 3, num_changed_entries, slot_id_suffix, slot_id_prefix], 0, 0, 0,
    ///       0]`, where `slot_id_{suffix, prefix}` are the slot identifiers and
    ///       `num_changed_entries` is the number of changed key-value pairs in the map.
    ///         - For partial state deltas, the map header must only be included if
    ///           `num_changed_entries` is not zero.
    ///         - For full state deltas, the map header must always be included.
    pub fn to_commitment(&self) -> Word {
        <Self as SequentialCommit>::to_commitment(self)
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
        let new_nonce = self.new_nonce.expect("non-empty patches should have a new nonce set");
        elements.extend_from_slice(&[
            new_nonce,
            Felt::ZERO,
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

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::{AccountPatch, AccountVaultPatch};
    use crate::Felt;
    use crate::account::{AccountCode, AccountId, AccountStoragePatch, StorageSlotName};
    use crate::asset::FungibleAsset;
    use crate::errors::AccountPatchError;
    use crate::testing::account_id::ACCOUNT_ID_PRIVATE_SENDER;

    /// A `new_nonce` set to `Some(Felt::ZERO)` is rejected: the tx kernel guarantees the nonce of
    /// an updated account is at least one, so empty patches must pass `None` instead.
    #[test]
    fn account_patch_new_nonce_is_zero() -> anyhow::Result<()> {
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER)?;

        let error = AccountPatch::new(
            account_id,
            AccountStoragePatch::new(),
            AccountVaultPatch::new([]),
            None,
            Some(Felt::ZERO),
        )
        .unwrap_err();

        assert_matches!(error, AccountPatchError::NewNonceIsZero);

        Ok(())
    }

    /// A patch that updates storage or the vault but leaves `new_nonce` as `None` is rejected,
    /// since any account state change requires the nonce to be incremented.
    #[test]
    fn account_patch_non_empty_with_no_nonce_update() -> anyhow::Result<()> {
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER)?;

        let non_empty_storage = AccountStoragePatch::from_iters([StorageSlotName::mock(1)], [], []);
        let storage_error = AccountPatch::new(
            account_id,
            non_empty_storage,
            AccountVaultPatch::new([]),
            None,
            None,
        )
        .unwrap_err();
        assert_matches!(
            storage_error,
            AccountPatchError::NonEmptyStorageOrVaultDeltaWithZeroNonceDelta
        );

        let non_empty_vault = AccountVaultPatch::new([FungibleAsset::mock(100)]);
        let vault_error =
            AccountPatch::new(account_id, AccountStoragePatch::new(), non_empty_vault, None, None)
                .unwrap_err();
        assert_matches!(
            vault_error,
            AccountPatchError::NonEmptyStorageOrVaultDeltaWithZeroNonceDelta
        );

        Ok(())
    }

    /// A patch for a newly created account (`new_nonce = Some(Felt::ONE)`) must include the
    /// account code, since otherwise the full account cannot be reconstructed from the patch.
    #[test]
    fn account_patch_new_account_requires_code() -> anyhow::Result<()> {
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER)?;

        let error = AccountPatch::new(
            account_id,
            AccountStoragePatch::new(),
            AccountVaultPatch::new([]),
            None,
            Some(Felt::ONE),
        )
        .unwrap_err();
        assert_matches!(error, AccountPatchError::CodeMustBeProvidedForNewAccounts);

        // With the code provided, the same patch should succeed.
        AccountPatch::new(
            account_id,
            AccountStoragePatch::new(),
            AccountVaultPatch::new([]),
            Some(AccountCode::mock()),
            Some(Felt::ONE),
        )?;

        Ok(())
    }
}
