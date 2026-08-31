use alloc::boxed::Box;
use alloc::string::ToString;

use crate::Word;
use crate::account::{AccountId, AccountUpdateDetails, validate_new_public_account};
use crate::errors::BatchAccountUpdateError;
use crate::transaction::ProvenTransaction;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

// BATCH ACCOUNT UPDATE
// ================================================================================================

/// Represents the changes made to an account resulting from executing a batch of transactions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchAccountUpdate {
    /// ID of the updated account.
    account_id: AccountId,

    /// Commitment to the state of the account before this update is applied.
    ///
    /// Equal to `Word::empty()` for new accounts.
    initial_state_commitment: Word,

    /// Commitment to the state of the account after this update is applied.
    final_state_commitment: Word,

    /// A set of changes which can be applied to the previous account state (i.e. `initial_state`)
    /// to get the new account state. For private accounts, this is set to
    /// [`AccountUpdateDetails::Private`].
    details: AccountUpdateDetails,
}

impl BatchAccountUpdate {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a [`BatchAccountUpdate`] by cloning the update and other details from the provided
    /// [`ProvenTransaction`].
    pub fn from_transaction(transaction: &ProvenTransaction) -> Self {
        Self {
            account_id: transaction.account_id(),
            initial_state_commitment: transaction.account_update().initial_state_commitment(),
            final_state_commitment: transaction.account_update().final_state_commitment(),
            details: transaction.account_update().details().clone(),
        }
    }

    /// Creates a validated [`BatchAccountUpdate`] from the provided parts.
    ///
    /// This enforces the same public/private account-detail invariants as transaction account
    /// updates. For a new public account, the patch must contain the complete account state and
    /// reconstruct to `final_state_commitment`.
    pub fn new(
        account_id: AccountId,
        initial_state_commitment: Word,
        final_state_commitment: Word,
        details: AccountUpdateDetails,
    ) -> Result<Self, BatchAccountUpdateError> {
        let update = Self {
            account_id,
            initial_state_commitment,
            final_state_commitment,
            details,
        };

        update.validate()?;

        Ok(update)
    }

    /// Validates this account update's size and account-detail invariants.
    pub(crate) fn validate(&self) -> Result<(), BatchAccountUpdateError> {
        self.details.validate_size(self.account_id)?;

        let Some(patch) = self.details.validate_for_account(self.account_id)? else {
            return Ok(());
        };

        if self.initial_state_commitment.is_empty() {
            validate_new_public_account(patch, self.final_state_commitment)?;
        }

        Ok(())
    }

    /// Creates a [`BatchAccountUpdate`] from the provided parts without checking any consistency.
    #[cfg(any(feature = "testing", test))]
    pub fn new_unchecked(
        account_id: AccountId,
        initial_state_commitment: Word,
        final_state_commitment: Word,
        details: AccountUpdateDetails,
    ) -> Self {
        Self {
            account_id,
            initial_state_commitment,
            final_state_commitment,
            details,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the ID of the updated account.
    pub fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Returns a commitment to the state of the account before this update is applied.
    ///
    /// This is equal to [`Word::empty()`] for new accounts.
    pub fn initial_state_commitment(&self) -> Word {
        self.initial_state_commitment
    }

    /// Returns a commitment to the state of the account after this update is applied.
    pub fn final_state_commitment(&self) -> Word {
        self.final_state_commitment
    }

    /// Returns the contained [`AccountUpdateDetails`].
    ///
    /// This update can be used to build the new account state from the previous account state.
    pub fn details(&self) -> &AccountUpdateDetails {
        &self.details
    }

    /// Returns `true` if the account update details are for a private account.
    pub fn is_private(&self) -> bool {
        self.details.is_private()
    }

    // MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Merges the transaction's update into this account update.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The account ID of the merging transaction does not match the account ID of the existing
    ///   update.
    /// - The merging transaction's initial state commitment does not match the final state
    ///   commitment of the current update.
    /// - The underlying [`AccountUpdateDetails::merge`] fails.
    /// - The merged account update fails the validation performed by [`Self::new`], including the
    ///   account update size limit and new-public-account commitment checks.
    pub fn merge_proven_tx(
        &mut self,
        tx: &ProvenTransaction,
    ) -> Result<(), BatchAccountUpdateError> {
        if self.account_id != tx.account_id() {
            return Err(BatchAccountUpdateError::AccountUpdateIdMismatch {
                transaction: tx.id(),
                expected_account_id: self.account_id,
                actual_account_id: tx.account_id(),
            });
        }

        if self.final_state_commitment != tx.account_update().initial_state_commitment() {
            return Err(BatchAccountUpdateError::AccountUpdateInitialStateMismatch(tx.id()));
        }

        let details = self.details.clone().merge(tx.account_update().details().clone()).map_err(
            |source_err| {
                BatchAccountUpdateError::TransactionUpdateMergeError(tx.id(), Box::new(source_err))
            },
        )?;
        let merged_update = Self::new(
            self.account_id,
            self.initial_state_commitment,
            tx.account_update().final_state_commitment(),
            details,
        )?;

        *self = merged_update;

        Ok(())
    }

    // CONVERSIONS
    // --------------------------------------------------------------------------------------------

    /// Consumes the update and returns the underlying [`AccountUpdateDetails`].
    pub fn into_update(self) -> AccountUpdateDetails {
        self.details
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for BatchAccountUpdate {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.account_id.write_into(target);
        self.initial_state_commitment.write_into(target);
        self.final_state_commitment.write_into(target);
        self.details.write_into(target);
    }
}

impl Deserializable for BatchAccountUpdate {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let account_id = AccountId::read_from(source)?;
        let initial_state_commitment = Word::read_from(source)?;
        let final_state_commitment = Word::read_from(source)?;
        let details = AccountUpdateDetails::read_from(source)?;
        Self::new(account_id, initial_state_commitment, final_state_commitment, details)
            .map_err(|error| DeserializationError::InvalidValue(error.to_string()))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use core::ops::Range;

    use assert_matches::assert_matches;

    use super::BatchAccountUpdate;
    use crate::account::{
        Account,
        AccountId,
        AccountPatch,
        AccountType,
        AccountUpdateDetails,
        AccountVaultPatch,
        StorageMapKey,
        StorageSlotName,
    };
    use crate::block::BlockNumber;
    use crate::errors::BatchAccountUpdateError;
    use crate::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE;
    use crate::testing::add_component::AddComponent;
    use crate::testing::noop_auth_component::NoopAuthComponent;
    use crate::testing::storage::AccountStoragePatchBuilder;
    use crate::transaction::{InputNoteCommitment, OutputNote, ProvenTransaction, TxAccountUpdate};
    use crate::utils::serde::Serializable;
    use crate::{ACCOUNT_UPDATE_MAX_SIZE, Felt, Word};

    fn map_update_patch(
        account_id: AccountId,
        key_range: Range<u32>,
        final_nonce: u32,
    ) -> AccountPatch {
        let entries =
            key_range.map(|key| (StorageMapKey::from_index(key), Word::from([key + 1, 1, 2, 3])));
        let storage = AccountStoragePatchBuilder::new()
            .update_map(StorageSlotName::mock(4), entries)
            .build();

        AccountPatch::new(
            account_id,
            storage,
            AccountVaultPatch::default(),
            None,
            Some(Felt::from(final_nonce)),
        )
        .unwrap()
    }

    fn proven_transaction(
        account_id: AccountId,
        initial_state_commitment: Word,
        final_state_commitment: Word,
        patch: AccountPatch,
    ) -> ProvenTransaction {
        let patch_commitment = patch.to_commitment();
        let update = TxAccountUpdate::new(
            account_id,
            initial_state_commitment,
            final_state_commitment,
            patch_commitment,
            AccountUpdateDetails::Public(patch),
        )
        .unwrap();

        ProvenTransaction::new(
            update,
            Vec::<InputNoteCommitment>::new(),
            Vec::<OutputNote>::new(),
            BlockNumber::from(1),
            Word::empty(),
            BlockNumber::from(2),
            crate::testing::proof::dummy_execution_proof(),
        )
        .unwrap()
    }

    #[test]
    fn merge_rejects_aggregate_update_exceeding_size_limit_atomically() {
        let account_id =
            AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap();
        let initial_state_commitment = Word::from([1_u32, 2, 3, 4]);
        let intermediate_state_commitment = Word::from([5_u32, 6, 7, 8]);
        let final_state_commitment = Word::from([9_u32, 10, 11, 12]);
        let total_entries_to_exceed_limit =
            ACCOUNT_UPDATE_MAX_SIZE as usize / (StorageMapKey::SERIALIZED_SIZE * 2);
        let entries_per_tx = total_entries_to_exceed_limit / 2;
        let second_range_start = u32::try_from(entries_per_tx).unwrap();
        let second_range_end = u32::try_from(total_entries_to_exceed_limit).unwrap();

        let first_tx = proven_transaction(
            account_id,
            initial_state_commitment,
            intermediate_state_commitment,
            map_update_patch(account_id, 0..second_range_start, 2),
        );
        let second_tx = proven_transaction(
            account_id,
            intermediate_state_commitment,
            final_state_commitment,
            map_update_patch(account_id, second_range_start..second_range_end, 3),
        );
        let merged_details = first_tx
            .account_update()
            .details()
            .clone()
            .merge(second_tx.account_update().details().clone())
            .unwrap();
        let expected_update_size = merged_details.get_size_hint();
        assert!(expected_update_size > ACCOUNT_UPDATE_MAX_SIZE as usize);
        let mut update = BatchAccountUpdate::from_transaction(&first_tx);
        let original_update = update.clone();

        let error = update.merge_proven_tx(&second_tx).unwrap_err();

        assert_matches!(
            error,
            BatchAccountUpdateError::AccountUpdateSizeLimitExceeded {
                account_id: actual_account_id,
                update_size,
            } if actual_account_id == account_id && update_size == expected_update_size
        );
        assert_eq!(update, original_update);
    }

    #[test]
    fn merge_rejects_full_state_commitment_mismatch_atomically() {
        let account = Account::builder([9; 32])
            .account_type(AccountType::Public)
            .with_component(NoopAuthComponent)
            .with_component(AddComponent)
            .build_existing()
            .unwrap();
        let account_commitment = account.to_commitment();
        let wrong_final_state_commitment = Word::from([9_u32, 10, 11, 12]);
        assert_ne!(wrong_final_state_commitment, account_commitment);
        let first_tx = proven_transaction(
            account.id(),
            Word::empty(),
            account_commitment,
            AccountPatch::try_from(account.clone()).unwrap(),
        );
        let second_tx = proven_transaction(
            account.id(),
            account_commitment,
            wrong_final_state_commitment,
            AccountPatch::empty(account.id()),
        );
        let mut update = BatchAccountUpdate::from_transaction(&first_tx);
        let original_update = update.clone();

        let error = update.merge_proven_tx(&second_tx).unwrap_err();

        assert_matches!(
            error,
            BatchAccountUpdateError::AccountFinalCommitmentMismatch {
                final_state_commitment,
                account_commitment: actual_account_commitment,
            } if final_state_commitment == wrong_final_state_commitment
                && actual_account_commitment == account_commitment
        );
        assert_eq!(update, original_update);
    }

    #[test]
    fn merge_accepts_valid_aggregate_update() {
        let account_id =
            AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap();
        let initial_state_commitment = Word::from([1_u32, 2, 3, 4]);
        let intermediate_state_commitment = Word::from([5_u32, 6, 7, 8]);
        let final_state_commitment = Word::from([9_u32, 10, 11, 12]);
        let first_tx = proven_transaction(
            account_id,
            initial_state_commitment,
            intermediate_state_commitment,
            map_update_patch(account_id, 0..1, 2),
        );
        let second_tx = proven_transaction(
            account_id,
            intermediate_state_commitment,
            final_state_commitment,
            map_update_patch(account_id, 1..2, 3),
        );
        let mut update = BatchAccountUpdate::from_transaction(&first_tx);

        update.merge_proven_tx(&second_tx).unwrap();

        assert_eq!(update.initial_state_commitment(), initial_state_commitment);
        assert_eq!(update.final_state_commitment(), final_state_commitment);
        update.validate().unwrap();
    }
}
