use alloc::boxed::Box;

use crate::Word;
use crate::account::AccountId;
use crate::account::delta::AccountUpdateDetails;
use crate::errors::BatchAccountUpdateError;
use crate::transaction::ProvenTransaction;
use crate::utils::serde::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
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
    /// - If the underlying [`AccountUpdateDetails::merge`] fails.
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

        self.details = self.details.clone().merge(tx.account_update().details().clone()).map_err(
            |source_err| {
                BatchAccountUpdateError::TransactionUpdateMergeError(tx.id(), Box::new(source_err))
            },
        )?;
        self.final_state_commitment = tx.account_update().final_state_commitment();

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
        Ok(Self {
            account_id: AccountId::read_from(source)?,
            initial_state_commitment: Word::read_from(source)?,
            final_state_commitment: Word::read_from(source)?,
            details: AccountUpdateDetails::read_from(source)?,
        })
    }
}
