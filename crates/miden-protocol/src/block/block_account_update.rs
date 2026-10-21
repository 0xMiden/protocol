use alloc::string::ToString;

use crate::Word;
use crate::account::{AccountId, AccountUpdateDetails, validate_new_public_account};
use crate::errors::BlockAccountUpdateError;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

// BLOCK ACCOUNT UPDATE
// ================================================================================================

/// Describes the changes made to an account state resulting from executing transactions contained
/// in a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockAccountUpdate {
    /// ID of the updated account.
    account_id: AccountId,

    /// Final commitment to the new state of the account after this update.
    final_state_commitment: Word,

    /// A set of changes which can be applied to the previous account state (i.e., the state as of
    /// the last block) to get the new account state. For private accounts, this is set to
    /// [AccountUpdateDetails::Private].
    details: AccountUpdateDetails,
}

impl BlockAccountUpdate {
    /// Returns a new validated [`BlockAccountUpdate`].
    pub fn new(
        account_id: AccountId,
        final_state_commitment: Word,
        details: AccountUpdateDetails,
    ) -> Result<Self, BlockAccountUpdateError> {
        let update = Self::new_unchecked(account_id, final_state_commitment, details);
        update.validate()?;
        Ok(update)
    }

    /// Returns a new [`BlockAccountUpdate`] without validating its invariants.
    ///
    /// Callers must ensure that the update details are compatible with the account ID.
    pub(crate) const fn new_unchecked(
        account_id: AccountId,
        final_state_commitment: Word,
        details: AccountUpdateDetails,
    ) -> Self {
        Self {
            account_id,
            final_state_commitment,
            details,
        }
    }

    /// Validates that this account update's details are compatible with its account ID.
    pub(crate) fn validate(&self) -> Result<(), BlockAccountUpdateError> {
        self.details.validate_for_account(self.account_id)?;
        Ok(())
    }

    /// Validates that the update of a new public account reconstructs to its final state
    /// commitment.
    ///
    /// The update itself cannot tell a creation from an upgrade, so the caller must know that the
    /// account is new.
    pub(super) fn validate_new_account_patch(&self) -> Result<(), BlockAccountUpdateError> {
        if let AccountUpdateDetails::Public(patch) = &self.details {
            validate_new_public_account(patch, self.final_state_commitment)?;
        }

        Ok(())
    }

    /// Returns the ID of the updated account.
    pub fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Returns the state commitment of the account after this update.
    pub fn final_state_commitment(&self) -> Word {
        self.final_state_commitment
    }

    /// Returns the account update details for this account update.
    ///
    /// These details can be used to build the new account state from the previous account state.
    pub fn details(&self) -> &AccountUpdateDetails {
        &self.details
    }

    /// Returns `true` if the account update details are for private account.
    pub fn is_private(&self) -> bool {
        self.details.is_private()
    }
}

impl Serializable for BlockAccountUpdate {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.account_id.write_into(target);
        self.final_state_commitment.write_into(target);
        self.details.write_into(target);
    }
}

impl Deserializable for BlockAccountUpdate {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Self::new(
            AccountId::read_from(source)?,
            Word::read_from(source)?,
            AccountUpdateDetails::read_from(source)?,
        )
        .map_err(|error| DeserializationError::InvalidValue(error.to_string()))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::BlockAccountUpdate;
    use crate::Word;
    use crate::account::{AccountId, AccountPatch, AccountUpdateDetails};
    use crate::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE;

    #[test]
    fn accepts_partial_public_account_patch() -> anyhow::Result<()> {
        let account_id = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE)?;

        BlockAccountUpdate::new(
            account_id,
            Word::empty(),
            AccountUpdateDetails::Public(AccountPatch::empty(account_id)),
        )?;

        Ok(())
    }
}
