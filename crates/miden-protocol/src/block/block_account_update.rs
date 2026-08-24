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
    /// Callers must ensure that the update details are compatible with the account ID and that a
    /// full-state public account update matches the final state commitment.
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
    pub fn validate(&self) -> Result<(), BlockAccountUpdateError> {
        let Some(patch) = self.details.validate_for_account(self.account_id)? else {
            return Ok(());
        };

        if patch.is_full_state() {
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
    use assert_matches::assert_matches;

    use super::BlockAccountUpdate;
    use crate::Word;
    use crate::account::{Account, AccountPatch, AccountType, AccountUpdateDetails};
    use crate::errors::BlockAccountUpdateError;
    use crate::testing::add_component::AddComponent;
    use crate::testing::noop_auth_component::NoopAuthComponent;
    use crate::utils::serde::{Deserializable, DeserializationError, Serializable};

    fn public_account_and_full_patch() -> (Account, AccountPatch) {
        let account = Account::builder([9; 32])
            .account_type(AccountType::Public)
            .with_component(NoopAuthComponent)
            .with_component(AddComponent)
            .build_existing()
            .unwrap();
        let patch = AccountPatch::try_from(account.clone()).unwrap();
        assert!(patch.is_full_state());

        (account, patch)
    }

    #[test]
    fn accepts_full_state_patch_matching_final_commitment() {
        let (account, patch) = public_account_and_full_patch();

        BlockAccountUpdate::new(
            account.id(),
            account.to_commitment(),
            AccountUpdateDetails::Public(patch),
        )
        .unwrap();
    }

    #[test]
    fn rejects_full_state_patch_not_matching_final_commitment() {
        let (account, patch) = public_account_and_full_patch();
        let final_state_commitment = Word::empty();
        let account_commitment = account.to_commitment();
        assert_ne!(final_state_commitment, account_commitment);

        let error = BlockAccountUpdate::new(
            account.id(),
            final_state_commitment,
            AccountUpdateDetails::Public(patch),
        )
        .unwrap_err();

        assert_matches!(
            error,
            BlockAccountUpdateError::AccountFinalCommitmentMismatch {
                final_state_commitment: actual_final_state_commitment,
                account_commitment: actual_account_commitment,
            } if actual_final_state_commitment == final_state_commitment
                && actual_account_commitment == account_commitment
        );
    }

    #[test]
    fn deserialization_rejects_full_state_patch_not_matching_final_commitment() {
        let (account, patch) = public_account_and_full_patch();
        let final_state_commitment = Word::empty();
        let account_commitment = account.to_commitment();
        assert_ne!(final_state_commitment, account_commitment);
        let invalid_update = BlockAccountUpdate::new_unchecked(
            account.id(),
            final_state_commitment,
            AccountUpdateDetails::Public(patch),
        );

        let error = BlockAccountUpdate::read_from_bytes(&invalid_update.to_bytes()).unwrap_err();

        assert_matches!(
            error,
            DeserializationError::InvalidValue(message)
                if message == format!(
                    "block account update's final commitment {final_state_commitment} and reconstructed account commitment {account_commitment} must match"
                )
        );
    }

    #[test]
    fn accepts_partial_public_account_patch() {
        let (account, _) = public_account_and_full_patch();

        BlockAccountUpdate::new(
            account.id(),
            Word::empty(),
            AccountUpdateDetails::Public(AccountPatch::empty(account.id())),
        )
        .unwrap();
    }
}
