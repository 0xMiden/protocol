use crate::Word;
use crate::account::AccountId;
use crate::account::delta::AccountUpdateDetails;
use crate::utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

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
    /// Returns a new [BlockAccountUpdate] instantiated from the specified components.
    pub const fn new(
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
        Ok(Self {
            account_id: AccountId::read_from(source)?,
            final_state_commitment: Word::read_from(source)?,
            details: AccountUpdateDetails::read_from(source)?,
        })
    }
}
