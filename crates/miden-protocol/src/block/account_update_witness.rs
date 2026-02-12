use crate::Word;
use crate::account::delta::AccountUpdateDetails;
use crate::block::account_tree::AccountWitness;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

/// This type encapsulates essentially three components:
/// - The initial and final state commitment of the account update.
/// - The witness is an smt proof of the initial state commitment of the account before the block in
///   which the witness is included, that is, in the account tree at the state of the previous block
///   header.
/// - The account update details represent the delta between the state of the account before the
///   block and the state after this block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountUpdateWitness {
    /// The state commitment before the update.
    initial_state_commitment: Word,
    /// The state commitment after the update.
    final_state_commitment: Word,
    /// The account witness proving that the initial state commitment is the current state in the
    /// account tree.
    initial_state_proof: AccountWitness,
    /// A set of changes which can be applied to the previous account state (i.e., the state as of
    /// the last block, equivalent to `initial_state_commitment`) to get the new account state. For
    /// private accounts, this is set to [`AccountUpdateDetails::Private`].
    details: AccountUpdateDetails,
}

impl AccountUpdateWitness {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Constructs a new, partial [`AccountUpdateWitness`] from the provided parts.
    pub fn new(
        initial_state_commitment: Word,
        final_state_commitment: Word,
        initial_state_proof: AccountWitness,
        details: AccountUpdateDetails,
    ) -> Self {
        Self {
            initial_state_commitment,
            final_state_commitment,
            initial_state_proof,
            details,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the initial state commitment of the account.
    pub fn initial_state_commitment(&self) -> Word {
        self.initial_state_commitment
    }

    /// Returns the final state commitment of the account.
    pub fn final_state_commitment(&self) -> Word {
        self.final_state_commitment
    }

    /// Returns a reference to the initial state proof of the account.
    pub fn as_witness(&self) -> &AccountWitness {
        &self.initial_state_proof
    }

    /// Returns the [`AccountWitness`] of this update witness.
    pub fn to_witness(&self) -> AccountWitness {
        self.initial_state_proof.clone()
    }

    /// Returns a reference to the underlying [`AccountUpdateDetails`] of this update, representing
    /// the state transition of the account from the previous block to the block this witness is
    /// for.
    pub fn details(&self) -> &AccountUpdateDetails {
        &self.details
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Returns a mutable reference to the initial state proof of the account.
    pub fn initial_state_proof_mut(&mut self) -> &mut AccountWitness {
        &mut self.initial_state_proof
    }

    /// Consumes self and returns its parts.
    pub fn into_parts(self) -> (Word, Word, AccountWitness, AccountUpdateDetails) {
        (
            self.initial_state_commitment,
            self.final_state_commitment,
            self.initial_state_proof,
            self.details,
        )
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for AccountUpdateWitness {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(self.initial_state_commitment);
        target.write(self.final_state_commitment);
        target.write(&self.initial_state_proof);
        target.write(&self.details);
    }
}

impl Deserializable for AccountUpdateWitness {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let initial_state_commitment = source.read()?;
        let final_state_commitment = source.read()?;
        let initial_state_proof = source.read()?;
        let details = source.read()?;

        Ok(AccountUpdateWitness {
            initial_state_commitment,
            final_state_commitment,
            initial_state_proof,
            details,
        })
    }
}
