use core::fmt::{Debug, Display};

use miden_crypto_derive::WordWrapper;

use super::{ExecutedTransaction, Felt, Hasher, ProvenTransaction, WORD_SIZE, Word, ZERO};
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

// TRANSACTION COMMITMENTS
// ================================================================================================

/// The four commitments that make up the preimage of the corresponding [`TransactionId`].
#[derive(Clone, Copy)]
pub struct TransactionCommitments {
    init_account_commitment: Word,
    final_account_commitment: Word,
    input_notes_commitment: Word,
    output_notes_commitment: Word,
}

impl TransactionCommitments {
    /// Length of the felt sequence returned by [`Self::elements`].
    pub const ELEMENTS_LEN: usize = 4 * WORD_SIZE;

    /// Returns a new [`TransactionCommitments`] from the four commitment words.
    pub fn new(
        init_account_commitment: Word,
        final_account_commitment: Word,
        input_notes_commitment: Word,
        output_notes_commitment: Word,
    ) -> Self {
        Self {
            init_account_commitment,
            final_account_commitment,
            input_notes_commitment,
            output_notes_commitment,
        }
    }

    /// Returns the transaction commitments as a felt sequence.
    ///
    /// The layout is:
    ///   `[INIT[4], FINAL[4], INPUT_NOTES_COMMITMENT[4], OUTPUT_NOTES_COMMITMENT[4]]`
    ///
    /// The batch kernel pipes this same felt sequence from the advice provider to memory and
    /// asserts the resulting hash matches a previously-verified `tx_id`.
    pub fn elements(&self) -> [Felt; Self::ELEMENTS_LEN] {
        let mut elements = [ZERO; Self::ELEMENTS_LEN];
        elements[..4].copy_from_slice(self.init_account_commitment.as_elements());
        elements[4..8].copy_from_slice(self.final_account_commitment.as_elements());
        elements[8..12].copy_from_slice(self.input_notes_commitment.as_elements());
        elements[12..16].copy_from_slice(self.output_notes_commitment.as_elements());
        elements
    }

    /// Returns the initial account commitment.
    pub fn init_account_commitment(&self) -> Word {
        self.init_account_commitment
    }

    /// Returns the final account commitment.
    pub fn final_account_commitment(&self) -> Word {
        self.final_account_commitment
    }

    /// Returns the input notes commitment.
    pub fn input_notes_commitment(&self) -> Word {
        self.input_notes_commitment
    }

    /// Returns the output notes commitment.
    pub fn output_notes_commitment(&self) -> Word {
        self.output_notes_commitment
    }
}

impl From<&ProvenTransaction> for TransactionCommitments {
    fn from(tx: &ProvenTransaction) -> Self {
        Self {
            init_account_commitment: tx.account_update().initial_state_commitment(),
            final_account_commitment: tx.account_update().final_state_commitment(),
            input_notes_commitment: tx.input_notes().commitment(),
            output_notes_commitment: tx.output_notes().commitment(),
        }
    }
}

impl From<&ExecutedTransaction> for TransactionCommitments {
    fn from(tx: &ExecutedTransaction) -> Self {
        Self {
            init_account_commitment: tx.initial_account().initial_commitment(),
            final_account_commitment: tx.final_account().to_commitment(),
            input_notes_commitment: tx.input_notes().commitment(),
            output_notes_commitment: tx.output_notes().commitment(),
        }
    }
}

// TRANSACTION ID
// ================================================================================================

/// A unique identifier of a transaction.
///
/// Transaction ID is computed as:
///
/// hash(
///     INIT_ACCOUNT_COMMITMENT,
///     FINAL_ACCOUNT_COMMITMENT,
///     INPUT_NOTES_COMMITMENT,
///     OUTPUT_NOTES_COMMITMENT,
/// )
///
/// This achieves the following properties:
/// - Transactions are identical if and only if they have the same ID.
/// - Computing transaction ID can be done solely from public transaction data.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, WordWrapper)]
pub struct TransactionId(Word);

impl TransactionId {
    /// Returns a new [TransactionId] from the given [`TransactionCommitments`].
    pub fn new(commitments: TransactionCommitments) -> Self {
        Self(Hasher::hash_elements(&commitments.elements()))
    }
}

impl Debug for TransactionId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Display for TransactionId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

// CONVERSIONS INTO TRANSACTION ID
// ================================================================================================

impl From<&ProvenTransaction> for TransactionId {
    fn from(tx: &ProvenTransaction) -> Self {
        Self::new(TransactionCommitments::from(tx))
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for TransactionId {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.0.to_bytes());
    }
}

impl Deserializable for TransactionId {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let id = Word::read_from(source)?;
        Ok(Self(id))
    }
}
