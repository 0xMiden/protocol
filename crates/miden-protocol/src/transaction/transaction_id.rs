use alloc::string::String;
use core::fmt::{Debug, Display};

use miden_crypto_derive::WordWrapper;

use super::{Felt, Hasher, ProvenTransaction, WORD_SIZE, Word, ZERO};
use crate::asset::{Asset, FungibleAsset};
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

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
///     FEE_ASSET,
/// )
///
/// This achieves the following properties:
/// - Transactions are identical if and only if they have the same ID.
/// - Computing transaction ID can be done solely from public transaction data.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, WordWrapper)]
pub struct TransactionId(Word);

impl TransactionId {
    /// Returns a new [TransactionId] instantiated from the provided transaction components.
    pub fn new(
        init_account_commitment: Word,
        final_account_commitment: Word,
        input_notes_commitment: Word,
        output_notes_commitment: Word,
        fee_asset: FungibleAsset,
    ) -> Self {
        let mut elements = [ZERO; 6 * WORD_SIZE];
        elements[..4].copy_from_slice(init_account_commitment.as_elements());
        elements[4..8].copy_from_slice(final_account_commitment.as_elements());
        elements[8..12].copy_from_slice(input_notes_commitment.as_elements());
        elements[12..16].copy_from_slice(output_notes_commitment.as_elements());
        elements[16..].copy_from_slice(&Asset::from(fee_asset).as_elements());
        Self(Hasher::hash_elements(&elements))
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
        Self::new(
            tx.account_update().initial_state_commitment(),
            tx.account_update().final_state_commitment(),
            tx.input_notes().commitment(),
            tx.output_notes().commitment(),
            tx.fee(),
        )
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
