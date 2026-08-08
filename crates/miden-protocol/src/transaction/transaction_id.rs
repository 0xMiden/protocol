use core::fmt::{Debug, Display};
use core::str::FromStr;

use miden_crypto_derive::WordWrapper;

use super::{Hasher, ProvenTransaction, WORD_SIZE, Word, ZERO};
use crate::WordError;
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
    ) -> Self {
        let mut elements = [ZERO; 4 * WORD_SIZE];
        elements[..4].copy_from_slice(init_account_commitment.as_elements());
        elements[4..8].copy_from_slice(final_account_commitment.as_elements());
        elements[8..12].copy_from_slice(input_notes_commitment.as_elements());
        elements[12..16].copy_from_slice(output_notes_commitment.as_elements());
        Self(Hasher::hash_elements(&elements))
    }

    /// Attempts to convert from a hexadecimal string to a [TransactionId].
    ///
    /// Callers must ensure the provided value is an actual [`TransactionId`].
    pub fn from_hex(hex_value: &str) -> Result<Self, WordError> {
        Word::try_from(hex_value).map(Self::from_raw)
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

impl FromStr for TransactionId {
    type Err = WordError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_id_from_hex_round_trip() {
        let id = TransactionId::new(Word::empty(), Word::empty(), Word::empty(), Word::empty());
        let hex = id.to_hex();

        assert_eq!(TransactionId::from_hex(&hex).unwrap(), id);
        assert_eq!(hex.parse::<TransactionId>().unwrap(), id);
    }

    #[test]
    fn transaction_id_from_hex_rejects_invalid_value() {
        assert!("not-a-transaction-id".parse::<TransactionId>().is_err());
    }
}
