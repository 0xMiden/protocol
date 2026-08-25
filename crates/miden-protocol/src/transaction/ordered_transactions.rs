use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::account::AccountId;
use crate::note::{NoteHeader, NoteId, Nullifier};
use crate::transaction::{InputNoteCommitment, TransactionHeader, TransactionId};
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{Felt, Hasher, Word};

// ORDERED TRANSACTION HEADERS
// ================================================================================================

/// The ordered set of transaction headers in a [`ProvenBatch`](crate::batch::ProvenBatch) or
/// [`ProvenBlock`](crate::block::ProvenBlock).
///
/// This is a newtype wrapper representing either:
/// - the set of transactions in a **batch**,
/// - or the flattened sets of transactions of each proven batch in a **block**.
///
/// This type cannot be constructed directly, but can be retrieved through:
/// - [`ProposedBatch::transaction_headers`](crate::batch::ProposedBatch::transaction_headers),
/// - [`OrderedBatches::into_transactions`](crate::batch::OrderedBatches::into_transactions).
///
/// The rationale for this requirement is that it allows a client to cheaply validate the
/// correctness of the transactions in a proven block returned by a remote prover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderedTransactionHeaders(Vec<TransactionHeader>);

/// The external input and output notes derived from an ordered sequence of
/// [`TransactionHeader`]s.
pub(crate) struct AggregatedTransactionNotes {
    input_notes: BTreeMap<Nullifier, InputNoteCommitment>,
    output_notes: BTreeMap<NoteId, NoteHeader>,
}

impl AggregatedTransactionNotes {
    pub(crate) fn input_notes(&self) -> &BTreeMap<Nullifier, InputNoteCommitment> {
        &self.input_notes
    }

    pub(crate) fn output_notes(&self) -> &BTreeMap<NoteId, NoteHeader> {
        &self.output_notes
    }
}

/// An error found while aggregating notes from an ordered sequence of [`TransactionHeader`]s.
pub(crate) enum TransactionHeaderNoteAggregationError {
    DuplicateInputNote(Nullifier),
    DuplicateOutputNote(NoteId),
    NoteCreatedAndConsumed(NoteId),
}

impl OrderedTransactionHeaders {
    /// Creates a new set of ordered transaction headers from the provided vector.
    ///
    /// # Warning
    ///
    /// See the type-level documentation for the requirements of the passed transactions.
    pub fn new_unchecked(transactions: Vec<TransactionHeader>) -> Self {
        Self(transactions)
    }

    /// Computes a commitment to the list of transactions.
    ///
    /// This is a sequential hash over each transaction's ID and its account ID.
    pub fn commitment(&self) -> Word {
        Self::compute_commitment(self.0.as_slice().iter().map(|tx| (tx.id(), tx.account_id())))
    }

    /// Returns a reference to the underlying transaction headers.
    pub fn as_slice(&self) -> &[TransactionHeader] {
        &self.0
    }

    /// Consumes self and returns the underlying vector of transaction headers.
    pub fn into_vec(self) -> Vec<TransactionHeader> {
        self.0
    }

    /// Derives the external input and output notes after erasing notes created and consumed within
    /// this ordered sequence of [`TransactionHeader`]s.
    pub(crate) fn aggregate_notes(
        &self,
    ) -> Result<AggregatedTransactionNotes, TransactionHeaderNoteAggregationError> {
        let mut input_nullifiers = BTreeSet::new();
        let mut output_note_ids = BTreeSet::new();
        let mut input_notes = BTreeMap::<Nullifier, InputNoteCommitment>::new();
        let mut output_notes = BTreeMap::<NoteId, (TransactionId, NoteHeader)>::new();

        for transaction in &self.0 {
            for output_note in transaction.output_notes() {
                if !output_note_ids.insert(output_note.id()) {
                    return Err(TransactionHeaderNoteAggregationError::DuplicateOutputNote(
                        output_note.id(),
                    ));
                }
                output_notes.insert(output_note.id(), (transaction.id(), *output_note));
            }

            for input_note in transaction.input_notes() {
                if !input_nullifiers.insert(input_note.nullifier()) {
                    return Err(TransactionHeaderNoteAggregationError::DuplicateInputNote(
                        input_note.nullifier(),
                    ));
                }

                if let Some(input_header) = input_note.header()
                    && let Some((created_by, _)) = output_notes.remove(&input_header.id())
                {
                    if created_by == transaction.id() {
                        return Err(TransactionHeaderNoteAggregationError::NoteCreatedAndConsumed(
                            input_header.id(),
                        ));
                    }
                    continue;
                }

                input_notes.insert(input_note.nullifier(), input_note.clone());
            }
        }

        for input_note in input_notes.values().filter_map(InputNoteCommitment::header) {
            if output_notes.contains_key(&input_note.id()) {
                return Err(TransactionHeaderNoteAggregationError::NoteCreatedAndConsumed(
                    input_note.id(),
                ));
            }
        }

        Ok(AggregatedTransactionNotes {
            input_notes,
            output_notes: output_notes
                .into_iter()
                .map(|(note_id, (_, note_header))| (note_id, note_header))
                .collect(),
        })
    }

    // PUBLIC HELPERS
    // --------------------------------------------------------------------------------------------

    /// Computes a commitment to the provided list of transactions.
    ///
    /// Each transaction is represented by a transaction ID and an account ID which it was executed
    /// against. The commitment is a sequential hash over (TRANSACTION_ID, ACCOUNT_ID) tuples.
    pub(crate) fn compute_commitment(
        transactions: impl IntoIterator<Item = (TransactionId, AccountId)>,
    ) -> Word {
        let mut elements = vec![];
        for (transaction_id, account_id) in transactions {
            elements.extend_from_slice(transaction_id.as_elements());
            elements.extend_from_slice(&[
                account_id.suffix(),
                account_id.prefix().as_felt(),
                Felt::ZERO,
                Felt::ZERO,
            ]);
        }

        Hasher::hash_elements(&elements)
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for OrderedTransactionHeaders {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.0.write_into(target)
    }
}

impl Deserializable for OrderedTransactionHeaders {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        source.read().map(OrderedTransactionHeaders::new_unchecked)
    }
}
