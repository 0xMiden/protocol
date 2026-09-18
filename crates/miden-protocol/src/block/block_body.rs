use alloc::collections::BTreeSet;
use alloc::string::ToString;
use alloc::vec::Vec;

use miden_core::Word;

use crate::block::{
    BlockAccountUpdate,
    BlockNoteIndex,
    BlockNoteTree,
    OutputNoteBatch,
    ProposedBlock,
};
use crate::errors::BlockBodyError;
use crate::note::Nullifier;
use crate::transaction::{OrderedTransactionHeaders, OutputNote};
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{
    MAX_ACCOUNTS_PER_BLOCK,
    MAX_BATCHES_PER_BLOCK,
    MAX_INPUT_NOTES_PER_BLOCK,
    MAX_OUTPUT_NOTES_PER_BATCH,
};

// BLOCK BODY
// ================================================================================================

/// Body of a block in the chain which contains data pertaining to all relevant state changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockBody {
    /// Account updates for the block.
    updated_accounts: Vec<BlockAccountUpdate>,

    /// Note batches created by the transactions in this block.
    output_note_batches: Vec<OutputNoteBatch>,

    /// Nullifiers created by the transactions in this block through the consumption of notes.
    created_nullifiers: Vec<Nullifier>,

    /// The aggregated and flattened transaction headers of all batches in the order in which they
    /// appeared in the proposed block.
    transactions: OrderedTransactionHeaders,
}

impl BlockBody {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`BlockBody`] and validates its local structural constraints.
    ///
    /// This constructor does not verify that the created nullifiers and output notes correspond to
    /// the ordered transaction headers. It also does not authenticate input notes, verify note
    /// inclusion proofs, or verify that the account updates represent the transactions' state
    /// transitions. Those checks must be performed while constructing the proposed block or by a
    /// block verifier.
    ///
    /// # Errors
    ///
    /// Returns an error if a size, index, or uniqueness constraint is violated.
    pub fn new(
        updated_accounts: Vec<BlockAccountUpdate>,
        output_note_batches: Vec<OutputNoteBatch>,
        created_nullifiers: Vec<Nullifier>,
        transactions: OrderedTransactionHeaders,
    ) -> Result<Self, BlockBodyError> {
        if output_note_batches.len() > MAX_BATCHES_PER_BLOCK {
            return Err(BlockBodyError::TooManyOutputNoteBatches(output_note_batches.len()));
        }
        if updated_accounts.len() > MAX_ACCOUNTS_PER_BLOCK {
            return Err(BlockBodyError::TooManyAccountUpdates(updated_accounts.len()));
        }
        if created_nullifiers.len() > MAX_INPUT_NOTES_PER_BLOCK {
            return Err(BlockBodyError::TooManyNullifiers(created_nullifiers.len()));
        }

        let mut account_ids = BTreeSet::new();
        for update in &updated_accounts {
            if !account_ids.insert(update.account_id()) {
                return Err(BlockBodyError::DuplicateAccountUpdate(update.account_id()));
            }
        }

        let mut output_note_ids = BTreeSet::new();
        for (batch_index, batch) in output_note_batches.iter().enumerate() {
            if batch.len() > MAX_OUTPUT_NOTES_PER_BATCH {
                return Err(BlockBodyError::TooManyOutputNotes {
                    batch_index,
                    note_count: batch.len(),
                });
            }
            let mut note_indices = BTreeSet::new();
            for (note_index, note) in batch {
                if BlockNoteIndex::new(batch_index, *note_index).is_none() {
                    return Err(BlockBodyError::InvalidOutputNoteIndex {
                        batch_index,
                        note_index: *note_index,
                    });
                }
                if !note_indices.insert(*note_index) {
                    return Err(BlockBodyError::DuplicateOutputNoteIndex {
                        batch_index,
                        note_index: *note_index,
                    });
                }
                if !output_note_ids.insert(note.id()) {
                    return Err(BlockBodyError::DuplicateOutputNote(note.id()));
                }
            }
        }

        let mut nullifiers = BTreeSet::new();
        for nullifier in &created_nullifiers {
            if !nullifiers.insert(*nullifier) {
                return Err(BlockBodyError::DuplicateNullifier(*nullifier));
            }
        }

        let mut transaction_ids = BTreeSet::new();
        for transaction in transactions.as_slice() {
            if !transaction_ids.insert(transaction.id()) {
                return Err(BlockBodyError::DuplicateTransaction(transaction.id()));
            }
        }

        Ok(Self::new_unchecked(
            updated_accounts,
            output_note_batches,
            created_nullifiers,
            transactions,
        ))
    }

    /// Creates a new [`BlockBody`] without performing any validation.
    ///
    /// # Warning
    ///
    /// Callers must ensure that the block body satisfies all invariants checked by
    /// [`BlockBody::new`].
    pub fn new_unchecked(
        updated_accounts: Vec<BlockAccountUpdate>,
        output_note_batches: Vec<OutputNoteBatch>,
        created_nullifiers: Vec<Nullifier>,
        transactions: OrderedTransactionHeaders,
    ) -> Self {
        Self {
            updated_accounts,
            output_note_batches,
            created_nullifiers,
            transactions,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the slice of [`BlockAccountUpdate`]s for all accounts updated in the block.
    pub fn updated_accounts(&self) -> &[BlockAccountUpdate] {
        &self.updated_accounts
    }

    /// Returns the slice of [`OutputNoteBatch`]es for all output notes created in the block.
    pub fn output_note_batches(&self) -> &[OutputNoteBatch] {
        &self.output_note_batches
    }

    /// Returns a reference to the slice of nullifiers for all notes consumed in the block.
    pub fn created_nullifiers(&self) -> &[Nullifier] {
        &self.created_nullifiers
    }

    /// Returns the [`OrderedTransactionHeaders`] of all transactions included in this block.
    pub fn transactions(&self) -> &OrderedTransactionHeaders {
        &self.transactions
    }

    /// Returns the commitment of all transactions included in this block.
    pub fn transaction_commitment(&self) -> Word {
        self.transactions.commitment()
    }

    /// Returns an iterator over all [`OutputNote`]s created in this block.
    ///
    /// Each note is accompanied by a corresponding index specifying where the note is located
    /// in the block's [`BlockNoteTree`].
    pub fn output_notes(&self) -> impl Iterator<Item = (BlockNoteIndex, &OutputNote)> {
        self.output_note_batches.iter().enumerate().flat_map(|(batch_idx, notes)| {
            notes.iter().map(move |(note_idx_in_batch, note)| {
                (
                    // SAFETY: The block body contains at most the max allowed number of
                    // batches and each batch is guaranteed to contain
                    // at most the max allowed number of output notes.
                    BlockNoteIndex::new(batch_idx, *note_idx_in_batch)
                        .expect("max batches in block and max notes in batches should be enforced"),
                    note,
                )
            })
        })
    }

    /// Computes the [`BlockNoteTree`] containing all [`OutputNote`]s created in this block.
    pub fn compute_block_note_tree(&self) -> BlockNoteTree {
        let entries = self.output_notes().map(|(note_index, note)| (note_index, note.into()));

        // SAFETY: We only construct block bodies that:
        // - do not contain duplicates
        // - contain at most the max allowed number of batches and each batch is guaranteed to
        //   contain at most the max allowed number of output notes.
        BlockNoteTree::with_entries(entries)
                .expect("the output notes of the block should not contain duplicates and contain at most the allowed maximum")
    }

    // DESTRUCTURING
    // --------------------------------------------------------------------------------------------

    /// Consumes the block body and returns its parts.
    pub fn into_parts(
        self,
    ) -> (
        Vec<BlockAccountUpdate>,
        Vec<OutputNoteBatch>,
        Vec<Nullifier>,
        OrderedTransactionHeaders,
    ) {
        (
            self.updated_accounts,
            self.output_note_batches,
            self.created_nullifiers,
            self.transactions,
        )
    }
}

impl From<ProposedBlock> for BlockBody {
    fn from(block: ProposedBlock) -> Self {
        // Split the proposed block into its constituent parts.
        let (batches, account_updated_witnesses, output_note_batches, created_nullifiers, ..) =
            block.into_parts();

        // Transform the account update witnesses into block account updates.
        let updated_accounts = account_updated_witnesses
            .into_iter()
            .map(|(account_id, update_witness)| {
                let (
                    _initial_state_commitment,
                    final_state_commitment,
                    // Note that compute_account_root took out this value so it should not be used.
                    _initial_state_proof,
                    details,
                ) = update_witness.into_parts();
                // The proposed block's account update witnesses were validated while the block
                // was assembled.
                BlockAccountUpdate::new_unchecked(account_id, final_state_commitment, details)
            })
            .collect();
        let created_nullifiers = created_nullifiers.keys().copied().collect::<Vec<_>>();
        // Aggregate the verified transactions of all batches.
        let transactions = batches.into_transactions();
        Self {
            updated_accounts,
            output_note_batches,
            created_nullifiers,
            transactions,
        }
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for BlockBody {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.updated_accounts.write_into(target);
        self.output_note_batches.write_into(target);
        self.created_nullifiers.write_into(target);
        self.transactions.write_into(target);
    }
}

impl Deserializable for BlockBody {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Self::new(
            Vec::read_from(source)?,
            Vec::read_from(source)?,
            Vec::read_from(source)?,
            OrderedTransactionHeaders::read_from(source)?,
        )
        .map_err(|error| DeserializationError::InvalidValue(error.to_string()))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use assert_matches::assert_matches;
    use rstest::rstest;

    use super::BlockBody;
    use crate::Word;
    use crate::account::AccountId;
    use crate::errors::{BlockBodyError, TransactionHeaderError};
    use crate::note::{Note, NoteHeader};
    use crate::testing::account_id::ACCOUNT_ID_PRIVATE_SENDER;
    use crate::transaction::{
        InputNoteCommitment,
        InputNotes,
        OrderedTransactionHeaders,
        OutputNote,
        RawOutputNote,
        TransactionHeader,
    };
    use crate::utils::serde::{Deserializable, Serializable};

    fn account_id() -> AccountId {
        AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER).unwrap()
    }

    fn transaction_header(
        initial_state_commitment: Word,
        final_state_commitment: Word,
        input_notes: InputNotes<InputNoteCommitment>,
        output_notes: Vec<NoteHeader>,
    ) -> Result<TransactionHeader, TransactionHeaderError> {
        TransactionHeader::new(
            account_id(),
            initial_state_commitment,
            final_state_commitment,
            input_notes,
            output_notes,
        )
    }

    fn into_output_note(note: Note) -> OutputNote {
        RawOutputNote::Full(note).into_output_note().unwrap()
    }

    #[rstest]
    #[case::missing_from_body(true)]
    #[case::unexpected_in_body(false)]
    fn accepts_created_nullifiers_mismatch(#[case] transaction_has_input: bool) {
        let note = Note::mock_noop(Word::from([1_u32, 2, 3, 4]));
        let input =
            InputNoteCommitment::from_parts_unchecked(note.nullifier(), Some(*note.header()));
        let input_notes = if transaction_has_input {
            InputNotes::new(vec![input]).unwrap()
        } else {
            InputNotes::default()
        };
        let created_nullifiers = if transaction_has_input {
            vec![]
        } else {
            vec![note.nullifier()]
        };
        let transactions = OrderedTransactionHeaders::new_unchecked(vec![
            transaction_header(
                Word::from([1_u32, 2, 3, 4]),
                Word::from([5_u32, 6, 7, 8]),
                input_notes,
                vec![],
            )
            .unwrap(),
        ]);

        BlockBody::new(vec![], vec![], created_nullifiers, transactions).unwrap();
    }

    #[rstest]
    #[case::missing_from_body(true)]
    #[case::unexpected_in_body(false)]
    fn accepts_output_notes_mismatch(#[case] transaction_has_output: bool) {
        let note = Note::mock_noop(Word::from([1_u32, 2, 3, 4]));
        let output_notes = if transaction_has_output {
            vec![]
        } else {
            vec![vec![(0, into_output_note(note.clone()))]]
        };
        let transaction_output_notes = if transaction_has_output {
            vec![*note.header()]
        } else {
            vec![]
        };
        let transactions = OrderedTransactionHeaders::new_unchecked(vec![
            transaction_header(
                Word::from([1_u32, 2, 3, 4]),
                Word::from([5_u32, 6, 7, 8]),
                InputNotes::default(),
                transaction_output_notes,
            )
            .unwrap(),
        ]);

        BlockBody::new(vec![], output_notes, vec![], transactions).unwrap();
    }

    #[test]
    fn accepts_matching_transaction_notes() {
        let input_note = Note::mock_noop(Word::from([1_u32, 2, 3, 4]));
        let output_note = Note::mock_noop(Word::from([5_u32, 6, 7, 8]));
        let input = InputNoteCommitment::from_parts_unchecked(
            input_note.nullifier(),
            Some(*input_note.header()),
        );
        let transactions = OrderedTransactionHeaders::new_unchecked(vec![
            transaction_header(
                Word::from([1_u32, 2, 3, 4]),
                Word::from([5_u32, 6, 7, 8]),
                InputNotes::new(vec![input]).unwrap(),
                vec![*output_note.header()],
            )
            .unwrap(),
        ]);

        BlockBody::new(
            vec![],
            vec![vec![(0, into_output_note(output_note))]],
            vec![input_note.nullifier()],
            transactions,
        )
        .unwrap();
    }

    #[test]
    fn rejects_duplicate_supplied_nullifier() {
        let note = Note::mock_noop(Word::from([1_u32, 2, 3, 4]));
        let nullifier = note.nullifier();
        let transactions = OrderedTransactionHeaders::new_unchecked(vec![]);

        let result = BlockBody::new(vec![], vec![], vec![nullifier, nullifier], transactions);

        assert_matches!(
            result,
            Err(BlockBodyError::DuplicateNullifier(nullifier)) if nullifier == note.nullifier()
        );
    }

    #[test]
    fn rejects_duplicate_supplied_output_note() {
        let note = Note::mock_noop(Word::from([1_u32, 2, 3, 4]));
        let output_note = into_output_note(note.clone());
        let transactions = OrderedTransactionHeaders::new_unchecked(vec![]);

        let result = BlockBody::new(
            vec![],
            vec![vec![(0, output_note.clone()), (1, output_note)]],
            vec![],
            transactions,
        );

        assert_matches!(
            result,
            Err(BlockBodyError::DuplicateOutputNote(note_id)) if note_id == note.id()
        );
    }

    #[test]
    fn accepts_note_consumed_before_created_in_transaction_headers() {
        let note = Note::mock_noop(Word::from([1_u32, 2, 3, 4]));
        let input =
            InputNoteCommitment::from_parts_unchecked(note.nullifier(), Some(*note.header()));
        let transactions = OrderedTransactionHeaders::new_unchecked(vec![
            transaction_header(
                Word::from([1_u32, 2, 3, 4]),
                Word::from([5_u32, 6, 7, 8]),
                InputNotes::new(vec![input]).unwrap(),
                vec![],
            )
            .unwrap(),
            transaction_header(
                Word::from([5_u32, 6, 7, 8]),
                Word::from([9_u32, 10, 11, 12]),
                InputNotes::default(),
                vec![*note.header()],
            )
            .unwrap(),
        ]);

        BlockBody::new(
            vec![],
            vec![vec![(0, into_output_note(note.clone()))]],
            vec![note.nullifier()],
            transactions,
        )
        .unwrap();
    }

    #[test]
    fn deserialization_accepts_output_notes_mismatch() {
        let note = Note::mock_noop(Word::from([1_u32, 2, 3, 4]));
        let transactions = OrderedTransactionHeaders::new_unchecked(vec![
            transaction_header(
                Word::from([1_u32, 2, 3, 4]),
                Word::from([5_u32, 6, 7, 8]),
                InputNotes::default(),
                vec![*note.header()],
            )
            .unwrap(),
        ]);
        let invalid_body = BlockBody::new_unchecked(vec![], vec![], vec![], transactions);

        BlockBody::read_from_bytes(&invalid_body.to_bytes()).unwrap();
    }

    #[test]
    fn deserialization_accepts_created_nullifiers_mismatch() {
        let note = Note::mock_noop(Word::from([1_u32, 2, 3, 4]));
        let input =
            InputNoteCommitment::from_parts_unchecked(note.nullifier(), Some(*note.header()));
        let transactions = OrderedTransactionHeaders::new_unchecked(vec![
            transaction_header(
                Word::from([1_u32, 2, 3, 4]),
                Word::from([5_u32, 6, 7, 8]),
                InputNotes::new(vec![input]).unwrap(),
                vec![],
            )
            .unwrap(),
        ]);
        let invalid_body = BlockBody::new_unchecked(vec![], vec![], vec![], transactions);

        BlockBody::read_from_bytes(&invalid_body.to_bytes()).unwrap();
    }
}
