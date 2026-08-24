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

    /// Creates a new [`BlockBody`] and validates its structural constraints.
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
            update.validate().map_err(|source| BlockBodyError::InvalidAccountUpdate {
                account_id: update.account_id(),
                source,
            })?;
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
    /// This does not validate any of the guarantees of this type. It should only be used internally
    /// (in miden-lib) or in tests.
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
                BlockAccountUpdate::new(account_id, final_state_commitment, details)
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
