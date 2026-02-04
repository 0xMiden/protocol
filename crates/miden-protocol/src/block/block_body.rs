use alloc::vec::Vec;

use miden_core::Word;
use miden_core::utils::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

use crate::block::{
    BlockAccountUpdate,
    BlockNoteIndex,
    BlockNoteTree,
    OutputNoteBatch,
    ProposedBlock,
};
use crate::note::Nullifier;
use crate::transaction::{OrderedTransactionHeaders, OutputNote};

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
        let entries = self
            .output_notes()
            .map(|(note_index, note)| (note_index, note.id(), note.metadata()));

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
        let block = Self {
            updated_accounts: Vec::read_from(source)?,
            output_note_batches: Vec::read_from(source)?,
            created_nullifiers: Vec::read_from(source)?,
            transactions: OrderedTransactionHeaders::read_from(source)?,
        };
        Ok(block)
    }
}
