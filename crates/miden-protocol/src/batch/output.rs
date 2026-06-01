use crate::Word;
use crate::block::BlockNumber;

// BATCH OUTPUTS
// ================================================================================================

/// The public outputs produced by the batch kernel.
///
/// This is the parsed, typed form of the kernel's output stack (see
/// [`BatchKernel::parse_output_stack`](crate::batch::BatchKernel::parse_output_stack)), mirroring
/// [`TransactionOutputs`](crate::transaction::TransactionOutputs) for transactions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchOutputs {
    /// The commitment to the batch's input notes.
    input_notes_commitment: Word,
    /// The root of the batch's note tree (the [`BatchNoteTree`](crate::batch::BatchNoteTree)) over
    /// the batch's output notes.
    batch_note_tree_root: Word,
    /// The block number at which the batch expires.
    batch_expiration_block_num: BlockNumber,
}

impl BatchOutputs {
    // OUTPUT STACK LAYOUT
    // --------------------------------------------------------------------------------------------

    /// The element index at which the input notes commitment word starts on the output stack.
    pub const INPUT_NOTES_COMMITMENT_WORD_IDX: usize = 0;
    /// The element index at which the batch note tree root word starts on the output stack.
    pub const BATCH_NOTE_TREE_ROOT_WORD_IDX: usize = 4;
    /// The element index at which the batch expiration block number is stored on the output stack.
    pub const BATCH_EXPIRATION_BLOCK_NUM_ELEMENT_IDX: usize = 8;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns a new [`BatchOutputs`] instantiated from the provided data.
    pub fn new(
        input_notes_commitment: Word,
        batch_note_tree_root: Word,
        batch_expiration_block_num: BlockNumber,
    ) -> Self {
        Self {
            input_notes_commitment,
            batch_note_tree_root,
            batch_expiration_block_num,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the commitment to the batch's input notes.
    pub fn input_notes_commitment(&self) -> Word {
        self.input_notes_commitment
    }

    /// Returns the root of the batch's note tree.
    pub fn batch_note_tree_root(&self) -> Word {
        self.batch_note_tree_root
    }

    /// Returns the block number at which the batch expires.
    pub fn batch_expiration_block_num(&self) -> BlockNumber {
        self.batch_expiration_block_num
    }
}
