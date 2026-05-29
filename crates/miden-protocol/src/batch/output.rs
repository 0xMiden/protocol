use crate::Word;
use crate::block::BlockNumber;

// BATCH OUTPUT
// ================================================================================================

/// The public outputs produced by the batch kernel.
///
/// This is the parsed, typed form of the kernel's output stack (see
/// [`BatchKernel::parse_output_stack`](crate::batch::BatchKernel::parse_output_stack)), mirroring
/// [`TransactionOutputs`](crate::transaction::TransactionOutputs) for transactions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchOutput {
    /// The commitment to the batch's input notes.
    input_notes_commitment: Word,
    /// The commitment to the batch's output notes.
    output_notes_commitment: Word,
    /// The block number at which the batch expires.
    batch_expiration_block_num: BlockNumber,
}

impl BatchOutput {
    // OUTPUT STACK LAYOUT
    // --------------------------------------------------------------------------------------------

    /// The element index at which the input notes commitment word starts on the output stack.
    pub const INPUT_NOTES_COMMITMENT_WORD_IDX: usize = 0;
    /// The element index at which the output notes commitment word starts on the output stack.
    pub const OUTPUT_NOTES_COMMITMENT_WORD_IDX: usize = 4;
    /// The element index at which the batch expiration block number is stored on the output stack.
    pub const BATCH_EXPIRATION_BLOCK_NUM_ELEMENT_IDX: usize = 8;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns a new [`BatchOutput`] instantiated from the provided data.
    pub fn new(
        input_notes_commitment: Word,
        output_notes_commitment: Word,
        batch_expiration_block_num: BlockNumber,
    ) -> Self {
        Self {
            input_notes_commitment,
            output_notes_commitment,
            batch_expiration_block_num,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the commitment to the batch's input notes.
    pub fn input_notes_commitment(&self) -> Word {
        self.input_notes_commitment
    }

    /// Returns the commitment to the batch's output notes.
    pub fn output_notes_commitment(&self) -> Word {
        self.output_notes_commitment
    }

    /// Returns the block number at which the batch expires.
    pub fn batch_expiration_block_num(&self) -> BlockNumber {
        self.batch_expiration_block_num
    }
}
