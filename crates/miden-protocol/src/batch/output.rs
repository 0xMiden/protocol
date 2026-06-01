use crate::block::BlockNumber;
use crate::errors::BatchOutputError;
use crate::vm::StackOutputs;
use crate::{Felt, Word};

// BATCH OUTPUTS
// ================================================================================================

/// The public outputs produced by the batch kernel.
///
/// This is the parsed, typed form of the kernel's output stack (see [`BatchOutputs::parse`]),
/// mirroring [`TransactionOutputs`](crate::transaction::TransactionOutputs) for transactions.
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

    // PARSER
    // --------------------------------------------------------------------------------------------

    /// Parses the batch kernel's output stack into a [`BatchOutputs`].
    ///
    /// # Errors
    ///
    /// Returns [`BatchOutputError::OutputStackInvalid`] if:
    /// - a required output word or element is missing from the stack;
    /// - the cells following `batch_expiration_block_num` (positions 9..16) are not all zero.
    ///
    /// Returns [`BatchOutputError::ExpirationBlockNumberTooLarge`] if `batch_expiration_block_num`
    /// does not fit into a `u32`.
    pub fn parse(stack: &StackOutputs) -> Result<Self, BatchOutputError> {
        let input_notes_commitment =
            stack.get_word(Self::INPUT_NOTES_COMMITMENT_WORD_IDX).ok_or_else(|| {
                BatchOutputError::OutputStackInvalid(
                    "input notes commitment word missing from output stack".into(),
                )
            })?;
        let batch_note_tree_root =
            stack.get_word(Self::BATCH_NOTE_TREE_ROOT_WORD_IDX).ok_or_else(|| {
                BatchOutputError::OutputStackInvalid(
                    "batch note tree root word missing from output stack".into(),
                )
            })?;

        let expiration_felt =
            stack.get_element(Self::BATCH_EXPIRATION_BLOCK_NUM_ELEMENT_IDX).ok_or_else(|| {
                BatchOutputError::OutputStackInvalid(
                    "batch expiration block number missing from output stack".into(),
                )
            })?;

        // Every cell after batch_expiration_block_num must be zero padding.
        if stack[Self::BATCH_EXPIRATION_BLOCK_NUM_ELEMENT_IDX + 1..]
            .iter()
            .any(|&felt| felt != Felt::ZERO)
        {
            return Err(BatchOutputError::OutputStackInvalid(
                "batch_expiration_block_num must be followed by zero padding".into(),
            ));
        }

        let batch_expiration_block_num = u32::try_from(expiration_felt.as_canonical_u64())
            .map_err(|_| BatchOutputError::ExpirationBlockNumberTooLarge(expiration_felt))?
            .into();

        Ok(Self::new(
            input_notes_commitment,
            batch_note_tree_root,
            batch_expiration_block_num,
        ))
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
