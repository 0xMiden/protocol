use alloc::vec::Vec;

use crate::block::BlockNumber;
use crate::errors::BatchOutputError;
use crate::vm::StackOutputs;
use crate::{Felt, Word};

// BATCH OUTPUTS
// ================================================================================================

/// The public outputs produced by the batch kernel.
///
/// This is the parsed, typed form of the kernel's output stack.
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

    // CONVERSIONS
    // --------------------------------------------------------------------------------------------

    /// Encodes these [`BatchOutputs`] into the batch kernel's output stack.
    ///
    /// This is the inverse of [`BatchOutputs::parse`]; the resulting stack is laid out as:
    ///
    /// ```text
    /// [INPUT_NOTES_COMMITMENT, BATCH_NOTE_TREE_ROOT, batch_expiration_block_num]
    /// ```
    pub fn into_stack_outputs(self) -> StackOutputs {
        let mut outputs: Vec<Felt> = Vec::with_capacity(9);
        outputs.extend_from_slice(self.input_notes_commitment.as_elements());
        outputs.extend_from_slice(self.batch_note_tree_root.as_elements());
        outputs.push(Felt::from(self.batch_expiration_block_num));

        StackOutputs::new(&outputs).expect("number of stack outputs should be <= 16")
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_returns_outputs_for_well_formed_stack() {
        let input_notes_commitment =
            Word::from([Felt::from(1u32), Felt::from(2u32), Felt::from(3u32), Felt::from(4u32)]);
        let batch_note_tree_root =
            Word::from([Felt::from(5u32), Felt::from(6u32), Felt::from(7u32), Felt::from(8u32)]);
        let elements = [
            Felt::from(1u32),
            Felt::from(2u32),
            Felt::from(3u32),
            Felt::from(4u32),
            Felt::from(5u32),
            Felt::from(6u32),
            Felt::from(7u32),
            Felt::from(8u32),
            Felt::from(1234u32),
        ];
        let stack = StackOutputs::new(&elements).unwrap();

        let outputs = BatchOutputs::parse(&stack).unwrap();

        assert_eq!(outputs.input_notes_commitment(), input_notes_commitment);
        assert_eq!(outputs.batch_note_tree_root(), batch_note_tree_root);
        assert_eq!(outputs.batch_expiration_block_num(), BlockNumber::from(1234u32));
    }

    #[test]
    fn parse_rejects_non_zero_padding() {
        // A valid 9-element output followed by a non-zero felt in the padding region (>= idx 9).
        let elements = [
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            Felt::from(7u32),
            Felt::from(1u32),
        ];
        let stack = StackOutputs::new(&elements).unwrap();

        assert!(matches!(
            BatchOutputs::parse(&stack),
            Err(BatchOutputError::OutputStackInvalid(_))
        ));
    }

    #[test]
    fn parse_rejects_oversized_expiration() {
        // An expiration value that does not fit into a u32.
        let oversized = Felt::from(u32::MAX) + Felt::from(1u32);
        let elements = [
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            oversized,
        ];
        let stack = StackOutputs::new(&elements).unwrap();

        assert!(matches!(
            BatchOutputs::parse(&stack),
            Err(BatchOutputError::ExpirationBlockNumberTooLarge(_))
        ));
    }
}
