use alloc::vec::Vec;

use crate::errors::BlockOutputError;
use crate::vm::StackOutputs;
use crate::{Felt, Word};

// BLOCK OUTPUTS
// ================================================================================================

/// The public outputs produced by the block kernel.
///
/// This is the parsed, typed form of the kernel's output stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockOutputs {
    /// The commitment of the block header created by the block kernel.
    block_commitment: Word,
    /// The commitment to the set of nullifiers created in the block.
    nullifier_commitment: Word,
}

impl BlockOutputs {
    // OUTPUT STACK LAYOUT
    // --------------------------------------------------------------------------------------------

    /// The element index at which the block commitment word starts on the output stack.
    pub const BLOCK_COMMITMENT_WORD_IDX: usize = 0;
    /// The element index at which the nullifier commitment word starts on the output stack.
    pub const NULLIFIER_COMMITMENT_WORD_IDX: usize = 4;

    /// The number of elements the block kernel's outputs occupy on the stack.
    const NUM_OUTPUT_ELEMENTS: usize = 8;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns a new [`BlockOutputs`] instantiated from the provided data.
    pub fn new(block_commitment: Word, nullifier_commitment: Word) -> Self {
        Self { block_commitment, nullifier_commitment }
    }

    // PARSER
    // --------------------------------------------------------------------------------------------

    /// Parses the block kernel's output stack into a [`BlockOutputs`].
    ///
    /// # Errors
    ///
    /// Returns [`BlockOutputError::PaddingNotZero`] if the cells following the nullifier
    /// commitment (positions 8..16) are not all zero.
    pub fn parse(stack: &StackOutputs) -> Result<Self, BlockOutputError> {
        let block_commitment = stack
            .get_word(Self::BLOCK_COMMITMENT_WORD_IDX)
            .expect("block commitment word should be within the output stack");

        let nullifier_commitment = stack
            .get_word(Self::NULLIFIER_COMMITMENT_WORD_IDX)
            .expect("nullifier commitment word should be within the output stack");

        // Every cell after the nullifier commitment must be zero padding.
        if let Some(index) = stack[Self::NUM_OUTPUT_ELEMENTS..]
            .iter()
            .position(|&felt| felt != Felt::ZERO)
            .map(|offset| offset + Self::NUM_OUTPUT_ELEMENTS)
        {
            return Err(BlockOutputError::PaddingNotZero { index });
        }

        Ok(Self::new(block_commitment, nullifier_commitment))
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the commitment of the block header created by the block kernel.
    pub fn block_commitment(&self) -> Word {
        self.block_commitment
    }

    /// Returns the commitment to the set of nullifiers created in the block.
    pub fn nullifier_commitment(&self) -> Word {
        self.nullifier_commitment
    }

    // CONVERSIONS
    // --------------------------------------------------------------------------------------------

    /// Encodes these [`BlockOutputs`] into the block kernel's output stack.
    ///
    /// This is the inverse of [`BlockOutputs::parse`]; the resulting stack is laid out as:
    ///
    /// ```text
    /// [BLOCK_COMMITMENT, NULLIFIER_COMMITMENT]
    /// ```
    pub fn into_stack_outputs(self) -> StackOutputs {
        let mut outputs: Vec<Felt> = Vec::with_capacity(Self::NUM_OUTPUT_ELEMENTS);
        outputs.extend_from_slice(self.block_commitment.as_elements());
        outputs.extend_from_slice(self.nullifier_commitment.as_elements());

        StackOutputs::new(&outputs).expect("number of stack outputs should be <= 16")
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;

    #[test]
    fn parse_returns_outputs_for_well_formed_stack() {
        let block_commitment =
            Word::from([Felt::from(1u32), Felt::from(2u32), Felt::from(3u32), Felt::from(4u32)]);
        let nullifier_commitment =
            Word::from([Felt::from(5u32), Felt::from(6u32), Felt::from(7u32), Felt::from(8u32)]);
        let stack = BlockOutputs::new(block_commitment, nullifier_commitment).into_stack_outputs();

        let outputs = BlockOutputs::parse(&stack).unwrap();

        assert_eq!(outputs.block_commitment(), block_commitment);
        assert_eq!(outputs.nullifier_commitment(), nullifier_commitment);
    }

    #[test]
    fn parse_reports_the_index_of_the_first_non_zero_padding_cell() {
        // Leave the first padding cell zero so the reported index is not simply the first one.
        let mut elements = [Felt::ZERO; 12];
        elements[11] = Felt::from(1u32);
        let stack = StackOutputs::new(&elements).unwrap();

        assert_matches!(
            BlockOutputs::parse(&stack),
            Err(BlockOutputError::PaddingNotZero { index: 11 })
        );
    }
}
