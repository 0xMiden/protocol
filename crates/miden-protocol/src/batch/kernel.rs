use alloc::vec::Vec;

use miden_core::program::Kernel;

use crate::batch::{BatchOutput, ProposedBatch};
use crate::block::BlockNumber;
use crate::errors::BatchOutputError;
use crate::utils::serde::Deserializable;
use crate::utils::sync::LazyLock;
use crate::vm::{AdviceInputs, Program, ProgramInfo, StackInputs, StackOutputs};
use crate::{Felt, Word};

// CONSTANTS
// ================================================================================================

static KERNEL_MAIN: LazyLock<Program> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/assets/kernels/batch_kernel.masb"));
    Program::read_from_bytes(bytes).expect("failed to deserialize batch kernel runtime")
});

// BATCH KERNEL
// ================================================================================================

/// The batch kernel program: an executable Miden program that proves a batch of transactions.
///
/// The kernel takes `[BLOCK_COMMITMENT, BATCH_ID]` as public inputs and emits
/// `[INPUT_NOTES_COMMITMENT, BATCH_NOTE_TREE_ROOT, batch_expiration_block_num]`. See
/// `asm/kernels/batch/main.masm` for the input/output contract.
pub struct BatchKernel;

impl BatchKernel {
    // KERNEL SOURCE CODE
    // --------------------------------------------------------------------------------------------

    /// Returns the executable batch kernel program loaded from the build's `OUT_DIR`.
    pub fn main() -> Program {
        KERNEL_MAIN.clone()
    }

    /// Returns [`ProgramInfo`] for the batch kernel program.
    ///
    /// The batch kernel does not expose syscalls, so the associated [`Kernel`] is empty.
    pub fn program_info() -> ProgramInfo {
        ProgramInfo::new(Self::main().hash(), Kernel::default())
    }

    // INPUT BUILDERS
    // --------------------------------------------------------------------------------------------

    /// Transforms the provided [`ProposedBatch`] into the stack and advice inputs needed to
    /// execute the batch kernel.
    pub fn prepare_inputs(proposed_batch: &ProposedBatch) -> (StackInputs, AdviceInputs) {
        let block_commitment = proposed_batch.reference_block_header().commitment();
        let batch_id = proposed_batch.id().as_word();

        let stack_inputs = Self::build_input_stack(block_commitment, batch_id);
        let advice_inputs = Self::build_advice_inputs(proposed_batch);

        (stack_inputs, advice_inputs)
    }

    /// Returns the stack with the public inputs required by the batch kernel.
    ///
    /// The initial stack is:
    ///
    /// ```text
    /// [BLOCK_COMMITMENT, BATCH_ID, pad(8)]
    /// ```
    ///
    /// Where:
    /// - `BLOCK_COMMITMENT` is the commitment of the batch's reference block.
    /// - `BATCH_ID` is the batch's [`BatchId`](crate::batch::BatchId).
    pub fn build_input_stack(block_commitment: Word, batch_id: Word) -> StackInputs {
        let mut inputs: Vec<Felt> = Vec::with_capacity(8);
        inputs.extend_from_slice(block_commitment.as_elements());
        inputs.extend_from_slice(batch_id.as_elements());

        StackInputs::new(&inputs).expect("number of stack inputs should be <= 16")
    }

    /// Builds the stack with the expected batch kernel outputs.
    ///
    /// The output stack is defined as:
    ///
    /// ```text
    /// [INPUT_NOTES_COMMITMENT, BATCH_NOTE_TREE_ROOT, batch_expiration_block_num]
    /// ```
    pub fn build_output_stack(
        input_notes_commitment: Word,
        batch_note_tree_root: Word,
        batch_expiration_block_num: BlockNumber,
    ) -> StackOutputs {
        let mut outputs: Vec<Felt> = Vec::with_capacity(9);
        outputs.extend_from_slice(input_notes_commitment.as_elements());
        outputs.extend_from_slice(batch_note_tree_root.as_elements());
        outputs.push(Felt::from(batch_expiration_block_num));

        StackOutputs::new(&outputs).expect("number of stack outputs should be <= 16")
    }

    /// Extracts the [`BatchOutput`] from the provided stack outputs.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The padding cells (positions 9..16) are not all zero.
    /// - `batch_expiration_block_num` does not fit into a `u32`.
    pub fn parse_output_stack(stack: &StackOutputs) -> Result<BatchOutput, BatchOutputError> {
        let input_notes_commitment = stack
            .get_word(BatchOutput::INPUT_NOTES_COMMITMENT_WORD_IDX)
            .expect("input_notes_commitment word missing");
        let batch_note_tree_root = stack
            .get_word(BatchOutput::BATCH_NOTE_TREE_ROOT_WORD_IDX)
            .expect("batch_note_tree_root word missing");

        let expiration_felt = stack
            .get_element(BatchOutput::BATCH_EXPIRATION_BLOCK_NUM_ELEMENT_IDX)
            .expect("batch_expiration_block_num missing");

        // Every cell after batch_expiration_block_num must be zero padding.
        if stack[BatchOutput::BATCH_EXPIRATION_BLOCK_NUM_ELEMENT_IDX + 1..]
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

        Ok(BatchOutput::new(
            input_notes_commitment,
            batch_note_tree_root,
            batch_expiration_block_num,
        ))
    }

    // ADVICE BUILDER
    // --------------------------------------------------------------------------------------------

    /// Builds the advice inputs (map + stack) consumed by the batch kernel.
    ///
    /// The skeleton kernel ignores its advice inputs, so this returns the default empty value.
    fn build_advice_inputs(_proposed_batch: &ProposedBatch) -> AdviceInputs {
        AdviceInputs::default()
    }
}
