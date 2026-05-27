use alloc::vec::Vec;

use miden_core::program::Kernel;

use crate::batch::ProposedBatch;
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

// Output stack indices (layout at the end of `batch/main.masm::main`).
const INPUT_NOTES_COMMITMENT_WORD_IDX: usize = 0;
const OUTPUT_NOTES_COMMITMENT_WORD_IDX: usize = 4;
const BATCH_EXPIRATION_BLOCK_NUM_ELEMENT_IDX: usize = 8;
// The word containing `batch_expiration_block_num` plus three padding zeros.
const EXPIRATION_PAD_WORD_FELT_IDX: usize = 8;
const EXPIRATION_PAD_WORD_INNER_OFFSET: usize = 1;
// The trailing word at felt indices 12..16 must be all zero.
const TRAILING_PAD_WORD_FELT_IDX: usize = 12;

// BATCH KERNEL
// ================================================================================================

/// The batch kernel program: an executable Miden program that proves a batch of transactions.
///
/// The kernel takes `[TRANSACTIONS_COMMITMENT, BLOCK_HASH]` as public inputs and emits
/// `[INPUT_NOTES_COMMITMENT, OUTPUT_NOTES_COMMITMENT, batch_expiration_block_num]`. See
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
        let block_hash = proposed_batch.reference_block_header().commitment();
        let transactions_commitment = proposed_batch.id().as_word();

        let stack_inputs = Self::build_input_stack(transactions_commitment, block_hash);
        let advice_inputs = Self::build_advice_inputs(proposed_batch);

        (stack_inputs, advice_inputs)
    }

    /// Returns the stack with the public inputs required by the batch kernel.
    ///
    /// The initial stack is:
    ///
    /// ```text
    /// [TRANSACTIONS_COMMITMENT, BLOCK_HASH, pad(8)]
    /// ```
    ///
    /// Where:
    /// - `TRANSACTIONS_COMMITMENT` is the value [`BatchId`](crate::batch::BatchId) computes — a
    ///   sequential hash of `(transaction_id || account_id_prefix || account_id_suffix || 0 || 0)`
    ///   over all transactions in the batch.
    /// - `BLOCK_HASH` is the commitment of the batch's reference block.
    pub fn build_input_stack(transactions_commitment: Word, block_hash: Word) -> StackInputs {
        let mut inputs: Vec<Felt> = Vec::with_capacity(8);
        inputs.extend_from_slice(transactions_commitment.as_elements());
        inputs.extend_from_slice(block_hash.as_elements());

        StackInputs::new(&inputs).expect("number of stack inputs should be <= 16")
    }

    /// Builds the stack with the expected batch kernel outputs.
    ///
    /// The output stack is defined as:
    ///
    /// ```text
    /// [INPUT_NOTES_COMMITMENT, OUTPUT_NOTES_COMMITMENT, batch_expiration_block_num]
    /// ```
    pub fn build_output_stack(
        input_notes_commitment: Word,
        output_notes_commitment: Word,
        batch_expiration_block_num: BlockNumber,
    ) -> StackOutputs {
        let mut outputs: Vec<Felt> = Vec::with_capacity(9);
        outputs.extend_from_slice(input_notes_commitment.as_elements());
        outputs.extend_from_slice(output_notes_commitment.as_elements());
        outputs.push(Felt::from(batch_expiration_block_num));

        StackOutputs::new(&outputs).expect("number of stack outputs should be <= 16")
    }

    /// Extracts batch output data from the provided stack outputs.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The padding cells (positions 9..16) are not all zero.
    /// - `batch_expiration_block_num` does not fit into a `u32`.
    pub fn parse_output_stack(
        stack: &StackOutputs,
    ) -> Result<(Word, Word, BlockNumber), BatchOutputError> {
        let input_notes_commitment = stack
            .get_word(INPUT_NOTES_COMMITMENT_WORD_IDX)
            .expect("input_notes_commitment word missing");
        let output_notes_commitment = stack
            .get_word(OUTPUT_NOTES_COMMITMENT_WORD_IDX)
            .expect("output_notes_commitment word missing");

        let expiration_felt = stack
            .get_element(BATCH_EXPIRATION_BLOCK_NUM_ELEMENT_IDX)
            .expect("batch_expiration_block_num missing");

        // The word at felt indices 8..12 contains [batch_expiration_block_num, 0, 0, 0]. Indices
        // 9..12 of the output stack must be zero.
        let pad_word = stack
            .get_word(EXPIRATION_PAD_WORD_FELT_IDX)
            .expect("expiration pad word missing");
        if pad_word.as_elements()[EXPIRATION_PAD_WORD_INNER_OFFSET..]
            != Word::empty().as_elements()[1..]
        {
            return Err(BatchOutputError::OutputStackInvalid(
                "batch_expiration_block_num must be followed by zero padding".into(),
            ));
        }

        // Felts 12..16 (the trailing word) must also be zero.
        let trailing_word =
            stack.get_word(TRAILING_PAD_WORD_FELT_IDX).expect("trailing word missing");
        if trailing_word != Word::empty() {
            return Err(BatchOutputError::OutputStackInvalid(
                "trailing output stack cells must be zero".into(),
            ));
        }

        let batch_expiration_block_num = u32::try_from(expiration_felt.as_canonical_u64())
            .map_err(|_| BatchOutputError::ExpirationBlockNumberTooLarge(expiration_felt))?
            .into();

        Ok((input_notes_commitment, output_notes_commitment, batch_expiration_block_num))
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
