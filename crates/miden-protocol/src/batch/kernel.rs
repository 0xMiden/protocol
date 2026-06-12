use alloc::vec::Vec;

use miden_core::program::Kernel;

use crate::batch::{BatchId, ProposedBatch};
use crate::utils::serde::Deserializable;
use crate::utils::sync::LazyLock;
use crate::vm::{AdviceInputs, Package, Program, ProgramInfo, StackInputs};
use crate::{Felt, Word};

// CONSTANTS
// ================================================================================================

static KERNEL_MAIN: LazyLock<Program> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/assets/kernels/batch_kernel.masp"));
    Package::read_from_bytes(bytes)
        .expect("failed to deserialize batch kernel package")
        .try_into_program()
        .expect("batch kernel package should contain a program")
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
        let batch_id = proposed_batch.id();

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
    /// - `BATCH_ID` is the batch's [`BatchId`].
    pub fn build_input_stack(block_commitment: Word, batch_id: BatchId) -> StackInputs {
        let mut inputs: Vec<Felt> = Vec::with_capacity(8);
        inputs.extend_from_slice(block_commitment.as_elements());
        inputs.extend_from_slice(batch_id.as_word().as_elements());

        StackInputs::new(&inputs).expect("number of stack inputs should be <= 16")
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
