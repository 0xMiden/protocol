use alloc::vec::Vec;

use miden_core::program::KernelDescriptor;

use crate::block::ProposedBlock;
use crate::crypto::SequentialCommit;
use crate::utils::serde::Deserializable;
use crate::utils::sync::LazyLock;
use crate::vm::{AdviceInputs, Package, Program, ProgramInfo, StackInputs};
use crate::{Felt, Word};

// CONSTANTS
// ================================================================================================

static KERNEL_MAIN: LazyLock<Program> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/assets/kernels/miden-block-kernel:miden-block-kernel.masp"
    ));
    Package::read_from_bytes(bytes)
        .expect("failed to deserialize block kernel package")
        .try_into_program()
        .expect("block kernel package should contain a program")
});

// BLOCK KERNEL
// ================================================================================================

/// The block kernel program: an executable Miden program that proves a block of batches.
///
/// The kernel takes `[PREV_BLOCK_COMMITMENT, BATCHES_COMMITMENT]` as public inputs and emits
/// `[BLOCK_COMMITMENT, NULLIFIER_COMMITMENT]`. See `asm/kernels/block/main.masm` for the
/// input/output contract.
pub struct BlockKernel;

impl BlockKernel {
    // KERNEL SOURCE CODE
    // --------------------------------------------------------------------------------------------

    /// Returns the executable block kernel program loaded from the build's `OUT_DIR`.
    pub fn main() -> Program {
        KERNEL_MAIN.clone()
    }

    /// Returns [`ProgramInfo`] for the block kernel program.
    ///
    /// The block kernel does not expose syscalls, so the associated [`KernelDescriptor`] is empty.
    pub fn program_info() -> ProgramInfo {
        ProgramInfo::new(Self::main().hash(), KernelDescriptor::default())
    }

    // INPUT BUILDERS
    // --------------------------------------------------------------------------------------------

    /// Transforms the provided [`ProposedBlock`] into the stack and advice inputs needed to execute
    /// the block kernel.
    pub fn prepare_inputs(proposed_block: &ProposedBlock) -> (StackInputs, AdviceInputs) {
        let prev_block_commitment = proposed_block.prev_block_header().commitment();
        let batches_commitment = proposed_block.batches().to_commitment();

        let stack_inputs = Self::build_input_stack(prev_block_commitment, batches_commitment);

        // TODO: Create a dedicated `BlockAdviceInputs` struct mirroring `TransactionAdviceInputs`
        let advice_inputs = AdviceInputs::default();

        (stack_inputs, advice_inputs)
    }

    /// Returns the stack with the public inputs required by the block kernel.
    ///
    /// The initial stack is:
    ///
    /// ```text
    /// [PREV_BLOCK_COMMITMENT, BATCHES_COMMITMENT, pad(8)]
    /// ```
    ///
    /// Where:
    /// - `PREV_BLOCK_COMMITMENT` is the commitment of the block header this block builds on top of.
    /// - `BATCHES_COMMITMENT` is the sequential commitment to the batch IDs in the block.
    pub fn build_input_stack(prev_block_commitment: Word, batches_commitment: Word) -> StackInputs {
        let mut inputs: Vec<Felt> = Vec::with_capacity(8);
        inputs.extend_from_slice(prev_block_commitment.as_elements());
        inputs.extend_from_slice(batches_commitment.as_elements());

        StackInputs::new(&inputs).expect("number of stack inputs should be <= 16")
    }
}
