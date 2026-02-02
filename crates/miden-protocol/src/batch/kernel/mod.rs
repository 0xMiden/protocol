//! Batch Kernel
//!
//! This module provides the Rust wrapper for the batch kernel MASM program.
//! The batch kernel proves the validity of a batch of already-proven transactions.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::batch::BatchId;
use crate::block::BlockNumber;
use crate::utils::serde::Deserializable;
use crate::utils::sync::LazyLock;
use crate::vm::{Program, ProgramInfo, StackInputs, StackOutputs};
use crate::{Felt, Word};

mod advice_inputs;
pub use advice_inputs::BatchAdviceInputs;

// CONSTANTS
// ================================================================================================

// Initialize the batch kernel main program only once
static BATCH_KERNEL_MAIN: LazyLock<Program> = LazyLock::new(|| {
    let kernel_main_bytes =
        include_bytes!(concat!(env!("OUT_DIR"), "/assets/kernels/batch_kernel.masb"));
    Program::read_from_bytes(kernel_main_bytes)
        .expect("failed to deserialize batch kernel runtime")
});

// BATCH KERNEL ERROR
// ================================================================================================

/// Error type for batch kernel operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchKernelError {
    /// Failed to parse output stack.
    InvalidOutputStack(String),
}

impl core::fmt::Display for BatchKernelError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BatchKernelError::InvalidOutputStack(msg) => {
                write!(f, "invalid batch kernel output stack: {}", msg)
            },
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BatchKernelError {}

// BATCH KERNEL
// ================================================================================================

/// Batch kernel for proving transaction batches.
///
/// The batch kernel takes a list of proven transactions and produces a single proof
/// that attests to the validity of the entire batch.
pub struct BatchKernel;

impl BatchKernel {
    // KERNEL SOURCE CODE
    // --------------------------------------------------------------------------------------------

    /// Returns an AST of the batch kernel executable program.
    ///
    /// # Panics
    /// Panics if the batch kernel source is not well-formed.
    pub fn main() -> Program {
        BATCH_KERNEL_MAIN.clone()
    }

    /// Returns [ProgramInfo] for the batch kernel executable program.
    pub fn program_info() -> ProgramInfo {
        Self::main().into()
    }

    // INPUT/OUTPUT STACK
    // --------------------------------------------------------------------------------------------

    /// Builds the input stack for the batch kernel.
    ///
    /// The input stack contains:
    /// - `BLOCK_HASH`: The reference block hash (commitment to block header)
    /// - `TRANSACTIONS_COMMITMENT` (BatchId): Sequential hash of [(TX_ID, account_id), ...]
    ///
    /// Stack layout (top to bottom):
    /// ```text
    /// [BLOCK_HASH, TRANSACTIONS_COMMITMENT]
    /// ```
    pub fn build_input_stack(block_hash: Word, batch_id: BatchId) -> StackInputs {
        let mut inputs: Vec<Felt> = Vec::with_capacity(16);
        inputs.extend(block_hash);
        // Reverse BatchId to match MASM rpo256::hash_elements output order
        inputs.extend(batch_id.as_elements().iter().rev());
        // Pad to 16 elements (required for correct stack positioning)
        inputs.resize(16, Felt::from(0_u32));

        StackInputs::new(inputs)
            .map_err(|e| e.to_string())
            .expect("Invalid stack input")
    }

    /// Parses the output stack from batch kernel execution.
    ///
    /// Output stack layout:
    /// ```text
    /// [INPUT_NOTES_COMMITMENT, OUTPUT_NOTES_SMT_ROOT, batch_expiration_block_num, ...]
    /// ```
    ///
    /// Returns:
    /// - `input_notes_commitment`: Sequential hash of [(nullifier, empty_word_or_note_hash), ...]
    /// - `output_notes_smt_root`: Root of the output notes Sparse Merkle Tree
    /// - `batch_expiration_block_num`: Minimum expiration block across all transactions
    pub fn parse_output_stack(
        outputs: &StackOutputs,
    ) -> Result<BatchKernelOutputs, BatchKernelError> {
        // Output stack layout:
        // [INPUT_NOTES_COMMITMENT (0-3), OUTPUT_NOTES_SMT_ROOT (4-7), batch_expiration (8), ...]

        let input_notes_commitment = outputs
            .get_stack_word_be(0)
            .ok_or_else(|| BatchKernelError::InvalidOutputStack(
                "input_notes_commitment (first word) missing".to_string(),
            ))?;

        let output_notes_smt_root = outputs
            .get_stack_word_be(4)
            .ok_or_else(|| BatchKernelError::InvalidOutputStack(
                "output_notes_smt_root (second word) missing".to_string(),
            ))?;

        let batch_expiration_felt = outputs
            .get_stack_item(8)
            .ok_or_else(|| BatchKernelError::InvalidOutputStack(
                "batch_expiration_block_num (element at index 8) missing".to_string(),
            ))?;

        let batch_expiration_block_num: BlockNumber = u32::try_from(batch_expiration_felt.as_int())
            .map_err(|_| BatchKernelError::InvalidOutputStack(
                "batch expiration block number should be smaller than u32::MAX".to_string(),
            ))?
            .into();

        Ok(BatchKernelOutputs {
            input_notes_commitment,
            output_notes_smt_root,
            batch_expiration_block_num,
        })
    }
}

// BATCH KERNEL OUTPUTS
// ================================================================================================

/// Outputs produced by the batch kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchKernelOutputs {
    /// Sequential hash of [(nullifier, empty_word_or_note_hash), ...].
    /// For unauthenticated notes, empty_word_or_note_hash is hash(note_id, note_metadata).
    pub input_notes_commitment: Word,

    /// Root of the output notes Sparse Merkle Tree.
    pub output_notes_smt_root: Word,

    /// Minimum expiration block across all transactions in the batch.
    pub batch_expiration_block_num: BlockNumber,
}
