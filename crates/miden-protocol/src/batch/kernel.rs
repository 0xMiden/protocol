use alloc::vec::Vec;

use miden_core::program::Kernel;

use crate::batch::{BatchId, ProposedBatch};
use crate::transaction::TransactionId;
use crate::utils::serde::Deserializable;
use crate::utils::sync::LazyLock;
use crate::vm::{AdviceInputs, Program, ProgramInfo, StackInputs};
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

    /// Builds the advice inputs consumed by the batch kernel.
    ///
    /// The kernel reconstructs and verifies the batch's `INPUT_NOTES_COMMITMENT` by walking a
    /// layered advice map, each layer keyed by a hash the previous layer verified:
    /// - `BATCH_ID` -> the `(tx_id, account_id)` tuple list (matching
    ///   `BatchId::hash_input_elements`).
    /// - each `tx_id` -> the transaction header felt sequence (matching
    ///   `TransactionId::input_elements`).
    /// - each per-tx `INPUT_NOTES_COMMITMENT` -> the `(NULLIFIER, EMPTY_OR_COMMITMENT)` tuples.
    ///
    /// The per-tx output-notes layer and the expiration data are wired up in follow-up PRs.
    fn build_advice_inputs(proposed_batch: &ProposedBatch) -> AdviceInputs {
        let mut advice_inputs = AdviceInputs::default();

        // Layer 1: BATCH_ID -> [(tx_id, account_id) tuples].
        let layer1_data = BatchId::hash_input_elements(
            proposed_batch.transactions().iter().map(|tx| (tx.id(), tx.account_id())),
        );
        advice_inputs.map.extend([(proposed_batch.id().as_word(), layer1_data)]);

        for tx in proposed_batch.transactions().iter() {
            // Layer 2: tx_id -> the felt sequence TransactionId::new hashes.
            let header_data = TransactionId::input_elements(
                tx.account_update().initial_state_commitment(),
                tx.account_update().final_state_commitment(),
                tx.input_notes().commitment(),
                tx.output_notes().commitment(),
                tx.fee(),
            );
            advice_inputs.map.extend([(tx.id().as_word(), header_data.to_vec())]);

            // Layer 3: per-tx INPUT_NOTES_COMMITMENT -> [(NULLIFIER, EMPTY_OR_NOTE_ID) tuples].
            // This must reproduce `build_input_note_commitment` exactly: per note, the nullifier
            // followed by the note ID (or the empty word for authenticated notes).
            let input_notes_commitment = tx.input_notes().commitment();
            if input_notes_commitment != Word::empty() {
                let mut notes_commitment_preimage_data: Vec<Felt> =
                    Vec::with_capacity(usize::from(tx.input_notes().num_notes()) * 8);
                for note_commit in tx.input_notes().iter() {
                    notes_commitment_preimage_data
                        .extend_from_slice(note_commit.nullifier().as_word().as_elements());
                    let note_id_or_empty =
                        note_commit.header().map_or(Word::empty(), |header| header.id().as_word());
                    notes_commitment_preimage_data
                        .extend_from_slice(note_id_or_empty.as_elements());
                }
                advice_inputs
                    .map
                    .extend([(input_notes_commitment, notes_commitment_preimage_data)]);
            }
        }

        advice_inputs
    }
}
