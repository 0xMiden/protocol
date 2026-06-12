use alloc::vec::Vec;

use miden_core::program::Kernel;
use miden_core::utils::hash_string_to_word;

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

// Advice-map keys under which the sorted (pre-erasure) note lists are provided to the kernel. Their
// integrity is established by the kernel binding every list entry to the per-transaction notes that
// are anchored in `BATCH_ID`, not by the key, so any fixed sentinel works. Each key is the word
// hash of a domain message; the kernel derives the same word via the MASM `word("...")` constant
// (both use `hash_string_to_word`), so the two sides agree by construction.
const INPUT_NOTE_LIST_KEY_MESSAGE: &str = "miden::batch_kernel::input_note_list";
const OUTPUT_NOTE_LIST_KEY_MESSAGE: &str = "miden::batch_kernel::output_note_list";

fn input_note_list_key() -> Word {
    hash_string_to_word(INPUT_NOTE_LIST_KEY_MESSAGE)
}

fn output_note_list_key() -> Word {
    hash_string_to_word(OUTPUT_NOTE_LIST_KEY_MESSAGE)
}

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
    /// - each per-tx `INPUT_NOTES_COMMITMENT` -> the `(NULLIFIER, EMPTY_OR_NOTE_ID)` tuples.
    /// - each per-tx `OUTPUT_NOTES_COMMITMENT` -> the `(DETAILS_COMMITMENT, METADATA_COMMITMENT)`
    ///   tuples (the kernel derives each output `NoteId` from these via `poseidon2::merge`).
    ///
    /// It also provides two nullifier/note-id-sorted lists — the pre-erasure union of every
    /// transaction's input notes (keyed by [`input_note_list_key`]) and output notes (keyed by
    /// [`output_note_list_key`]). The kernel binds every entry of these lists to the
    /// per-transaction notes above (so the host cannot inject, omit, or duplicate notes),
    /// derives erasure by cross-referencing the two lists, and hashes the non-erased input
    /// notes in nullifier order to reproduce `ProposedBatch::input_notes().commitment()`.
    fn build_advice_inputs(proposed_batch: &ProposedBatch) -> AdviceInputs {
        let mut advice_inputs = AdviceInputs::default();

        // Layer 1: BATCH_ID -> [(tx_id, account_id) tuples].
        let layer1_data = BatchId::hash_input_elements(
            proposed_batch.transactions().iter().map(|tx| (tx.id(), tx.account_id())),
        );
        advice_inputs.map.extend([(proposed_batch.id().as_word(), layer1_data)]);

        // Pre-erasure union of every transaction's notes, collected while walking the per-tx layers
        // and sorted below to match `ProposedBatch`'s nullifier / note-id ordering.
        let mut input_list: Vec<(Word, Word)> = Vec::new(); // (nullifier, note_id_or_empty)
        let mut output_list: Vec<Word> = Vec::new(); // note_id

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
                let mut preimage_data: Vec<Felt> =
                    Vec::with_capacity(usize::from(tx.input_notes().num_notes()) * 8);
                for note_commit in tx.input_notes().iter() {
                    let nullifier = note_commit.nullifier().as_word();
                    let note_id_or_empty =
                        note_commit.header().map_or(Word::empty(), |header| header.id().as_word());
                    preimage_data.extend_from_slice(nullifier.as_elements());
                    preimage_data.extend_from_slice(note_id_or_empty.as_elements());
                    input_list.push((nullifier, note_id_or_empty));
                }
                advice_inputs.map.extend([(input_notes_commitment, preimage_data)]);
            }

            // Layer 3': per-tx OUTPUT_NOTES_COMMITMENT -> [(DETAILS_COMMITMENT,
            // METADATA_COMMITMENT) tuples]. Mirrors `OutputNotes::commitment`; the
            // kernel derives each output NoteId as `merge(details_commitment,
            // metadata_commitment)`.
            let output_notes_commitment = tx.output_notes().commitment();
            if output_notes_commitment != Word::empty() {
                let mut preimage_data: Vec<Felt> =
                    Vec::with_capacity(tx.output_notes().num_notes() * 8);
                for note in tx.output_notes().iter() {
                    preimage_data
                        .extend_from_slice(note.details_commitment().as_word().as_elements());
                    preimage_data.extend_from_slice(note.metadata().to_commitment().as_elements());
                    output_list.push(note.id().as_word());
                }
                advice_inputs.map.extend([(output_notes_commitment, preimage_data)]);
            }
        }

        // Sort the sorted note lists ascending by nullifier / note id. `Word`'s ordering compares
        // the most-significant felt first, matching the batch kernel's `word::lt`
        // strict-sort check, `sorted_array`'s lookup order, and `ProposedBatch`'s
        // `InputNoteCommitment::nullifier` order.
        input_list.sort_by(|a, b| a.0.cmp(&b.0));
        output_list.sort_unstable();

        // INPUT_NOTE_LIST_KEY -> [(NULLIFIER[4], NOTE_ID_OR_EMPTY[4]) ...] (8 felts per note).
        let mut input_blob: Vec<Felt> = Vec::with_capacity(input_list.len() * 8);
        for (nullifier, note_id_or_empty) in &input_list {
            input_blob.extend_from_slice(nullifier.as_elements());
            input_blob.extend_from_slice(note_id_or_empty.as_elements());
        }
        advice_inputs.map.extend([(input_note_list_key(), input_blob)]);

        // OUTPUT_NOTE_LIST_KEY -> [(NOTE_ID[4], 0, 0, 0, 0) ...] (8 felts per note; the VALUE word
        // is unused, present only so the entries fit `sorted_array`'s KEY+VALUE layout).
        let mut output_blob: Vec<Felt> = Vec::with_capacity(output_list.len() * 8);
        for note_id in &output_list {
            output_blob.extend_from_slice(note_id.as_elements());
            output_blob.extend_from_slice(Word::empty().as_elements());
        }
        advice_inputs.map.extend([(output_note_list_key(), output_blob)]);

        advice_inputs
    }
}

#[cfg(any(feature = "testing", test))]
impl BatchKernel {
    /// The advice-map key under which the nullifier-sorted input-note list is provided to the
    /// kernel. Exposed so tests can construct override blobs without duplicating the sentinel
    /// value.
    pub fn input_note_list_key() -> Word {
        input_note_list_key()
    }

    /// The advice-map key under which the note-id-sorted output-note list is provided to the
    /// kernel.
    pub fn output_note_list_key() -> Word {
        output_note_list_key()
    }
}
